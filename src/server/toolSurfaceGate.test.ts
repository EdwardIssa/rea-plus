import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import type { Tool } from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import type { RecordedMcpCatalog } from "../recordedMcpCatalog.js";
import { DeferredEvidenceMcpServer } from "./DeferredEvidenceMcpServer.js";
import { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { ToolResultDelivery } from "./ToolResultDelivery.js";
import { registerDiscoveryTools } from "./toolDiscovery.js";

const connect = async (
  server: EvidenceMcpServer | DeferredEvidenceMcpServer,
): Promise<Client> => {
  const client = new Client({ name: "gate-client", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return client;
};

describe("authorization at execution (gate: revocation)", () => {
  it("a discovered and loaded tool that is revoked fails at call time and never runs", async () => {
    const server = new EvidenceMcpServer(
      { name: "gate-revocation", version: "1" },
      { capabilities: {} },
      undefined,
      new ToolResultDelivery(1024 * 1024),
      undefined,
      "full",
      undefined,
      undefined,
      "lazy",
    );
    let calls = 0;
    server.registerTool(
      "fixture_guarded",
      {
        title: "Fixture guarded",
        description: "Counts its own invocations.",
        inputSchema: z.strictObject({}),
        outputSchema: z.strictObject({ calls: z.number().int() }),
      },
      async () => {
        calls += 1;
        return {
          content: [{ type: "text", text: JSON.stringify({ calls }) }],
          structuredContent: { calls },
        };
      },
    );
    registerDiscoveryTools((name, config, callback) => {
      server.registerTool(name, config as never, callback as never);
    }, server.toolSurface);
    const client = await connect(server);
    try {
      const initial = await client.listTools();
      expect(initial.tools.map(({ name }) => name)).not.toContain(
        "fixture_guarded",
      );
      const load = await client.callTool({
        name: "load_tool_schema",
        arguments: { name: "fixture_guarded" },
      });
      expect(load.isError).not.toBe(true);
      const allowed = await client.callTool({
        name: "fixture_guarded",
        arguments: {},
      });
      expect(allowed.isError).not.toBe(true);
      expect(calls).toBe(1);

      // Revocation: the surface withdraws the advertisement server-side.
      expect(server.toolSurface.unload("fixture_guarded")).toBe(true);
      const afterRevoke = await client.listTools();
      expect(afterRevoke.tools.map(({ name }) => name)).not.toContain(
        "fixture_guarded",
      );
      await expect(
        client.callTool({ name: "fixture_guarded", arguments: {} }),
      ).rejects.toThrow(/disabled/);
      // Zero unauthorized executions after revocation.
      expect(calls).toBe(1);

      // Connect-time machinery is not revocable through the load path.
      expect(server.toolSurface.unload("search_tools")).toBe(false);
      expect(server.toolSurface.unload("fixture_guarded")).toBe(false);
    } finally {
      await client.close();
      await server.close();
    }
  });
});

describe("schema-version contract (gate: stale schema)", () => {
  const inputV1 = z.strictObject({ n: z.number().int() });
  const inputV2 = z.strictObject({
    n: z.number().int(),
    m: z.number().int(),
  });
  const output = z.strictObject({ n: z.number().int() });
  const catalog: RecordedMcpCatalog = {
    version: 1,
    info: { name: "gate-version-fixture", version: "1" },
    instructions: "Fixture",
    capabilities: { tools: { listChanged: true } },
    identity: {
      counts: { cli_commands: 0, mcp_tools: 1, mcp_prompts: 0 },
      digests: {
        tools_sha256: "fixture",
        prompts_sha256: "fixture",
        combined_sha256: "fixture",
      },
    },
    tools: [
      {
        name: "fixture_versioned",
        inputSchema: z.toJSONSchema(inputV1, {
          io: "input",
        }) as Tool["inputSchema"],
        outputSchema: z.toJSONSchema(output),
      },
    ],
    evidenceReferenceAlternatives: [],
    prompts: [],
  };

  it("re-validates arguments at invocation against the current schema, never the loaded snapshot", async () => {
    let calls = 0;
    const server = new DeferredEvidenceMcpServer(
      catalog,
      new ToolResultDelivery(1024 * 1024),
      async (target) => {
        target.materialize(() => {
          target.registerTool(
            "fixture_versioned",
            { inputSchema: inputV2, outputSchema: output },
            async (args) => {
              calls += 1;
              return {
                content: [
                  { type: "text", text: JSON.stringify({ n: args.n }) },
                ],
                structuredContent: { n: args.n },
              };
            },
          );
        });
      },
    );
    const client = await connect(server);
    try {
      // The client sees and loads the recorded (v1) schema: only `n`.
      const listed = await client.listTools();
      const advertised = listed.tools.find(
        ({ name }) => name === "fixture_versioned",
      );
      expect(advertised?.inputSchema.properties).toHaveProperty("n");
      expect(advertised?.inputSchema.properties).not.toHaveProperty("m");

      // Arguments valid under the stale v1 schema are refused at invocation
      // because the current v2 schema also requires `m`; the tool never runs.
      const stale = await client
        .callTool({ name: "fixture_versioned", arguments: { n: 1 } })
        .then(
          (result) => ({ rejected: false, isError: result.isError === true }),
          () => ({ rejected: true, isError: false }),
        );
      expect(stale.rejected || stale.isError).toBe(true);
      expect(calls).toBe(0);

      // Arguments valid under the current schema call successfully.
      const current = await client.callTool({
        name: "fixture_versioned",
        arguments: { n: 1, m: 2 },
      });
      expect(current.isError).not.toBe(true);
      expect(calls).toBe(1);
    } finally {
      await client.close();
      await server.close();
    }
  });
});
