import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import type { Tool } from "@modelcontextprotocol/server";
import { expect, it } from "vitest";
import { z } from "zod";

import type { RecordedMcpCatalog } from "../recordedMcpCatalog.js";
import { DeferredEvidenceMcpServer } from "./DeferredEvidenceMcpServer.js";
import { ToolResultDelivery } from "./ToolResultDelivery.js";

const input = z.strictObject({ n: z.number().int().nonnegative().default(3) });
const output = z.strictObject({ n: z.number().int() });

const toolEntry = (name: string): Tool => ({
  name,
  inputSchema: z.toJSONSchema(input, {
    io: "input",
  }) as Tool["inputSchema"],
  outputSchema: z.toJSONSchema(output),
});

const catalog: RecordedMcpCatalog = {
  version: 1,
  info: { name: "deferred-lazy-fixture", version: "1" },
  instructions: "Fixture",
  capabilities: { tools: { listChanged: true } },
  identity: {
    counts: { cli_commands: 0, mcp_tools: 2, mcp_prompts: 0 },
    digests: {
      tools_sha256: "fixture",
      prompts_sha256: "fixture",
      combined_sha256: "fixture",
    },
  },
  tools: [toolEntry("list_unknowns"), toolEntry("fixture_needle")],
  evidenceReferenceAlternatives: [],
  prompts: [],
};

it("serves discovery from the recorded catalog before materializing, then loads and calls a hidden tool", async () => {
  let loads = 0;
  const server = new DeferredEvidenceMcpServer(
    catalog,
    new ToolResultDelivery(1024 * 1024),
    async (target) => {
      loads += 1;
      target.materialize(() => {
        for (const name of ["list_unknowns", "fixture_needle"])
          target.registerTool(
            name,
            { inputSchema: input, outputSchema: output },
            async (args) => ({
              content: [{ type: "text", text: JSON.stringify({ n: args.n }) }],
              structuredContent: { n: args.n },
            }),
          );
      });
    },
    { toolSurfaceMode: "lazy" },
  );
  const client = new Client({ name: "deferred-lazy-client", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    const initial = await client.listTools();
    const initialNames = initial.tools.map(({ name }) => name);
    expect(initialNames).toContain("list_unknowns");
    expect(initialNames).toContain("search_tools");
    expect(initialNames).toContain("load_tool_schema");
    expect(initialNames).toContain("read_tool_result_page");
    expect(initialNames).not.toContain("fixture_needle");

    const search = await client.callTool({
      name: "search_tools",
      arguments: { query: "fixture_needle", limit: 5 },
    });
    expect(search.isError).not.toBe(true);
    const found = search.structuredContent as {
      matches: { name: string; advertised: boolean }[];
      registered_tools: number;
    };
    expect(found.registered_tools).toBe(5);
    expect(found.matches[0]).toMatchObject({
      name: "fixture_needle",
      advertised: false,
    });
    expect(loads).toBe(0);

    const load = await client.callTool({
      name: "load_tool_schema",
      arguments: { name: "fixture_needle" },
    });
    expect(load.isError).not.toBe(true);
    expect(loads).toBe(0);
    const afterLoad = await client.listTools();
    expect(afterLoad.tools.map(({ name }) => name)).toContain("fixture_needle");

    const call = await client.callTool({
      name: "fixture_needle",
      arguments: { n: 7 },
    });
    expect(call.isError).not.toBe(true);
    expect(call.structuredContent).toEqual({ n: 7 });
    expect(loads).toBe(1);
  } finally {
    await client.close();
    await server.close();
  }
});
