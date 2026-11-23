import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it, onTestFinished } from "vitest";

import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

const NEEDLE = "record_unknown";

const NEEDLE_ARGUMENTS = {
  question: "Does this remain unknown?",
  severity: "medium",
  domain: "bundle-format",
  required_authority: null,
  required_confidence: "derived",
  required_environment: null,
  recommended_probes: [{ operation: "observe", rationale: "Inspect it." }],
  relationships: [],
};

const CONCURRENT_LOADS = [
  NEEDLE,
  "inspect_wasm_artifact",
  "cutter_command",
  "analyze_javascript_application",
  "read_guidance_section",
  "list_strings",
] as const;

const connectLazy = async (): Promise<Client> => {
  const session = createTestBinarySession(() => {
    throw new Error("Discovery must not start a deep provider");
  });
  const server = createServer(
    { kind: "session", session },
    { environment: { REA_MCP_TOOL_SURFACE: "lazy" } },
  );
  const client = new Client({
    name: "lazy-concurrent-discovery",
    version: "1",
  });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return client;
};

it("advertises every tool from a concurrent load burst exactly once and keeps each callable", async () => {
  const client = await connectLazy();
  const initial = await client.listTools();
  const initialNames = initial.tools.map(({ name }) => name);
  for (const name of CONCURRENT_LOADS) expect(initialNames).not.toContain(name);

  // One burst: six distinct loads, two duplicates of tools in the same
  // burst, and searches racing the registrations they observe.
  const requested = [...CONCURRENT_LOADS, NEEDLE, "list_strings"] as const;
  const operations: Promise<unknown>[] = requested.map(
    async (name) =>
      await client.callTool({
        name: "load_tool_schema",
        arguments: { name },
      }),
  );
  for (const query of ["record an unknown", "wasm artifact", "strings"]) {
    operations.push(
      client.callTool({
        name: "search_tools",
        arguments: { query, limit: 5 },
      }),
    );
  }
  const settled = await Promise.all(operations);
  const loads = settled.slice(0, requested.length) as {
    isError?: boolean;
    structuredContent?: { name?: string; advertised?: boolean };
  }[];
  loads.forEach((load, index) => {
    expect(load.isError, JSON.stringify(load)).not.toBe(true);
    expect(load.structuredContent).toMatchObject({
      name: requested[index],
      advertised: true,
    });
  });
  const searches = settled.slice(requested.length) as {
    isError?: boolean;
    structuredContent?: { registered_tools?: number };
  }[];
  for (const search of searches) {
    expect(search.isError).not.toBe(true);
    expect(search.structuredContent?.registered_tools).toBeGreaterThan(200);
  }

  // The burst converged: every distinct tool is advertised exactly once,
  // and the advertised count grew by the distinct loads only.
  const after = await client.listTools();
  const afterNames = after.tools.map(({ name }) => name);
  for (const name of CONCURRENT_LOADS) {
    expect(afterNames.filter((entry) => entry === name)).toHaveLength(1);
  }
  expect(afterNames.length).toBe(initialNames.length + CONCURRENT_LOADS.length);
  const coverage = await client.callTool({
    name: "search_tools",
    arguments: { query: "record an unknown question", limit: 10 },
  });
  expect(coverage.isError).not.toBe(true);
  expect(
    (coverage.structuredContent as { advertised_tools: number })
      .advertised_tools,
  ).toBe(initialNames.length + CONCURRENT_LOADS.length);

  // A tool loaded inside the burst executes end to end.
  const recorded = await client.callTool({
    name: NEEDLE,
    arguments: NEEDLE_ARGUMENTS,
  });
  expect(recorded.isError).not.toBe(true);
  expect(JSON.stringify(recorded.structuredContent)).toContain(
    "Does this remain unknown?",
  );
});
