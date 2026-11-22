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

const connectLazy = async (): Promise<Client> => {
  const session = createTestBinarySession(() => {
    throw new Error("Discovery must not start a deep provider");
  });
  const server = createServer(
    { kind: "session", session },
    { environment: { REA_MCP_TOOL_SURFACE: "lazy" } },
  );
  const client = new Client({ name: "lazy-discovery", version: "1" });
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

it("discovers, loads, and calls a non-core tool that is not advertised at connect", async () => {
  const client = await connectLazy();

  // Connect-time advertisement: core group plus discovery machinery only.
  const initial = await client.listTools();
  const initialNames = initial.tools.map(({ name }) => name);
  expect(initialNames).toContain("binary_session");
  expect(initialNames).toContain("search_tools");
  expect(initialNames).toContain("load_tool_schema");
  expect(initialNames).toContain("read_tool_result_page");
  expect(initialNames).not.toContain(NEEDLE);
  expect(initialNames).not.toContain("list_strings");
  expect(initialNames).not.toContain("inspect_wasm_artifact");
  expect(initialNames.length).toBeLessThanOrEqual(20);

  // The needle is registered but not advertised: a direct call is refused
  // by the SDK as a disabled tool, surfacing as a protocol error.
  await expect(
    client.callTool({ name: NEEDLE, arguments: NEEDLE_ARGUMENTS }),
  ).rejects.toThrow(/disabled/);

  // Discovery by intent finds the needle without its schema being advertised.
  const search = await client.callTool({
    name: "search_tools",
    arguments: { query: "record an unknown question", limit: 10 },
  });
  expect(search.isError).not.toBe(true);
  const found = search.structuredContent as {
    matches: { name: string; advertised: boolean }[];
    registered_tools: number;
    advertised_tools: number;
  };
  expect(found.registered_tools).toBeGreaterThan(200);
  expect(found.advertised_tools).toBe(initialNames.length);
  const needleMatch = found.matches.find(({ name }) => name === NEEDLE);
  expect(needleMatch?.advertised).toBe(false);

  // Tools from unrelated families are equally discoverable by name.
  for (const name of [
    "inspect_wasm_artifact",
    "cutter_command",
    "analyze_javascript_application",
    "read_guidance_section",
  ]) {
    const byName = await client.callTool({
      name: "search_tools",
      arguments: { query: name, limit: 5 },
    });
    const matches = (
      byName.structuredContent as { matches: { name: string }[] }
    ).matches;
    expect(matches.map((match) => match.name)).toContain(name);
  }

  // Loading returns the advertised schema and advertises the tool.
  const load = await client.callTool({
    name: "load_tool_schema",
    arguments: { name: NEEDLE },
  });
  expect(load.isError).not.toBe(true);
  const loaded = load.structuredContent as {
    name: string;
    inputSchema: { properties?: Record<string, unknown> };
    advertised: boolean;
  };
  expect(loaded.name).toBe(NEEDLE);
  expect(loaded.advertised).toBe(true);
  expect(loaded.inputSchema.properties).toHaveProperty("question");
  const afterLoad = await client.listTools();
  expect(afterLoad.tools.map(({ name }) => name)).toContain(NEEDLE);

  // The loaded tool now calls successfully end to end.
  const recorded = await client.callTool({
    name: NEEDLE,
    arguments: NEEDLE_ARGUMENTS,
  });
  expect(recorded.isError).not.toBe(true);
  expect(JSON.stringify(recorded.structuredContent)).toContain(
    "Does this remain unknown?",
  );
});

it("reports an unknown tool load with closest-match guidance", async () => {
  const client = await connectLazy();
  const load = await client.callTool({
    name: "load_tool_schema",
    arguments: { name: "record_unknowns" },
  });
  expect(load.isError).toBe(true);
  const text = load.content
    .map((item) => (item.type === "text" ? item.text : ""))
    .join("\n");
  expect(text).toContain("record_unknown");
});
