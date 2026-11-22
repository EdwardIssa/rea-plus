import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it, onTestFinished } from "vitest";

import { parseClaimCheckLedger } from "../../../src/domain/claimCheck/claimCheckLedger.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { runtimeEvidenceRecord } from "../../fixtures/claimCheck/runtimeClaimCheckFixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const TOOL = "adjudicate_runtime_claims";

const connect = async (surface: "lazy" | "full"): Promise<Client> => {
  const session = createTestBinarySession(() => {
    throw new Error("Runtime claim check must not start a deep provider");
  });
  const server = createServer(
    { kind: "session", session },
    { environment: { REA_MCP_TOOL_SURFACE: surface } },
  );
  const client = new Client({ name: "runtime-claim-check", version: "1" });
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

it("discovers, loads, and calls adjudicate_runtime_claims on the lazy surface", async () => {
  const client = await connect("lazy");

  const initial = await client.listTools();
  expect(initial.tools.map(({ name }) => name)).not.toContain(TOOL);

  const search = await client.callTool({
    name: "search_tools",
    arguments: { query: TOOL, limit: 5 },
  });
  expect(search.isError).not.toBe(true);
  const matches = (search.structuredContent as { matches: { name: string }[] })
    .matches;
  expect(matches.map((match) => match.name)).toContain(TOOL);

  const load = await client.callTool({
    name: "load_tool_schema",
    arguments: { name: TOOL },
  });
  expect(load.isError).not.toBe(true);
  const loaded = load.structuredContent as {
    name: string;
    advertised: boolean;
    inputSchema: { properties?: Record<string, unknown> };
  };
  expect(loaded.name).toBe(TOOL);
  expect(loaded.advertised).toBe(true);
  expect(loaded.inputSchema.properties).toHaveProperty("evidence_path");
  expect(loaded.inputSchema.properties).toHaveProperty("ledger_path");
  expect(loaded.inputSchema.properties).not.toHaveProperty("artifact_path");

  const root = await createTestTempDirectory("rea-runtime-claim-check-mcp-");
  const records = [11, 22, 33].map((pid) =>
    runtimeEvidenceRecord({ pid, filed: ["alpha-secret-one"] }),
  );
  const evidencePath = join(root, "evidence.json");
  await writeFile(evidencePath, JSON.stringify(records));
  const ledgerPath = join(root, "ledger.json");

  const called = await client.callTool({
    name: TOOL,
    arguments: { evidence_path: evidencePath, ledger_path: ledgerPath },
  });
  expect(called.isError).not.toBe(true);
  const outcome = called.structuredContent as {
    counts: { supported: number; refuted: number; unknown: number };
    claims_considered: number;
    report_digest: string;
    ledger_path: string;
  };
  expect(outcome.counts).toEqual({ supported: 1, refuted: 0, unknown: 0 });
  expect(outcome.claims_considered).toBe(1);
  expect(outcome.report_digest).toMatch(/^[a-f0-9]{64}$/u);
  expect(outcome.ledger_path).toBe(ledgerPath);
  const ledger = parseClaimCheckLedger(
    JSON.parse(await readFile(ledgerPath, "utf8")),
  );
  expect(ledger.summary).toMatchObject({ complete: true, supported: 1 });
});

it("advertises adjudicate_runtime_claims at connect on the full surface", async () => {
  const client = await connect("full");
  const initial = await client.listTools();
  expect(initial.tools.map(({ name }) => name)).toContain(TOOL);
});
