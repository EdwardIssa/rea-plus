import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it, onTestFinished } from "vitest";

import { parseClaimCheckLedger } from "../../../src/domain/claimCheck/claimCheckLedger.js";
import { createEvidence } from "../../../src/domain/evidence.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import {
  buildClaimCheckFixture,
  fixtureStringRow,
  type ClaimCheckFixture,
} from "../../fixtures/claimCheck/claimCheckFixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const TOOL = "adjudicate_string_claims";

let fixturePromise: Promise<ClaimCheckFixture> | undefined;
const fixture = (): Promise<ClaimCheckFixture> =>
  (fixturePromise ??= buildClaimCheckFixture());

const connect = async (surface: "lazy" | "full"): Promise<Client> => {
  const session = createTestBinarySession(() => {
    throw new Error("Claim check must not start a deep provider");
  });
  const server = createServer(
    { kind: "session", session },
    { environment: { REA_MCP_TOOL_SURFACE: surface } },
  );
  const client = new Client({ name: "claim-check", version: "1" });
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

it("discovers, loads, and calls adjudicate_string_claims on the lazy surface", async () => {
  const f = await fixture();
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
  expect(loaded.inputSchema.properties).toHaveProperty("artifact_path");
  expect(loaded.inputSchema.properties).toHaveProperty("ledger_path");

  const root = await createTestTempDirectory("rea-claim-check-mcp-");
  const record = createEvidence(
    { path: "/fixtures/artifact", sha256: f.unstrippedSha256, format: "elf" },
    { id: "ghidra", name: "Ghidra", version: "12.1.4" },
    {
      operation: "list_strings",
      parameters: {},
      result: f.strings.map((entry) => fixtureStringRow(entry)),
    },
  );
  const evidencePath = join(root, "evidence.json");
  await writeFile(evidencePath, JSON.stringify(record));
  const ledgerPath = join(root, "ledger.json");

  const called = await client.callTool({
    name: TOOL,
    arguments: {
      evidence_path: evidencePath,
      artifact_path: f.unstrippedPath,
      ledger_path: ledgerPath,
    },
  });
  expect(called.isError).not.toBe(true);
  const outcome = called.structuredContent as {
    counts: { supported: number; refuted: number; unknown: number };
    claims_considered: number;
    report_digest: string;
    ledger_path: string;
  };
  expect(outcome.counts).toEqual({ supported: 3, refuted: 0, unknown: 0 });
  expect(outcome.claims_considered).toBe(3);
  expect(outcome.report_digest).toMatch(/^[a-f0-9]{64}$/u);
  expect(outcome.ledger_path).toBe(ledgerPath);
  const ledger = parseClaimCheckLedger(
    JSON.parse(await readFile(ledgerPath, "utf8")),
  );
  expect(ledger.summary).toMatchObject({ complete: true, supported: 3 });
});

it("advertises adjudicate_string_claims at connect on the full surface", async () => {
  const client = await connect("full");
  const initial = await client.listTools();
  expect(initial.tools.map(({ name }) => name)).toContain(TOOL);
});
