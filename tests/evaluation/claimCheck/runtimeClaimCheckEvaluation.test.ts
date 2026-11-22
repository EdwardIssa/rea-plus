import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { beforeAll, describe, expect, it, onTestFinished } from "vitest";

import { runRuntimeClaimCheck } from "../../../src/application/claimCheck/runRuntimeClaimCheck.js";
import { groupRuntimeEvidence } from "../../../src/application/claimCheck/extractRuntimeClaims.js";
import { runDynamicExecutionCommand } from "../../../src/application/dynamicExecution/runDynamicExecution.js";
import {
  parseClaimCheckLedger,
  resolveClaimCheckStates,
  type ClaimCheckLedger,
} from "../../../src/domain/claimCheck/claimCheckLedger.js";
import {
  buildRuntimeClaimCheckReport,
  type RuntimeClaimCheckOutcome,
} from "../../../src/domain/claimCheck/claimCheckRuntimeReport.js";
import {
  runtimeAdjudicationReasonSchema,
  RUNTIME_CLAIM_VALIDATOR,
} from "../../../src/domain/claimCheck/runtimeReplayValidator.js";
import { parseEvidence, type Evidence } from "../../../src/domain/evidence.js";
import { createServer } from "../../../src/server/createServer.js";
import {
  buildFixtures,
  FIXTURES_ROOT,
} from "../../../scripts/ablation/buildFixtures.mjs";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { runtimeEvidenceRecord } from "../../fixtures/claimCheck/runtimeClaimCheckFixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

/**
 * The claim-check runtime-class gate, run against REAL execute_dynamically
 * records: three genuine Frida runs per (fixture, stimulus) from the dynamic
 * fixture corpus, adjudicated as one set. Truth sets come from each
 * fixture's own truth.json string list for the stimulus exercised.
 */

const binaryOf = (id: string): string => join(FIXTURES_ROOT, "bin", id, id);
const sha256Of = (path: string): string =>
  createHash("sha256").update(readFileSync(path)).digest("hex");

interface StimulusCase {
  readonly fixture: string;
  readonly argv: readonly string[];
  readonly envSet: Readonly<Record<string, string>>;
  readonly truth: string;
}

const CASES: readonly StimulusCase[] = [
  { fixture: "a1", argv: [], envSet: {}, truth: "alpha-secret-one" },
  { fixture: "a3", argv: [], envSet: {}, truth: "charlie-config-secret" },
  { fixture: "b1", argv: [], envSet: {}, truth: "plug-one-hello" },
  { fixture: "c1", argv: ["0"], envSet: {}, truth: "result-add" },
  { fixture: "c1", argv: ["1"], envSet: {}, truth: "result-sub" },
  { fixture: "c1", argv: ["2"], envSet: {}, truth: "result-mul" },
  { fixture: "d2", argv: [], envSet: {}, truth: "feature-disabled" },
  {
    fixture: "d2",
    argv: [],
    envSet: { FEATURE_X: "1" },
    truth: "feature-enabled",
  },
];

const runsCache = new Map<string, Promise<Evidence[]>>();

const threeRuns = (testCase: StimulusCase): Promise<Evidence[]> => {
  const key = `${testCase.fixture}|${JSON.stringify(testCase.argv)}|${JSON.stringify(testCase.envSet)}`;
  const cached = runsCache.get(key);
  if (cached !== undefined) return cached;
  const pending = (async (): Promise<Evidence[]> => {
    const temp = await createTestTempDirectory("rea-runtime-eval-runs-");
    const records: Evidence[] = [];
    for (let index = 0; index < 3; index += 1) {
      const evidencePath = join(temp, `run-${index}.evidence.json`);
      const result = await runDynamicExecutionCommand({
        targetPath: binaryOf(testCase.fixture),
        argv: testCase.argv,
        envSet: testCase.envSet,
        evidencePath,
      });
      if (!result.ok) throw result.error;
      records.push(
        parseEvidence(JSON.parse(await readFile(evidencePath, "utf8"))),
      );
    }
    return records;
  })();
  runsCache.set(key, pending);
  return pending;
};

const verdictOf = (
  ledger: ClaimCheckLedger,
  records: readonly Evidence[],
  value: string,
): { state: string | null; reason: string | null } | undefined => {
  const claim = groupRuntimeEvidence(records)
    .flatMap((group) => group.claims)
    .find((candidate) => candidate.assertion.value === value);
  if (claim === undefined) return undefined;
  const resolved = resolveClaimCheckStates(ledger).get(claim.claim_id);
  return resolved === undefined
    ? undefined
    : { state: resolved.state, reason: resolved.reason };
};

const reportOutcomes = (
  ledger: ClaimCheckLedger,
): readonly RuntimeClaimCheckOutcome[] =>
  ledger.entries
    .filter((entry) => entry.kind === "adjudication")
    .map((entry) => ({
      claim_id: entry.claim_id,
      claim_version: entry.claim_version,
      state: entry.state,
      reason: runtimeAdjudicationReasonSchema.parse(entry.reason),
      validator: entry.validator,
      adjudication_digest: entry.record_digest,
      evidence_refs: entry.evidence_refs,
      observation_digest:
        entry.observed !== undefined && "observation_digest" in entry.observed
          ? entry.observed.observation_digest
          : "",
    }));

beforeAll(() => {
  buildFixtures();
}, 300_000);

describe("runtime claim-check evaluation: real replay sets", () => {
  for (const testCase of CASES) {
    it(`${testCase.fixture} ${JSON.stringify(testCase.argv)} ${JSON.stringify(testCase.envSet)}: ${testCase.truth} adjudicates supported from three real runs`, async () => {
      const records = await threeRuns(testCase);
      const result = await runRuntimeClaimCheck({ evidence: records });
      if (!result.ok) throw new Error(result.error.message);
      expect(verdictOf(result.value.ledger, records, testCase.truth)).toEqual({
        state: "supported",
        reason: "replay_recurred",
      });
      const report = buildRuntimeClaimCheckReport({
        validator: RUNTIME_CLAIM_VALIDATOR,
        truthSetId: `runtime-eval-${testCase.fixture}`,
        outcomes: reportOutcomes(result.value.ledger).map((entry) => ({
          ...entry,
          truth_state: "supported" as const,
        })),
        groups: [],
      });
      expect(report.precision).toBe(1);
      expect(report.coverage).toBe(1);
    }, 300_000);
  }

  it("is deterministic over the real a1 set: identical report digest across two adjudications", async () => {
    const records = await threeRuns(CASES[0]!);
    const first = await runRuntimeClaimCheck({ evidence: records });
    const second = await runRuntimeClaimCheck({ evidence: records });
    if (!first.ok || !second.ok) throw new Error("adjudication failed");
    expect(second.value.report_digest).toBe(first.value.report_digest);
    expect(second.value.ledger.ledger_id).toBe(first.value.ledger.ledger_id);
  }, 300_000);
});

describe("runtime claim-check evaluation: planted false claims against live witnesses", () => {
  it("refutes a cross-stimulus claim: result-sub filed under c1 s1 with two live s1 witnesses", async () => {
    const live = await threeRuns(CASES[3]!);
    const authored = runtimeEvidenceRecord({
      argv: ["0"],
      filed: ["result-sub"],
      pid: 991,
      subjectSha: sha256Of(binaryOf("c1")),
    });
    const records = [authored, live[0]!, live[1]!];
    const result = await runRuntimeClaimCheck({ evidence: records });
    if (!result.ok) throw new Error(result.error.message);
    expect(verdictOf(result.value.ledger, records, "result-sub")).toEqual({
      state: "refuted",
      reason: "replay_absent",
    });
    expect(
      verdictOf(result.value.ledger, records, "result-add")?.state,
    ).not.toBe("supported");
  }, 300_000);

  it("refutes a one-character mutation of the true value against live a1 witnesses", async () => {
    const live = await threeRuns(CASES[0]!);
    const authored = runtimeEvidenceRecord({
      filed: ["alpha-secret-onx"],
      pid: 992,
      subjectSha: sha256Of(binaryOf("a1")),
    });
    const records = [authored, live[0]!, live[1]!];
    const result = await runRuntimeClaimCheck({ evidence: records });
    if (!result.ok) throw new Error(result.error.message);
    expect(verdictOf(result.value.ledger, records, "alpha-secret-onx")).toEqual(
      { state: "refuted", reason: "replay_absent" },
    );
  }, 300_000);

  it("refutes a phantom row: filed by its record, absent from that record's own log", async () => {
    const live = await threeRuns(CASES[0]!);
    const authored = runtimeEvidenceRecord({
      filed: ["phantom-value"],
      logTexts: ["alpha-secret-one"],
      pid: 993,
      subjectSha: sha256Of(binaryOf("a1")),
    });
    const records = [authored, live[0]!, live[1]!];
    const result = await runRuntimeClaimCheck({ evidence: records });
    if (!result.ok) throw new Error(result.error.message);
    expect(verdictOf(result.value.ledger, records, "phantom-value")).toEqual({
      state: "refuted",
      reason: "record_inconsistent",
    });
  }, 300_000);
});

describe("runtime claim-check evaluation: the shipped MCP surface over real records", () => {
  it("adjudicates alpha-secret-one supported via adjudicate_runtime_claims, and unknown from the source record alone", async () => {
    const records = await threeRuns(CASES[0]!);
    const session = createTestBinarySession(() => {
      throw new Error("Runtime claim check must not start a deep provider");
    });
    const server = createServer(
      { kind: "session", session },
      { environment: { REA_MCP_TOOL_SURFACE: "full" } },
    );
    const client = new Client({ name: "runtime-eval", version: "1" });
    onTestFinished(async () => {
      await client.close();
      await server.close();
      await session.close();
    });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const root = await createTestTempDirectory("rea-runtime-eval-mcp-");
    const fullPath = join(root, "a1-runs.json");
    await writeFile(fullPath, JSON.stringify(records));
    const fullLedger = join(root, "ledger-full.json");
    const called = await client.callTool({
      name: "adjudicate_runtime_claims",
      arguments: { evidence_path: fullPath, ledger_path: fullLedger },
    });
    expect(called.isError).not.toBe(true);
    const outcome = called.structuredContent as {
      counts: { supported: number; refuted: number; unknown: number };
    };
    expect(outcome.counts).toEqual({ supported: 1, refuted: 0, unknown: 0 });
    const ledger = parseClaimCheckLedger(
      JSON.parse(await readFile(fullLedger, "utf8")),
    );
    expect(verdictOf(ledger, records, "alpha-secret-one")).toEqual({
      state: "supported",
      reason: "replay_recurred",
    });

    const soloPath = join(root, "a1-source-only.json");
    await writeFile(soloPath, JSON.stringify(records[0]));
    const soloLedger = join(root, "ledger-solo.json");
    const solo = await client.callTool({
      name: "adjudicate_runtime_claims",
      arguments: { evidence_path: soloPath, ledger_path: soloLedger },
    });
    expect(solo.isError).not.toBe(true);
    const soloOutcome = solo.structuredContent as {
      counts: { supported: number; refuted: number; unknown: number };
    };
    expect(soloOutcome.counts).toEqual({
      supported: 0,
      refuted: 0,
      unknown: 1,
    });
    const soloParsed = parseClaimCheckLedger(
      JSON.parse(await readFile(soloLedger, "utf8")),
    );
    expect(verdictOf(soloParsed, [records[0]!], "alpha-secret-one")).toEqual({
      state: "unknown",
      reason: "recurrence_unconfirmed",
    });
  }, 300_000);
});
