import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  parseClaimCheckLedger,
  resolveClaimCheckStates,
  type ClaimCheckLedger,
} from "../../domain/claimCheck/claimCheckLedger.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { groupRuntimeEvidence } from "./extractRuntimeClaims.js";
import { runRuntimeClaimCheck } from "./runRuntimeClaimCheck.js";

const SUBJECT_SHA = "ab".repeat(32);
const HOOKED = ["puts", "fputs", "printf", "fprintf", "write", "exit"];

interface RecordOptions {
  argv?: readonly string[];
  envSet?: Readonly<Record<string, string>>;
  filed?: readonly { value: string; channel?: string }[];
  logTexts?: readonly string[];
  pid?: number;
  limitations?: readonly string[];
  supervisorReason?: string;
  packMissing?: readonly string[];
  subjectSha?: string;
  parameters?: Record<string, unknown>;
}

const dynResult = (options: RecordOptions) => ({
  strings: (options.filed ?? []).map((row) => ({
    value: row.value,
    channel: row.channel ?? "puts",
  })),
  modules: [],
  symbols: [],
  output: { stdout: "", stderr: "", exit_code: 0 },
  execution: {
    hook_pack_version: "1.1.0",
    frida_version: "17.23.2",
    target_pid: options.pid ?? 4242,
    resume_observed: true,
    pack_ready: {
      hooked: HOOKED.filter(
        (hook) => !(options.packMissing ?? []).includes(hook),
      ),
      missing: [...(options.packMissing ?? [])],
    },
    supervisor: {
      reason: options.supervisorReason ?? "exited",
      peak_rss_bytes: 1000,
      wall_ms: 40 + (options.pid ?? 0),
    },
    budgets: {
      session_timeout_ms: 30000,
      deadline_ms: 75000,
      rss_cap_bytes: 3221225472,
    },
    containment: { survivors_after: [], breach: false },
  },
});

const logFor = (options: RecordOptions): unknown[] => {
  const texts =
    options.logTexts ?? (options.filed ?? []).map((row) => row.value);
  return [
    {
      type: "send",
      payload: {
        t: "pack_ready",
        version: "1.1.0",
        hooked: HOOKED.filter(
          (hook) => !(options.packMissing ?? []).includes(hook),
        ),
        missing: [...(options.packMissing ?? [])],
      },
    },
    ...texts.map((text) => ({
      type: "send",
      payload: { t: "puts", text },
    })),
  ];
};

const runtimeRecord = (options: RecordOptions): Evidence =>
  createEvidence(
    {
      path: "/fixtures/target",
      sha256: options.subjectSha ?? SUBJECT_SHA,
      format: "elf",
    },
    { id: "frida", name: "Frida", version: "17.23.2" },
    {
      operation: "execute_dynamically",
      parameters: options.parameters ?? {
        target_path: "/fixtures/target",
        argv: options.argv ?? [],
        env_set: options.envSet ?? {},
        session_timeout_ms: 30000,
        deadline_ms: 75000,
        rss_cap_bytes: 3221225472,
        evidence_path: "/tmp/e.json",
      },
      result: dynResult(options),
      rawResult: logFor(options),
      confidence: "observed",
      authority: "controlled-replay",
      limitations: options.limitations ?? [],
      evidenceLinks: [],
    },
  );

const verdictOf = (
  outcome: { ledger: ClaimCheckLedger },
  records: readonly Evidence[],
  value: string,
): { state: string | null; reason: string | null } | undefined => {
  const claim = groupRuntimeEvidence(records)
    .flatMap((group) => group.claims)
    .find((candidate) => candidate.assertion.value === value);
  if (claim === undefined) return undefined;
  const resolved = resolveClaimCheckStates(outcome.ledger).get(claim.claim_id);
  return resolved === undefined
    ? undefined
    : { state: resolved.state, reason: resolved.reason };
};

const run = async (evidence: readonly Evidence[]) => {
  const result = await runRuntimeClaimCheck({ evidence });
  if (!result.ok) throw new Error(`run failed: ${result.error.message}`);
  return result.value;
};

describe("runtime claim-check run: supported and unknown shapes", () => {
  it("supports a claim three agreeing records file and log, and the ledger round-trips", async () => {
    const records = [11, 22, 33].map((pid) =>
      runtimeRecord({ pid, filed: [{ value: "alpha-secret-one" }] }),
    );
    const outcome = await run(records);
    expect(outcome.counts).toEqual({ supported: 1, refuted: 0, unknown: 0 });
    expect(verdictOf(outcome, records, "alpha-secret-one")).toEqual({
      state: "supported",
      reason: "replay_recurred",
    });
    expect(
      parseClaimCheckLedger(JSON.parse(JSON.stringify(outcome.ledger))),
    ).toEqual(outcome.ledger);
  });

  it("is deterministic: a second adjudication of the same set yields the same report digest", async () => {
    const records = [11, 22, 33].map((pid) =>
      runtimeRecord({ pid, filed: [{ value: "alpha-secret-one" }] }),
    );
    const first = await run(records);
    const second = await run(records);
    expect(second.report_digest).toBe(first.report_digest);
    expect(second.ledger.ledger_id).toBe(first.ledger.ledger_id);
  });

  it("leaves a lone source record's claim unknown: recurrence unconfirmed", async () => {
    const records = [
      runtimeRecord({ pid: 11, filed: [{ value: "alpha-secret-one" }] }),
    ];
    const outcome = await run(records);
    expect(verdictOf(outcome, records, "alpha-secret-one")).toEqual({
      state: "unknown",
      reason: "recurrence_unconfirmed",
    });
  });

  it("leaves source plus one witness unconfirmed: the bar is two witnesses", async () => {
    const records = [11, 22].map((pid) =>
      runtimeRecord({ pid, filed: [{ value: "alpha-secret-one" }] }),
    );
    const outcome = await run(records);
    expect(verdictOf(outcome, records, "alpha-secret-one")).toEqual({
      state: "unknown",
      reason: "recurrence_unconfirmed",
    });
  });

  it("counts terminated witnesses as ineligible, never as absences", async () => {
    const records = [
      runtimeRecord({ pid: 11, filed: [{ value: "alpha-secret-one" }] }),
      runtimeRecord({
        pid: 22,
        filed: [{ value: "alpha-secret-one" }],
        supervisorReason: "deadline",
        limitations: ["run_terminated: deadline"],
      }),
      runtimeRecord({
        pid: 33,
        filed: [{ value: "alpha-secret-one" }],
        supervisorReason: "deadline",
        limitations: ["run_terminated: deadline"],
      }),
    ];
    const outcome = await run(records);
    expect(verdictOf(outcome, records, "alpha-secret-one")).toEqual({
      state: "unknown",
      reason: "recurrence_unconfirmed",
    });
  });

  it("adjudicates stimulus groups independently: no cross-group witnessing", async () => {
    const s1 = [11, 22, 33].map((pid) =>
      runtimeRecord({ pid, argv: ["0"], filed: [{ value: "result-add" }] }),
    );
    const s2 = [
      runtimeRecord({ pid: 44, argv: ["1"], filed: [{ value: "result-sub" }] }),
    ];
    const outcome = await run([...s1, ...s2]);
    expect(verdictOf(outcome, [...s1, ...s2], "result-add")).toEqual({
      state: "supported",
      reason: "replay_recurred",
    });
    expect(verdictOf(outcome, [...s1, ...s2], "result-sub")).toEqual({
      state: "unknown",
      reason: "recurrence_unconfirmed",
    });
  });
});

describe("runtime claim-check run: refuted and screened shapes", () => {
  it("refutes a claim no eligible witness reproduces and no volatile family explains", async () => {
    const records = [
      runtimeRecord({
        pid: 11,
        filed: [{ value: "alpha-secret-onx" }],
        logTexts: ["alpha-secret-onx"],
      }),
      runtimeRecord({ pid: 22, filed: [], logTexts: ["alpha-secret-one"] }),
      runtimeRecord({ pid: 33, filed: [], logTexts: ["alpha-secret-one"] }),
    ];
    const outcome = await run(records);
    expect(verdictOf(outcome, records, "alpha-secret-onx")).toEqual({
      state: "refuted",
      reason: "replay_absent",
    });
  });

  it("refutes a phantom row against its own record's complete log", async () => {
    const records = [
      runtimeRecord({
        pid: 11,
        filed: [{ value: "phantom-value" }],
        logTexts: ["alpha-secret-one"],
      }),
      runtimeRecord({ pid: 22, filed: [{ value: "alpha-secret-one" }] }),
      runtimeRecord({ pid: 33, filed: [{ value: "alpha-secret-one" }] }),
    ];
    const outcome = await run(records);
    expect(verdictOf(outcome, records, "phantom-value")).toEqual({
      state: "refuted",
      reason: "record_inconsistent",
    });
  });

  it("cannot call a phantom row inconsistent when its own record's log is incomplete", async () => {
    const records = [
      runtimeRecord({
        pid: 11,
        filed: [{ value: "phantom-value" }],
        logTexts: ["alpha-secret-one"],
        limitations: ["messages_truncated"],
      }),
      runtimeRecord({ pid: 22, filed: [{ value: "alpha-secret-one" }] }),
      runtimeRecord({ pid: 33, filed: [{ value: "alpha-secret-one" }] }),
    ];
    const outcome = await run(records);
    expect(verdictOf(outcome, records, "phantom-value")).toEqual({
      state: "unknown",
      reason: "record_incomplete",
    });
  });

  it("screens run-varying values as volatile instead of refuting them", async () => {
    const records = [
      runtimeRecord({ pid: 11, filed: [{ value: "run-10101" }] }),
      runtimeRecord({ pid: 22, filed: [{ value: "run-20202" }] }),
      runtimeRecord({ pid: 33, filed: [{ value: "run-30303" }] }),
    ];
    const outcome = await run(records);
    for (const value of ["run-10101", "run-20202", "run-30303"])
      expect(verdictOf(outcome, records, value)).toEqual({
        state: "unknown",
        reason: "value_volatile",
      });
  });

  it("marks a claim recurring in only some witnesses as partially recurred", async () => {
    const records = [
      runtimeRecord({ pid: 11, filed: [{ value: "flaky-value" }] }),
      runtimeRecord({
        pid: 22,
        filed: [],
        logTexts: ["flaky-value"],
      }),
      runtimeRecord({ pid: 33, filed: [], logTexts: ["other-value"] }),
    ];
    const outcome = await run(records);
    expect(verdictOf(outcome, records, "flaky-value")).toEqual({
      state: "unknown",
      reason: "recurrence_partial",
    });
  });
});

describe("runtime claim-check run: fail-closed inputs and the ledger chain", () => {
  it("aborts when a record cannot name its stimulus", async () => {
    const result = await runRuntimeClaimCheck({
      evidence: [
        runtimeRecord({
          pid: 11,
          parameters: { target_path: "/fixtures/target", env_set: {} },
        }),
      ],
    });
    expect(result.ok).toBe(false);
  });

  it("aborts when runtime records disagree about the subject", async () => {
    const result = await runRuntimeClaimCheck({
      evidence: [
        runtimeRecord({ pid: 11, filed: [{ value: "alpha-secret-one" }] }),
        runtimeRecord({
          pid: 22,
          filed: [{ value: "alpha-secret-one" }],
          subjectSha: "cd".repeat(32),
        }),
      ],
    });
    expect(result.ok).toBe(false);
  });

  it("writes the ledger file when a path is given, and a flipped byte breaks chain verification", async () => {
    const root = await mkdtemp(join(tmpdir(), "rea-runtime-claim-check-"));
    try {
      const ledgerPath = join(root, "ledger.json");
      const result = await runRuntimeClaimCheck({
        evidence: [11, 22, 33].map((pid) =>
          runtimeRecord({ pid, filed: [{ value: "alpha-secret-one" }] }),
        ),
        ledgerPath,
      });
      expect(result.ok).toBe(true);
      const text = await readFile(ledgerPath, "utf8");
      expect(parseClaimCheckLedger(JSON.parse(text)).summary.supported).toBe(1);
      const digestAt = text.indexOf('"record_digest": "') + 18;
      const flipped =
        text.slice(0, digestAt) +
        (text[digestAt] === "a" ? "b" : "a") +
        text.slice(digestAt + 1);
      expect(() => parseClaimCheckLedger(JSON.parse(flipped))).toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
