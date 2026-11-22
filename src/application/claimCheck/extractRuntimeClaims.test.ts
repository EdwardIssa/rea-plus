import { describe, expect, it } from "vitest";

import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  groupRuntimeEvidence,
  isRuntimeEvidence,
  stimulusOfRecord,
} from "./extractRuntimeClaims.js";

const SUBJECT_SHA = "ab".repeat(32);

const HOOKED = ["puts", "fputs", "printf", "fprintf"];

const dynResult = (values: readonly string[]) => ({
  strings: values.map((value) => ({ value, channel: "puts" as const })),
  modules: [],
  symbols: [],
  output: { stdout: "", stderr: "", exit_code: 0 },
  execution: {
    hook_pack_version: "1.1.0",
    frida_version: "17.23.2",
    target_pid: 4242,
    resume_observed: true,
    pack_ready: { hooked: HOOKED, missing: [] },
    supervisor: { reason: "exited", peak_rss_bytes: 1000, wall_ms: 50 },
    budgets: {
      session_timeout_ms: 30000,
      deadline_ms: 75000,
      rss_cap_bytes: 3221225472,
    },
    containment: { survivors_after: [], breach: false },
  },
});

const runtimeRecord = (input: {
  argv?: readonly string[];
  envSet?: Readonly<Record<string, string>>;
  filed?: readonly string[];
  pid?: number;
  parameters?: Record<string, unknown>;
}): Evidence =>
  createEvidence(
    { path: "/fixtures/target", sha256: SUBJECT_SHA, format: "elf" },
    { id: "frida", name: "Frida", version: "17.23.2" },
    {
      operation: "execute_dynamically",
      parameters: input.parameters ?? {
        target_path: "/fixtures/target",
        argv: input.argv ?? [],
        env_set: input.envSet ?? {},
        session_timeout_ms: 30000,
        deadline_ms: 75000,
        rss_cap_bytes: 3221225472,
        evidence_path: "/tmp/e.json",
      },
      result: dynResult(input.filed ?? []),
      rawResult: [],
      confidence: "observed",
      authority: "controlled-replay",
      evidenceLinks: [],
    },
  );

describe("runtime claim extraction", () => {
  it("recognizes only Frida execute_dynamically records as runtime sources", () => {
    expect(isRuntimeEvidence(runtimeRecord({}))).toBe(true);
    const other = createEvidence(
      { path: "/fixtures/target", sha256: SUBJECT_SHA, format: "elf" },
      { id: "ghidra", name: "Ghidra", version: "12.1.4" },
      {
        operation: "list_strings",
        parameters: {},
        result: [],
        evidenceLinks: [],
      },
    );
    expect(isRuntimeEvidence(other)).toBe(false);
  });

  it("groups by stimulus and unions filed rows with every filing record as a source", () => {
    const first = runtimeRecord({ argv: ["0"], filed: ["result-add"], pid: 1 });
    const second = runtimeRecord({
      argv: ["0"],
      filed: ["result-add", "extra-row"],
      pid: 2,
    });
    const otherStimulus = runtimeRecord({
      argv: ["1"],
      filed: ["result-sub"],
      pid: 3,
    });
    const groups = groupRuntimeEvidence([first, second, otherStimulus]);
    expect(groups).toHaveLength(2);
    const addGroup = groups.find(
      (group) => group.stimulusDigest === stimulusOfRecord(first).digest,
    );
    expect(addGroup?.records.map((record) => record.evidence_id)).toEqual(
      [first.evidence_id, second.evidence_id].sort(),
    );
    const add = addGroup?.claims.find(
      (claim) => claim.assertion.value === "result-add",
    );
    expect(add?.evidence_refs).toEqual(
      [first.evidence_id, second.evidence_id].sort(),
    );
    expect(add?.class).toBe("runtime-string");
    expect(
      addGroup?.claims.find((claim) => claim.assertion.value === "extra-row")
        ?.evidence_refs,
    ).toEqual([second.evidence_id]);
  });

  it("treats budget and path parameters as non-stimulus: records differing only there share a group", () => {
    const first = runtimeRecord({ argv: [], pid: 1 });
    const second = runtimeRecord({
      pid: 2,
      parameters: {
        target_path: "/elsewhere/target",
        argv: [],
        env_set: {},
        session_timeout_ms: 999,
        deadline_ms: 999,
        rss_cap_bytes: 1,
        evidence_path: "/tmp/other.json",
      },
    });
    expect(stimulusOfRecord(first).digest).toBe(
      stimulusOfRecord(second).digest,
    );
    expect(groupRuntimeEvidence([first, second])).toHaveLength(1);
  });

  it("dedupes a record presented twice: it is not its own second witness", () => {
    const record = runtimeRecord({ filed: ["alpha-secret-one"], pid: 7 });
    const groups = groupRuntimeEvidence([record, record]);
    expect(groups[0]?.records).toHaveLength(1);
  });

  it("aborts on a record whose parameters cannot yield a stimulus", () => {
    const malformed = runtimeRecord({
      parameters: { target_path: "/fixtures/target", env_set: {} },
    });
    expect(() => groupRuntimeEvidence([malformed])).toThrow(AnalysisInputError);
  });

  it("distinguishes stimuli by environment as well as argv", () => {
    const off = runtimeRecord({ envSet: {}, filed: ["feature-disabled"] });
    const on = runtimeRecord({
      envSet: { FEATURE_X: "1" },
      filed: ["feature-enabled"],
    });
    expect(groupRuntimeEvidence([off, on])).toHaveLength(2);
  });
});
