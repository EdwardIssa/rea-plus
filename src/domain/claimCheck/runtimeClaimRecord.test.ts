import { describe, expect, it } from "vitest";

import {
  buildRuntimeClaim,
  deriveRuntimeClaimId,
  deriveStimulusDigest,
  runtimeClaimRecordSchema,
  type RuntimeClaimSource,
} from "./runtimeClaimRecord.js";

const SUBJECT_SHA = "a".repeat(64);

const source = (
  overrides: Partial<RuntimeClaimSource> = {},
): RuntimeClaimSource => ({
  subjectSha256: SUBJECT_SHA,
  subjectFormat: "elf",
  evidenceRefs: [`ev_${"b".repeat(64)}`],
  providerId: "frida",
  providerVersion: "17.23.2",
  operation: "execute_dynamically",
  stimulusDigest: deriveStimulusDigest([], {}),
  ...overrides,
});

describe("runtime claim identity", () => {
  it("keys the claim on subject, stimulus, channel, and value", () => {
    const claim = buildRuntimeClaim(
      { value: "alpha-secret-one", channel: "puts" },
      source(),
    );
    expect(claim.class).toBe("runtime-string");
    expect(claim.label).toBe("pipeline-consensus");
    expect(claim.dependencies).toEqual([]);
    expect(claim.assertion).toEqual({
      value: "alpha-secret-one",
      channel: "puts",
      stimulus_digest: deriveStimulusDigest([], {}),
    });
    expect(claim.claim_id).toBe(
      deriveRuntimeClaimId(SUBJECT_SHA, claim.assertion),
    );
  });

  it("separates claims by stimulus: the same value under another stimulus is another claim", () => {
    const first = buildRuntimeClaim(
      { value: "result-add", channel: "puts" },
      source({ stimulusDigest: deriveStimulusDigest(["0"], {}) }),
    );
    const second = buildRuntimeClaim(
      { value: "result-add", channel: "puts" },
      source({ stimulusDigest: deriveStimulusDigest(["1"], {}) }),
    );
    expect(first.claim_id).not.toBe(second.claim_id);
  });

  it("separates claims by channel: the same value on two channels is two claims", () => {
    const viaPuts = buildRuntimeClaim(
      { value: "shared-value", channel: "puts" },
      source(),
    );
    const viaPrintf = buildRuntimeClaim(
      { value: "shared-value", channel: "printf_fmt" },
      source(),
    );
    expect(viaPuts.claim_id).not.toBe(viaPrintf.claim_id);
  });

  it("derives the stimulus digest from argv and env only, env key order aside", () => {
    expect(deriveStimulusDigest([], { A: "1", B: "2" })).toBe(
      deriveStimulusDigest([], { B: "2", A: "1" }),
    );
    expect(deriveStimulusDigest(["0"], {})).not.toBe(
      deriveStimulusDigest(["1"], {}),
    );
    expect(deriveStimulusDigest([], {})).not.toBe(
      deriveStimulusDigest([], { FEATURE_X: "1" }),
    );
  });

  it("sorts the claim's evidence refs and rejects a tampered identity", () => {
    const low = `ev_${"1".repeat(64)}`;
    const high = `ev_${"f".repeat(64)}`;
    const claim = buildRuntimeClaim(
      { value: "v", channel: "fputs" },
      source({ evidenceRefs: [high, low] }),
    );
    expect(claim.evidence_refs).toEqual([low, high]);
    expect(() =>
      runtimeClaimRecordSchema.parse({
        ...claim,
        claim_id: `cc_${"0".repeat(64)}`,
      }),
    ).toThrow();
    expect(() =>
      runtimeClaimRecordSchema.parse({
        ...claim,
        assertion: { ...claim.assertion, value: "other" },
      }),
    ).toThrow();
  });
});
