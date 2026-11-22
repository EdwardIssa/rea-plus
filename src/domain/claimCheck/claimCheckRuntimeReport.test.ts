import { describe, expect, it } from "vitest";

import { buildRuntimeClaimCheckReport } from "./claimCheckRuntimeReport.js";
import { RUNTIME_CLAIM_VALIDATOR } from "./runtimeReplayValidator.js";

const GROUP = {
  stimulus_digest: "e".repeat(64),
  records_presented: 3,
  eligible_witnesses: 2,
  ineligibility_by_cause: {
    containment: 0,
    terminated: 1,
    truncated: 0,
    pack_version_skew: 0,
    hook_missing: 0,
  },
  unfiled_observations: 1,
};

describe("runtime claim-check report", () => {
  it("reports precision and coverage side by side, unknowns by reason", () => {
    const report = buildRuntimeClaimCheckReport({
      validator: RUNTIME_CLAIM_VALIDATOR,
      truthSetId: "fixture-truth",
      groups: [GROUP],
      outcomes: [
        {
          claim_id: `cc_${"1".repeat(64)}`,
          claim_version: "a".repeat(64),
          state: "supported",
          reason: "replay_recurred",
          truth_state: "supported",
        },
        {
          claim_id: `cc_${"2".repeat(64)}`,
          claim_version: "a".repeat(64),
          state: "refuted",
          reason: "replay_absent",
          truth_state: "refuted",
        },
        {
          claim_id: `cc_${"3".repeat(64)}`,
          claim_version: "a".repeat(64),
          state: "unknown",
          reason: "recurrence_unconfirmed",
        },
      ],
    });
    expect(report.precision).toBe(1);
    expect(report.coverage).toBeCloseTo(2 / 3);
    expect(report.by_reason.recurrence_unconfirmed).toBe(1);
    expect(report.by_reason.replay_recurred).toBe(1);
    expect(report.groups).toEqual([GROUP]);
    expect(report.verdicts[2]?.truth_state).toBeNull();
  });

  it("keeps precision null without a truth set or a supported verdict", () => {
    const noTruth = buildRuntimeClaimCheckReport({
      validator: RUNTIME_CLAIM_VALIDATOR,
      truthSetId: null,
      groups: [],
      outcomes: [
        {
          claim_id: `cc_${"1".repeat(64)}`,
          claim_version: "a".repeat(64),
          state: "supported",
          reason: "replay_recurred",
        },
      ],
    });
    expect(noTruth.precision).toBeNull();
    const noSupported = buildRuntimeClaimCheckReport({
      validator: RUNTIME_CLAIM_VALIDATOR,
      truthSetId: "fixture-truth",
      groups: [],
      outcomes: [
        {
          claim_id: `cc_${"1".repeat(64)}`,
          claim_version: "a".repeat(64),
          state: "unknown",
          reason: "value_volatile",
        },
      ],
    });
    expect(noSupported.precision).toBeNull();
    expect(noSupported.coverage).toBe(0);
  });
});
