import { describe, expect, it } from "vitest";

import {
  buildClaimCheckReport,
  claimCheckReportSchema,
  type ClaimCheckOutcome,
} from "./claimCheckReport.js";
import { STRING_CLAIM_VALIDATOR } from "./stringClaimValidator.js";

const outcome = (
  digit: string,
  state: ClaimCheckOutcome["state"],
  reason: ClaimCheckOutcome["reason"],
  truth?: ClaimCheckOutcome["truth_state"],
): ClaimCheckOutcome => ({
  claim_id: `cc_${digit.repeat(64)}`,
  claim_version: "f".repeat(64),
  state,
  reason,
  ...(truth === undefined ? {} : { truth_state: truth }),
});

describe("claim-check report", () => {
  it("computes precision 1.0 and reason-coded coverage on a truth set", () => {
    const report = buildClaimCheckReport({
      validator: STRING_CLAIM_VALIDATOR,
      truthSetId: "fixture-truth-1",
      outcomes: [
        outcome("1", "supported", "bytes_match", "supported"),
        outcome("2", "supported", "bytes_match", "supported"),
        outcome("3", "refuted", "bytes_mismatch", "refuted"),
        outcome("4", "unknown", "address_unmapped", "unknown"),
        outcome("5", "unknown", "format_not_supported", "unknown"),
      ],
    });
    expect(report.precision).toBe(1);
    expect(report.coverage).toBeCloseTo(3 / 5);
    expect(report.by_state).toEqual({ supported: 2, refuted: 1, unknown: 2 });
    expect(report.by_reason.address_unmapped).toBe(1);
    expect(report.by_reason.format_not_supported).toBe(1);
    expect(report.totals).toEqual({ presented: 5, adjudicated: 3 });
  });

  it("drops precision below 1.0 when a refuted-truth claim is supported", () => {
    const report = buildClaimCheckReport({
      validator: STRING_CLAIM_VALIDATOR,
      truthSetId: "fixture-truth-1",
      outcomes: [
        outcome("1", "supported", "bytes_match", "supported"),
        outcome("2", "supported", "bytes_match", "refuted"),
      ],
    });
    expect(report.precision).toBe(0.5);
  });

  it("reports precision as null without a truth set and never combines scores", () => {
    const report = buildClaimCheckReport({
      validator: STRING_CLAIM_VALIDATOR,
      truthSetId: null,
      outcomes: [outcome("1", "supported", "bytes_match")],
    });
    expect(report.precision).toBeNull();
    expect(report.coverage).toBe(1);
    // The report shape carries precision and coverage as separate fields;
    // there is no combined scalar anywhere in the schema.
    expect(Object.keys(claimCheckReportSchema.shape)).not.toContain("score");
    expect(Object.keys(report)).not.toContain("groundedness");
  });
});
