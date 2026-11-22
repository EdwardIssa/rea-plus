import { z } from "zod";

import { digestSchema, prefixedDigestSchema } from "../digests.js";
import {
  adjudicationReasonSchema,
  adjudicationStateSchema,
  type AdjudicationReason,
  type AdjudicationState,
} from "./stringClaimValidator.js";

const reasonCountsSchema = z.strictObject({
  bytes_match: z.int().min(0),
  bytes_mismatch: z.int().min(0),
  address_unmapped: z.int().min(0),
  encoding_undeclared: z.int().min(0),
  artifact_missing: z.int().min(0),
  format_not_supported: z.int().min(0),
  assertion_malformed: z.int().min(0),
});

/** One adjudicated claim as a report lists it, with its truth state when known. */
export const claimCheckVerdictLineSchema = z.strictObject({
  claim_id: prefixedDigestSchema("cc"),
  claim_version: digestSchema,
  state: adjudicationStateSchema,
  reason: adjudicationReasonSchema,
  truth_state: adjudicationStateSchema.nullable(),
});
export type ClaimCheckVerdictLine = z.infer<typeof claimCheckVerdictLineSchema>;

/**
 * Validator quality over one presented claim set. Precision and coverage are
 * reported side by side and never combined into a single scalar score.
 * Precision is null when no truth set was supplied or no supported verdict
 * exists to judge; unknowns stay visible in by_reason, never dropped from
 * the coverage denominator.
 */
export const claimCheckReportSchema = z.strictObject({
  validator: z.strictObject({
    id: z.string().min(1),
    version: z.string().min(1),
  }),
  truth_set_id: z.string().min(1).nullable(),
  totals: z.strictObject({
    presented: z.int().min(0),
    adjudicated: z.int().min(0),
  }),
  by_state: z.strictObject({
    supported: z.int().min(0),
    refuted: z.int().min(0),
    unknown: z.int().min(0),
  }),
  by_reason: reasonCountsSchema,
  precision: z.number().min(0).max(1).nullable(),
  coverage: z.number().min(0).max(1),
  verdicts: z.array(claimCheckVerdictLineSchema),
});
export type ClaimCheckReport = z.infer<typeof claimCheckReportSchema>;

/** One outcome the report aggregates; truth_state is set only on truth sets. */
export interface ClaimCheckOutcome {
  readonly claim_id: string;
  readonly claim_version: string;
  readonly state: AdjudicationState;
  readonly reason: AdjudicationReason;
  readonly truth_state?: AdjudicationState;
}

const REASONS: readonly AdjudicationReason[] = [
  "bytes_match",
  "bytes_mismatch",
  "address_unmapped",
  "encoding_undeclared",
  "artifact_missing",
  "format_not_supported",
  "assertion_malformed",
];

/** Aggregate verdict outcomes into precision and coverage, per the fixed MVP definitions. */
export const buildClaimCheckReport = (input: {
  readonly validator: { readonly id: string; readonly version: string };
  readonly truthSetId: string | null;
  readonly outcomes: readonly ClaimCheckOutcome[];
}): ClaimCheckReport => {
  const byState = { supported: 0, refuted: 0, unknown: 0 };
  const byReason = Object.fromEntries(
    REASONS.map((reason) => [reason, 0]),
  ) as Record<AdjudicationReason, number>;
  let supportedVerdicts = 0;
  let trueSupported = 0;
  for (const outcome of input.outcomes) {
    byState[outcome.state] += 1;
    byReason[outcome.reason] += 1;
    if (outcome.state === "supported") {
      supportedVerdicts += 1;
      if (outcome.truth_state === "supported") trueSupported += 1;
    }
  }
  const presented = input.outcomes.length;
  const adjudicated = byState.supported + byState.refuted;
  return claimCheckReportSchema.parse({
    validator: input.validator,
    truth_set_id: input.truthSetId,
    totals: { presented, adjudicated },
    by_state: byState,
    by_reason: byReason,
    precision:
      input.truthSetId === null || supportedVerdicts === 0
        ? null
        : trueSupported / supportedVerdicts,
    coverage: presented === 0 ? 0 : adjudicated / presented,
    verdicts: input.outcomes.map((outcome) => ({
      claim_id: outcome.claim_id,
      claim_version: outcome.claim_version,
      state: outcome.state,
      reason: outcome.reason,
      truth_state: outcome.truth_state ?? null,
    })),
  });
};
