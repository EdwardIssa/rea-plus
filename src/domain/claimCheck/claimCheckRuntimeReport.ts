import { z } from "zod";

import { digestSchema, prefixedDigestSchema } from "../digests.js";
import { claimCheckLedgerSchema } from "./claimCheckLedger.js";
import {
  runtimeAdjudicationReasonSchema,
  type RuntimeAdjudicationReason,
  type WitnessIneligibilityCause,
} from "./runtimeReplayValidator.js";
import { adjudicationStateSchema } from "./stringClaimValidator.js";
import type { AdjudicationState } from "./stringClaimValidator.js";

const runtimeReasonCountsSchema = z.strictObject({
  replay_recurred: z.int().min(0),
  replay_absent: z.int().min(0),
  record_inconsistent: z.int().min(0),
  record_incomplete: z.int().min(0),
  recurrence_unconfirmed: z.int().min(0),
  recurrence_partial: z.int().min(0),
  value_volatile: z.int().min(0),
  assertion_malformed: z.int().min(0),
});

/** Witness accounting for one (subject, stimulus) group of a runtime run. */
export const runtimeGroupAccountingSchema = z.strictObject({
  stimulus_digest: digestSchema,
  records_presented: z.int().min(0),
  /** Distinct records that served as an eligible witness for some claim. */
  eligible_witnesses: z.int().min(0),
  /** Records excluded from some claim's witness set, by first cause. */
  ineligibility_by_cause: z.strictObject({
    containment: z.int().min(0),
    terminated: z.int().min(0),
    truncated: z.int().min(0),
    pack_version_skew: z.int().min(0),
    hook_missing: z.int().min(0),
  }),
  /** Observations re-derived from some log but filed in no record's rows. */
  unfiled_observations: z.int().min(0),
});
export type RuntimeGroupAccountingReport = z.infer<
  typeof runtimeGroupAccountingSchema
>;

/** One adjudicated runtime claim as a report lists it, with truth when known. */
export const runtimeClaimCheckVerdictLineSchema = z.strictObject({
  claim_id: prefixedDigestSchema("cc"),
  claim_version: digestSchema,
  state: adjudicationStateSchema,
  reason: runtimeAdjudicationReasonSchema,
  truth_state: adjudicationStateSchema.nullable(),
});
export type RuntimeClaimCheckVerdictLine = z.infer<
  typeof runtimeClaimCheckVerdictLineSchema
>;

/**
 * Validator quality over one presented runtime claim set. Precision and
 * coverage follow the claim-check definitions and are reported side by
 * side, never combined into a single scalar score. Precision is null when
 * no truth set was supplied or no supported verdict exists to judge;
 * unknowns stay visible in by_reason, never dropped from the denominator,
 * and a low-coverage run shows its witness shortfall by cause per group.
 */
export const runtimeClaimCheckReportSchema = z.strictObject({
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
  by_reason: runtimeReasonCountsSchema,
  precision: z.number().min(0).max(1).nullable(),
  coverage: z.number().min(0).max(1),
  groups: z.array(runtimeGroupAccountingSchema),
  verdicts: z.array(runtimeClaimCheckVerdictLineSchema),
});
export type RuntimeClaimCheckReport = z.infer<
  typeof runtimeClaimCheckReportSchema
>;

/** What one completed runtime claim-check run delivers to its surfaces. */
export const runtimeClaimCheckRunOutcomeSchema = z.strictObject({
  ledger: claimCheckLedgerSchema,
  ledger_path: z.string().nullable(),
  claims_considered: z.int().min(0),
  counts: z.strictObject({
    supported: z.int().min(0),
    refuted: z.int().min(0),
    unknown: z.int().min(0),
  }),
  stale_marked: z.int().min(0),
  report_digest: digestSchema,
});
export type RuntimeClaimCheckRunOutcome = z.infer<
  typeof runtimeClaimCheckRunOutcomeSchema
>;

/** One outcome the runtime report aggregates; truth_state only on truth sets. */
export interface RuntimeClaimCheckOutcome {
  readonly claim_id: string;
  readonly claim_version: string;
  readonly state: AdjudicationState;
  readonly reason: RuntimeAdjudicationReason;
  readonly truth_state?: AdjudicationState;
}

/** Per-group facts the report carries, in the application's group shape. */
export interface RuntimeGroupReportInput {
  readonly stimulus_digest: string;
  readonly records_presented: number;
  readonly eligible_witnesses: number;
  readonly ineligibility_by_cause: Readonly<
    Record<WitnessIneligibilityCause, number>
  >;
  readonly unfiled_observations: number;
}

const RUNTIME_REASONS: readonly RuntimeAdjudicationReason[] = [
  "replay_recurred",
  "replay_absent",
  "record_inconsistent",
  "record_incomplete",
  "recurrence_unconfirmed",
  "recurrence_partial",
  "value_volatile",
  "assertion_malformed",
];

/** Aggregate runtime verdict outcomes into precision and coverage. */
export const buildRuntimeClaimCheckReport = (input: {
  readonly validator: { readonly id: string; readonly version: string };
  readonly truthSetId: string | null;
  readonly outcomes: readonly RuntimeClaimCheckOutcome[];
  readonly groups: readonly RuntimeGroupReportInput[];
}): RuntimeClaimCheckReport => {
  const byState = { supported: 0, refuted: 0, unknown: 0 };
  const byReason = Object.fromEntries(
    RUNTIME_REASONS.map((reason) => [reason, 0]),
  ) as Record<RuntimeAdjudicationReason, number>;
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
  return runtimeClaimCheckReportSchema.parse({
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
    groups: input.groups.map((group) => ({
      stimulus_digest: group.stimulus_digest,
      records_presented: group.records_presented,
      eligible_witnesses: group.eligible_witnesses,
      ineligibility_by_cause: group.ineligibility_by_cause,
      unfiled_observations: group.unfiled_observations,
    })),
    verdicts: input.outcomes.map((outcome) => ({
      claim_id: outcome.claim_id,
      claim_version: outcome.claim_version,
      state: outcome.state,
      reason: outcome.reason,
      truth_state: outcome.truth_state ?? null,
    })),
  });
};
