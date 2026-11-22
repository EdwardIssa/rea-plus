import { z } from "zod";

import { digestSchema, prefixedDigestSchema } from "../digests.js";
import type { AdjudicationState } from "./stringClaimValidator.js";

/** The runtime replay validator's identity, recorded on every verdict. */
export const RUNTIME_CLAIM_VALIDATOR = {
  id: "rea-runtime-replay",
  version: "1.0.0",
} as const;

/**
 * Reason vocabulary for runtime-claim verdicts; every verdict names one.
 * Class-owned: the ledger's reason union widens with exactly these values.
 */
export const runtimeAdjudicationReasonSchema = z.enum([
  "replay_recurred",
  "replay_absent",
  "record_inconsistent",
  "record_incomplete",
  "recurrence_unconfirmed",
  "recurrence_partial",
  "value_volatile",
  "assertion_malformed",
]);
export type RuntimeAdjudicationReason = z.infer<
  typeof runtimeAdjudicationReasonSchema
>;

/**
 * What one runtime adjudication observed, in place of the byte shape: the
 * claim's source records, the eligible witnesses that carried the verdict,
 * and a digest of the primary source record's re-derived observation set.
 */
export const replayObservedSchema = z.strictObject({
  source_evidence_ids: z.array(prefixedDigestSchema("ev")),
  witness_evidence_ids: z.array(prefixedDigestSchema("ev")),
  eligible_witnesses: z.int().min(0),
  recurring_witnesses: z.int().min(0),
  observation_digest: digestSchema,
});
export type RuntimeReplayObserved = z.infer<typeof replayObservedSchema>;

/** One runtime validator decision: a state, its reason, and its replay shape. */
export interface RuntimeClaimVerdict {
  readonly state: AdjudicationState;
  readonly reason: RuntimeAdjudicationReason;
  readonly observed: RuntimeReplayObserved;
}
