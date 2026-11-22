import { z } from "zod";

import { prefixedDigestSchema } from "../digests.js";
import { dynamicSupervisorOutcomeSchema } from "./dynamicObservation.js";

/**
 * Budgets for one dynamic-execution run. The defaults are the ablation's
 * proven envelope (scripts/ablation/runBenchmark.mjs): a 30 s worker
 * session, a supervisor deadline derived as session + 45 s, and a 3 GiB
 * tree-RSS cap owned here as a domain constant, independently of the
 * Ghidra heap policy's identical value.
 */
export const DYNAMIC_EXECUTION_DEFAULT_SESSION_TIMEOUT_MS = 30_000;
export const DYNAMIC_EXECUTION_DEADLINE_GRACE_MS = 45_000;
export const DYNAMIC_EXECUTION_DEFAULT_RSS_CAP_BYTES = 3_221_225_472;
export const DYNAMIC_EXECUTION_MIN_SESSION_TIMEOUT_MS = 1_000;
export const DYNAMIC_EXECUTION_MAX_SESSION_TIMEOUT_MS = 600_000;
export const DYNAMIC_EXECUTION_MAX_DEADLINE_MS = 900_000;
export const DYNAMIC_EXECUTION_MIN_RSS_CAP_BYTES = 256 * 1024 * 1024;

/** The provider states a dynamic-execution surface can report. */
export const dynamicExecutionProviderStateSchema = z.enum([
  "absent",
  "loading",
  "ready",
]);
export type DynamicExecutionProviderState = z.infer<
  typeof dynamicExecutionProviderStateSchema
>;

/**
 * What one completed dynamic-execution run delivers to its surfaces. The
 * schema lives in the domain layer because contracts import domain only
 * (the claim-check boundary lesson). `failed` belongs to the shape for
 * completeness; a failed run is delivered as an AnalysisError instead, with
 * no Evidence written.
 */
export const dynamicExecutionRunOutcomeSchema = z.strictObject({
  provider_state: dynamicExecutionProviderStateSchema,
  status: z.enum(["complete", "terminated", "failed"]),
  evidence_id: prefixedDigestSchema("ev").nullable(),
  evidence_path: z.string().min(1),
  script_source_sha256: z.string().nullable(),
  counts: z.strictObject({
    strings: z.int().min(0),
    modules: z.int().min(0),
    symbols: z.int().min(0),
  }),
  supervisor: dynamicSupervisorOutcomeSchema,
  limitations: z.array(z.string()),
});
export type DynamicExecutionRunOutcome = z.infer<
  typeof dynamicExecutionRunOutcomeSchema
>;

/** Caller-selected budgets for one run, after defaults are applied. */
export interface DynamicExecutionBudgets {
  readonly sessionTimeoutMs: number;
  readonly deadlineMs: number;
  readonly rssCapBytes: number;
}

/** Apply the spec defaults: deadline derives as session + 45 s when unset. */
export const resolveDynamicExecutionBudgets = (input: {
  readonly sessionTimeoutMs?: number;
  readonly deadlineMs?: number;
  readonly rssCapBytes?: number;
}): DynamicExecutionBudgets => {
  const sessionTimeoutMs =
    input.sessionTimeoutMs ?? DYNAMIC_EXECUTION_DEFAULT_SESSION_TIMEOUT_MS;
  return {
    sessionTimeoutMs,
    deadlineMs:
      input.deadlineMs ??
      sessionTimeoutMs + DYNAMIC_EXECUTION_DEADLINE_GRACE_MS,
    rssCapBytes: input.rssCapBytes ?? DYNAMIC_EXECUTION_DEFAULT_RSS_CAP_BYTES,
  };
};
