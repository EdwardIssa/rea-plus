import type {
  DynamicAccountedProcess,
  DynamicContainment,
  DynamicDescendantAccounting,
} from "./dynamicObservation.js";

/**
 * Compose the Evidence containment verdict from the subreaper worker's
 * descendant accounting. Pure: the caller supplies the accounting the
 * worker published plus the post-settle liveness facts it measured
 * against that accounting, and this function decides what may be claimed.
 *
 * Sourcing rules (the verdict is only ever as strong as its accounting):
 * - No accounting, or accounting from a worker that could not prove it
 *   held the subreaper role, yields an UNVERIFIED verdict: `breach` is
 *   null and no survivor claim is made either way. An unmeasured run
 *   never reads as a clean run.
 * - With armed accounting, the survivors are the accounted descendants
 *   the caller found still alive after the settle (same pid, same exe),
 *   plus any target-image processes a post-settle sweep found — the
 *   sweep acts as a falsifier only; it can add a survivor the accounting
 *   somehow missed, it can never clear one the accounting recorded.
 * - Accounted descendants not among the survivors are the reaped set:
 *   processes the shim's accounting saw inside the run and that are gone
 *   by the verdict, named by exe image so an escapee that changed its
 *   image is still named.
 */
export interface ContainmentVerdictInput {
  readonly accounting: DynamicDescendantAccounting | null;
  /** Accounted `remaining` processes verified still alive post-settle. */
  readonly aliveAccounted: readonly DynamicAccountedProcess[];
  /** Target-image process names found by the post-settle sweep. */
  readonly sweepSurvivors: readonly string[];
}

export const composeContainmentVerdict = (
  input: ContainmentVerdictInput,
): DynamicContainment => {
  const accounting = input.accounting;
  if (accounting === null || !accounting.subreaper_armed)
    return {
      verified: false,
      source: "unavailable",
      survivors_after: [],
      breach: null,
      reaped_descendants: [],
    };
  const survivorNames = new Set<string>();
  for (const process of input.aliveAccounted) survivorNames.add(process.exe);
  for (const name of input.sweepSurvivors) survivorNames.add(name);
  const survivors_after = [...survivorNames].sort();
  const reaped = new Set<string>();
  for (const list of [accounting.observed, accounting.remaining])
    for (const process of list)
      if (!survivorNames.has(process.exe)) reaped.add(process.exe);
  return {
    verified: true,
    source: "subreaper_accounting",
    survivors_after,
    breach: survivors_after.length > 0,
    reaped_descendants: [...reaped].sort(),
  };
};

/**
 * True when the accounting's stored lists were capped below the true
 * totals it counted, so a reader knows the named sets are a prefix of
 * what the accounting observed (the counts remain exact).
 */
export const containmentAccountingTruncated = (
  accounting: DynamicDescendantAccounting,
): boolean =>
  accounting.observed_count > accounting.observed.length ||
  accounting.remaining_count > accounting.remaining.length;
