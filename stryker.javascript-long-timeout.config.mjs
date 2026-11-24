// Long-timeout VARIANT of stryker.javascript.config.mjs — measurement
// only, not the standing gate config. Do not use for pass/fail gating.
//
// Purpose: the pilot's finalize ranges of javascriptStaticAnalysis.ts
// recorded a ~37-40% timeout share at the standing ceiling
// (timeoutMS 30000 x timeoutFactor 1.5 = 45 s per mutant test run), and
// timeouts count as detected, which left the finalize score bounded
// between 93.04 (all timeouts detected) and 55.7 (none detected). This
// variant raises the ceiling to 200000 x 1.5 = 300 s per mutant test
// run so slow-but-finite mutants convert to assertion verdicts
// (killed or survived). Mutants that still exceed 300 s are reported
// as unconverted at that named ceiling.
//
// It pairs with vitest.javascript-mutation-long-timeout.config.ts,
// whose per-test cap (600 s) sits above this ceiling so Vitest never
// pre-empts a verdict. Incremental mode is off so a conversion run
// re-measures every mutant in scope instead of reusing a status
// recorded at the lower ceiling. Everything else (mutate scope,
// checkers, thresholds, reporters) is inherited unchanged; per-file
// rows remain the comparable unit, and scores from this variant are
// reported separately from standard-config scores, never blended.

import base from "./stryker.javascript.config.mjs";

/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
const config = {
  ...base,
  timeoutMS: 200_000,
  incremental: false,
  vitest: {
    ...base.vitest,
    configFile: "vitest.javascript-mutation-long-timeout.config.ts",
  },
};

export default config;
