// Stryker pilot for the JavaScript domain (src/domain/javascript).
//
// Standing scope is the whole domain source tree. Per the coding-frontier
// discipline, PR runs stay diff-scoped: pass --mutate with the changed files
// (or ranges, "file.ts:10-20") to override the scope below, and reserve the
// full-domain run for nightly/baseline measurement. Incremental mode is on
// so completed runs are not re-measured; it does not rescue an interrupted
// run (Stryker records results only when a run completes), so on a small
// host keep each run to one file or range.
//
// Two host-size lessons from the pilot, measured on ~1.5 shared CPUs and
// ~6 GB shared memory: (1) concurrency stays 2 — at 4, two vitest runners
// on the heaviest domain files (javascriptStaticAnalysis.ts and its
// end-to-end suites) exceed the memory limit and the host OOM-kills the
// run; (2) the break-threshold verdict compares the incremental-merged
// report, so a scoped run exits 1 until the accumulated measured set
// clears 75, even when the file it just measured scores above the gate.
// Read per-file rows, not the exit code, on scoped runs.
//
// The typescript checker needs the repo's typescript6 build linked into the
// Stryker packages first; `npm run test:mutation:javascript` runs
// scripts/prepare-reverse-tools-mutation.mjs before invoking Stryker (the
// script is shared with the reverse-tools mutation setup despite its name).
//
// Gate: mutation score break threshold 75 (80 is the "high" watermark the
// highest-risk modules are held to). The pilot baseline and survivor
// inventory live in the goal records, not in this repo.

/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
const config = {
  $schema: "./node_modules/@stryker-mutator/core/schema/stryker-schema.json",
  testRunner: "vitest",
  plugins: [
    "@stryker-mutator/typescript-checker",
    "@stryker-mutator/vitest-runner",
  ],
  vitest: {
    configFile: "vitest.javascript-mutation.config.ts",
    related: true,
  },
  checkers: ["typescript"],
  tsconfigFile: "tsconfig.javascript-mutation.json",
  typescriptChecker: {
    prioritizePerformanceOverAccuracy: true,
  },
  coverageAnalysis: "perTest",
  incremental: true,
  thresholds: { high: 80, low: 75, break: 75 },
  ignorePatterns: ["/.cache/rea-command-locks/**", "/coverage/**"],
  concurrency: 2,
  timeoutMS: 30000,
  reporters: ["clear-text", "progress", "html", "json"],
  jsonReporter: { fileName: "reports/mutation/javascript.json" },
  htmlReporter: { fileName: "reports/mutation/javascript.html" },
  mutate: [
    "src/domain/javascript/**/*.ts",
    "!src/domain/javascript/**/*.test.ts",
    "!src/domain/javascript/**/*.fixture.ts",
  ],
};

export default config;
