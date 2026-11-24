import { defineConfig } from "vitest/config";

// Long-timeout variant of vitest.javascript-mutation.config.ts, used only
// by stryker.javascript-long-timeout.config.mjs for timeout-conversion
// measurement runs. It is identical to the standing mutation lane config
// except for testTimeout: the standing 60 s per-test cap sits below the
// variant's raised Stryker ceiling, so a slow mutant would be reported
// as killed by a Vitest timeout instead of by an assertion. Raising the
// per-test cap above the Stryker ceiling keeps every verdict an
// assertion verdict; a mutant that still cannot finish is stopped by
// the Stryker ceiling and reported as a timeout there.
const JAVASCRIPT_DOMAIN_MODULES = ["src/domain/javascript/**/*.ts"];

export default defineConfig({
  test: {
    include: [
      "src/domain/javascript/**/*.test.ts",
      "src/application/javascript/**/*.test.ts",
    ],
    pool: "forks",
    maxWorkers: 2,
    retry: 0,
    testTimeout: 600_000,
    runner: "./tests/processOwnershipRunner.ts",
    coverage: {
      enabled: false,
      provider: "v8",
      reportsDirectory: "coverage/javascript-mutation",
      include: JAVASCRIPT_DOMAIN_MODULES,
      reporter: ["text", "text-summary", "json"],
    },
  },
});
