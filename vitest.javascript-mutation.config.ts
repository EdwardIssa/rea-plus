import { defineConfig } from "vitest/config";

// Dedicated Vitest config for the JavaScript-domain Stryker pilot
// (stryker.javascript.config.mjs). It mirrors vitest.reverse-tools.config.ts:
// a flat config (no projects) listing the test lane that covers the mutated
// sources, so the Stryker vitest runner can map mutants to tests with
// per-test coverage. The lane is the JS gate lane: the co-located domain
// tests plus the application-layer tests that drive them.
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
    testTimeout: 60_000,
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
