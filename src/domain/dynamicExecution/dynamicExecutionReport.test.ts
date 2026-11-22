import { describe, expect, it } from "vitest";

import { resolveDynamicExecutionBudgets } from "./dynamicExecutionReport.js";

describe("resolveDynamicExecutionBudgets", () => {
  it("applies the ablation envelope defaults", () => {
    expect(resolveDynamicExecutionBudgets({})).toEqual({
      sessionTimeoutMs: 30_000,
      deadlineMs: 75_000,
      rssCapBytes: 3_221_225_472,
    });
  });

  it("derives the deadline as session + 45 s when only the session is set", () => {
    expect(resolveDynamicExecutionBudgets({ sessionTimeoutMs: 8_000 })).toEqual(
      {
        sessionTimeoutMs: 8_000,
        deadlineMs: 53_000,
        rssCapBytes: 3_221_225_472,
      },
    );
  });

  it("honors explicit budgets verbatim", () => {
    expect(
      resolveDynamicExecutionBudgets({
        sessionTimeoutMs: 5_000,
        deadlineMs: 9_000,
        rssCapBytes: 536_870_912,
      }),
    ).toEqual({
      sessionTimeoutMs: 5_000,
      deadlineMs: 9_000,
      rssCapBytes: 536_870_912,
    });
  });
});
