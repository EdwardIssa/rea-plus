import { describe, expect, it } from "vitest";

import {
  applyDecisionRule,
  aggregateBenchmark,
  median,
  scoreClaims,
  truthItems,
} from "../../../scripts/ablation/scorer.mjs";

const truth = {
  strings: ["alpha-secret-one"],
  loaded_modules: [],
  resolved_symbols: [],
  executed_functions: { s1: ["main", "reveal"] },
  call_edges: { s1: [["main", "reveal"]] },
  outputs: { s1: "MARK:main\nMARK:reveal\nalpha-secret-one\n" },
  function_markers: { main: "MARK:main", reveal: "MARK:reveal" },
};

describe("scorer", () => {
  it("builds the truth item vocabulary", () => {
    const items = truthItems(truth as never);
    expect(items.has("string:alpha-secret-one")).toBe(true);
    expect(items.has("function:reveal@s1")).toBe(true);
    expect(items.has("edge:main>reveal@s1")).toBe(true);
    expect(items.size).toBe(4);
  });

  it("scores a perfect dynamic claim set at success 1 and FP 0", () => {
    const claims = {
      items: new Set(truthItems(truth as never)),
      outputs: new Map([["s1", truth.outputs.s1]]),
    };
    const score = scoreClaims(truth as never, claims as never);
    expect(score.success).toBe(1);
    expect(score.fp_rate).toBe(0);
    expect(score.truth).toBe(5);
  });

  it("counts a claimed-but-wrong output as one false claim, not a recovery", () => {
    const claims = {
      items: new Set<string>(),
      outputs: new Map([["s1", "wrong\n"]]),
    };
    const score = scoreClaims(truth as never, claims as never);
    expect(score.recovered).toBe(0);
    expect(score.false_claims).toBe(1);
    expect(score.fp_rate).toBe(1);
  });

  it("reports FP rate null when an arm claims nothing", () => {
    const claims = { items: new Set<string>(), outputs: new Map() };
    const score = scoreClaims(truth as never, claims as never);
    expect(score.fp_rate).toBeNull();
    expect(score.success).toBe(0);
  });

  it("computes medians for odd and even counts", () => {
    expect(median([3, 1, 2])).toBe(2);
    expect(median([1, 2, 3, 4])).toBe(2.5);
  });
});

const aggregateWith = (
  gainByClass: Record<string, number>,
  fp: number | null,
  wallRatio: number,
) => {
  const classes: Record<string, unknown> = {};
  let totalTruth = 0;
  let totalRecoveredS = 0;
  let totalRecoveredD = 0;
  for (const [cls, gain] of Object.entries(gainByClass)) {
    const truthCount = 100;
    const recoveredS = 40;
    const recoveredD = 40 + gain;
    classes[cls] = {
      static: {
        truth: truthCount,
        claimed: 50,
        recovered: recoveredS,
        missed: truthCount - recoveredS,
        false_claims: 2,
        success: recoveredS / truthCount,
        fp_rate: 0.04,
      },
      dynamic: {
        truth: truthCount,
        claimed: 100,
        recovered: recoveredD,
        missed: truthCount - recoveredD,
        false_claims: fp === null ? 0 : Math.round(fp * 100),
        success: recoveredD / truthCount,
        fp_rate: fp,
      },
      static_wall_ms: 1000,
      dynamic_wall_ms: 1000 * wallRatio,
      static_peak_rss_bytes: 1,
      dynamic_peak_rss_bytes: 1,
      targets: 5,
    };
    totalTruth += truthCount;
    totalRecoveredS += recoveredS;
    totalRecoveredD += recoveredD;
  }
  const overall = {
    static: {
      truth: totalTruth,
      claimed: 50,
      recovered: totalRecoveredS,
      missed: totalTruth - totalRecoveredS,
      false_claims: 2,
      success: totalRecoveredS / totalTruth,
      fp_rate: 0.04,
    },
    dynamic: {
      truth: totalTruth,
      claimed: 100,
      recovered: totalRecoveredD,
      missed: totalTruth - totalRecoveredD,
      false_claims: fp === null ? 0 : Math.round((fp ?? 0) * 100),
      success: totalRecoveredD / totalTruth,
      fp_rate: fp,
    },
    static_wall_ms: 1000,
    dynamic_wall_ms: 1000 * wallRatio,
    static_peak_rss_bytes: 1,
    dynamic_peak_rss_bytes: 1,
    targets: 20,
  };
  return { classes, overall };
};

describe("decision rule (pre-registered bands)", () => {
  it("BUILD when gain >= 25 in >= 3 classes, FP <= 5%, wall <= 3x", () => {
    const decision = applyDecisionRule(
      aggregateWith({ A: 30, B: 30, C: 30, D: 10 }, 0.03, 2) as never,
      true,
    );
    expect(decision.verdict).toBe("BUILD");
  });

  it("KILL when overall gain < 15 points", () => {
    const decision = applyDecisionRule(
      aggregateWith({ A: 10, B: 10, C: 10, D: 10 }, 0.01, 1) as never,
      true,
    );
    expect(decision.verdict).toBe("KILL");
  });

  it("KILL when dynamic FP rate > 10%", () => {
    const decision = applyDecisionRule(
      aggregateWith({ A: 40, B: 40, C: 40, D: 40 }, 0.2, 1) as never,
      true,
    );
    expect(decision.verdict).toBe("KILL");
  });

  it("KILL when containment is not proven, regardless of gain", () => {
    const decision = applyDecisionRule(
      aggregateWith({ A: 40, B: 40, C: 40, D: 40 }, 0.01, 1) as never,
      false,
    );
    expect(decision.verdict).toBe("KILL");
  });

  it("EXTEND in the FP 5-10% band", () => {
    const decision = applyDecisionRule(
      aggregateWith({ A: 30, B: 30, C: 30, D: 30 }, 0.07, 1) as never,
      true,
    );
    expect(decision.verdict).toBe("EXTEND");
  });

  it("EXTEND when gain is high but the wall ratio exceeds 3x", () => {
    const decision = applyDecisionRule(
      aggregateWith({ A: 30, B: 30, C: 30, D: 30 }, 0.01, 4) as never,
      true,
    );
    expect(decision.verdict).toBe("EXTEND");
  });

  it("EXTEND when gain concentrates in fewer than three classes", () => {
    const decision = applyDecisionRule(
      aggregateWith({ A: 60, B: 30, C: 0, D: 0 }, 0.01, 1) as never,
      true,
    );
    expect(decision.verdict).toBe("EXTEND");
  });
});

describe("aggregateBenchmark", () => {
  it("item-weights success across targets", () => {
    const rows = [
      {
        target_id: "a1",
        class: "A",
        static: {
          truth: 10,
          claimed: 5,
          recovered: 5,
          missed: 5,
          false_claims: 0,
          success: 0.5,
          fp_rate: 0,
        },
        dynamic: {
          truth: 10,
          claimed: 10,
          recovered: 10,
          missed: 0,
          false_claims: 0,
          success: 1,
          fp_rate: 0,
        },
        static_wall_ms: 100,
        dynamic_wall_ms: 200,
        static_peak_rss_bytes: 10,
        dynamic_peak_rss_bytes: 20,
      },
      {
        target_id: "a2",
        class: "A",
        static: {
          truth: 30,
          claimed: 5,
          recovered: 0,
          missed: 30,
          false_claims: 5,
          success: 0,
          fp_rate: 1,
        },
        dynamic: {
          truth: 30,
          claimed: 30,
          recovered: 15,
          missed: 15,
          false_claims: 0,
          success: 0.5,
          fp_rate: 0,
        },
        static_wall_ms: 300,
        dynamic_wall_ms: 400,
        static_peak_rss_bytes: 30,
        dynamic_peak_rss_bytes: 40,
      },
    ];
    const aggregate = aggregateBenchmark(rows as never);
    expect(aggregate.overall.static.success).toBeCloseTo(5 / 40);
    expect(aggregate.overall.dynamic.success).toBeCloseTo(25 / 40);
    expect(aggregate.classes["A"]?.targets).toBe(2);
  });
});
