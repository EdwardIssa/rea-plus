/**
 * Deterministic scorer + pre-registered decision rule for the
 * dynamic-execution ablation (spec sections 2 and 5). No model in the loop.
 * The rule is applied mechanically; this module never adjusts it.
 */
import {
  edgeItem,
  functionItem,
  moduleItem,
  stringItem,
  symbolItem,
} from "./claims.mjs";

/** All scored item keys for one target's truth file. */
export const truthItems = (truth) => {
  const items = new Set();
  for (const v of truth.strings) items.add(stringItem(v));
  for (const v of truth.loaded_modules) items.add(moduleItem(v));
  for (const v of truth.resolved_symbols) items.add(symbolItem(v));
  for (const [stimulus, fns] of Object.entries(truth.executed_functions))
    for (const fn of fns) items.add(functionItem(fn, stimulus));
  for (const [stimulus, edges] of Object.entries(truth.call_edges))
    for (const [c, f] of edges) items.add(edgeItem(c, f, stimulus));
  return items;
};

export const truthOutputStimuli = (truth) => Object.keys(truth.outputs);

/**
 * Score one claim set against one target's truth.
 * claims: { items: Set<string>, outputs: Map<stimulus, string> }.
 * Output items: one truth item per stimulus in truth.outputs; recovered iff
 * the claimed text equals the truth text; a claimed-but-different text is one
 * false claim.
 */
export const scoreClaims = (truth, claims) => {
  const truthSet = truthItems(truth);
  let recovered = 0;
  let falseClaims = 0;
  for (const item of claims.items) {
    if (truthSet.has(item)) recovered++;
    else falseClaims++;
  }
  let outputTruth = 0;
  let outputRecovered = 0;
  for (const [stimulus, expected] of Object.entries(truth.outputs)) {
    outputTruth++;
    if (claims.outputs.has(stimulus)) {
      if (claims.outputs.get(stimulus) === expected) outputRecovered++;
      else falseClaims++;
    }
  }
  const truthCount = truthSet.size + outputTruth;
  const claimedCount = claims.items.size + claims.outputs.size;
  const recoveredCount = recovered + outputRecovered;
  return {
    truth: truthCount,
    claimed: claimedCount,
    recovered: recoveredCount,
    missed: truthCount - recoveredCount,
    false_claims: falseClaims,
    success: truthCount === 0 ? 0 : recoveredCount / truthCount,
    fp_rate: claimedCount === 0 ? null : falseClaims / claimedCount,
  };
};

export const median = (values) => {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? sorted[mid]
    : (sorted[mid - 1] + sorted[mid]) / 2;
};

const sumScores = (scores) => {
  const total = {
    truth: 0,
    claimed: 0,
    recovered: 0,
    missed: 0,
    false_claims: 0,
  };
  for (const s of scores) {
    total.truth += s.truth;
    total.claimed += s.claimed;
    total.recovered += s.recovered;
    total.missed += s.missed;
    total.false_claims += s.false_claims;
  }
  total.success = total.truth === 0 ? 0 : total.recovered / total.truth;
  total.fp_rate =
    total.claimed === 0 ? null : total.false_claims / total.claimed;
  return total;
};

/**
 * Combine per-target median-repetition score rows (already item-summed per
 * target) into class and overall rows. Input shape:
 * [{ target_id, class, static: scoreClaimsRow, dynamic: scoreClaimsRow,
 *    static_wall_ms, dynamic_wall_ms, static_peak_rss_bytes,
 *    dynamic_peak_rss_bytes }]
 * Class/overall success and FP are item-weighted (summed counts), per spec:
 * task success = recovered / truth items over the whole set.
 */
export const aggregateBenchmark = (perTarget) => {
  const byClass = {};
  for (const row of perTarget) {
    byClass[row.class] ??= [];
    byClass[row.class].push(row);
  }
  const summarize = (rows) => ({
    static: sumScores(rows.map((r) => r.static)),
    dynamic: sumScores(rows.map((r) => r.dynamic)),
    static_wall_ms: median(rows.map((r) => r.static_wall_ms)),
    dynamic_wall_ms: median(rows.map((r) => r.dynamic_wall_ms)),
    static_peak_rss_bytes: median(rows.map((r) => r.static_peak_rss_bytes)),
    dynamic_peak_rss_bytes: median(rows.map((r) => r.dynamic_peak_rss_bytes)),
    targets: rows.length,
  });
  const classes = {};
  for (const [cls, rows] of Object.entries(byClass))
    classes[cls] = summarize(rows);
  return { classes, overall: summarize(perTarget) };
};

/**
 * The pre-registered decision rule (spec section 5), applied mechanically.
 * Inputs: the aggregateBenchmark result + containment status.
 */
export const applyDecisionRule = (aggregate, containmentOk) => {
  const { overall, classes } = aggregate;
  const gainPoints = (overall.dynamic.success - overall.static.success) * 100;
  const fp = overall.dynamic.fp_rate;
  const wallRatio =
    overall.static_wall_ms === 0
      ? Infinity
      : overall.dynamic_wall_ms / overall.static_wall_ms;
  const classGains = {};
  for (const [cls, row] of Object.entries(classes))
    classGains[cls] = (row.dynamic.success - row.static.success) * 100;
  const classesWithGain25 = Object.values(classGains).filter(
    (g) => g >= 25,
  ).length;
  const inputs = {
    gain_points: gainPoints,
    dynamic_fp_rate: fp,
    wall_ratio: wallRatio,
    class_gains_points: classGains,
    classes_with_gain_at_least_25: classesWithGain25,
    containment_ok: containmentOk,
  };
  const reasons = [];
  let verdict;
  const kill =
    gainPoints < 15 || (fp !== null && fp > 0.1) || containmentOk === false;
  if (kill) {
    verdict = "KILL";
    if (gainPoints < 15)
      reasons.push(`gain ${gainPoints.toFixed(1)} points < 15`);
    if (fp !== null && fp > 0.1)
      reasons.push(`dynamic FP rate ${(fp * 100).toFixed(1)}% > 10%`);
    if (containmentOk === false)
      reasons.push("containment could not be re-proven");
  } else if (
    gainPoints >= 25 &&
    classesWithGain25 >= 3 &&
    fp !== null &&
    fp <= 0.05 &&
    wallRatio <= 3
  ) {
    verdict = "BUILD";
    reasons.push(
      `gain ${gainPoints.toFixed(1)} points >= 25 in ${classesWithGain25} classes, FP ${(fp * 100).toFixed(1)}% <= 5%, wall ratio ${wallRatio.toFixed(2)} <= 3`,
    );
  } else {
    verdict = "EXTEND";
    if (gainPoints >= 15 && gainPoints < 25)
      reasons.push(`gain ${gainPoints.toFixed(1)} points in the 15-25 band`);
    if (fp !== null && fp > 0.05 && fp <= 0.1)
      reasons.push(
        `dynamic FP rate ${(fp * 100).toFixed(1)}% in the 5-10% band`,
      );
    if (classesWithGain25 < 3 && gainPoints >= 25)
      reasons.push("gain concentrates in fewer than three classes");
    if (wallRatio > 3) reasons.push(`wall ratio ${wallRatio.toFixed(2)} > 3`);
    if (fp === null)
      reasons.push("dynamic arm claimed nothing; FP rate is null");
    if (reasons.length === 0) reasons.push("between the BUILD and KILL bands");
  }
  return { verdict, inputs, reasons };
};
