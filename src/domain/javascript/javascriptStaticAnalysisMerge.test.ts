import { expect, it } from "vitest";
import { parseJavaScriptSource } from "./javascriptSourceParser.js";
import { partitionMetroBundle } from "./javascriptMetroBundlePartition.js";
import { analyzeParsedJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";
import type { JavaScriptStaticAnalysis } from "./javascriptStaticAnalysisTypes.js";
import { mergeJavaScriptStaticAnalyses } from "./javascriptStaticAnalysisMerge.js";

const MODULE_COUNT = 10;
const bundleSource = [
  "var registry = {};",
  ...Array.from({ length: MODULE_COUNT }, (_, i) =>
    [
      `__d(function (global, require, module, exports) {`,
      `  fetch("/api/items/${String(i)}");`,
      `  localStorage.setItem("key_${String(i)}", "value");`,
      `  localStorage.getItem("key_${String(i)}");`,
      `  crypto.subtle.digest("SHA-256", new Uint8Array(0));`,
      `}, ${String(i)}, []);`,
    ].join("\n"),
  ),
  "__r(0);",
].join("\n");

const shardAnalyze = (source: string): JavaScriptStaticAnalysis => {
  const parsed = parseJavaScriptSource(source, "bundle.js");
  expect(parsed).not.toBeNull();
  const partition = partitionMetroBundle(parsed!.program);
  expect(partition).not.toBeNull();
  const originalBody = parsed!.program.body;
  const analyses: JavaScriptStaticAnalysis[] = [];
  try {
    for (const shard of partition!.shards) {
      parsed!.program.body = [...shard.statements];
      analyses.push(analyzeParsedJavaScriptStaticSource(source, parsed!));
    }
  } finally {
    parsed!.program.body = originalBody;
  }
  return mergeJavaScriptStaticAnalyses(analyses);
};

it("merges per-shard static analyses into the whole-file result", () => {
  const whole = analyzeParsedJavaScriptStaticSource(
    bundleSource,
    parseJavaScriptSource(bundleSource, "bundle.js")!,
  );
  const merged = shardAnalyze(bundleSource);
  expect(merged.endpoints).toEqual(whole.endpoints);
  expect(merged.storage).toEqual(whole.storage);
  expect(merged.references).toEqual(whole.references);
  expect(merged.role_paths).toEqual(whole.role_paths);
  expect(merged.source_map_urls).toEqual(whole.source_map_urls);
  expect(merged.electron).toEqual(whole.electron);
  expect(merged.routes).toEqual(whole.routes);
  // One folded Metro registration carrying every module, matching whole-file.
  expect(merged.bundler_registrations).toEqual(whole.bundler_registrations);
  expect(merged.bundler_registrations[0]?.bundler).toBe("metro");
  expect(merged.bundler_registrations[0]?.modules.length).toBe(MODULE_COUNT);
  expect(merged.limitations).toEqual(whole.limitations);
  // Traversal accounting matches after root-node normalization.
  expect(merged.visited_ast_nodes).toBe(whole.visited_ast_nodes);
  expect(merged.analysis_coverage?.examination.status).toBe(
    whole.analysis_coverage?.examination.status,
  );
});

it("labels degraded shards as limited coverage, never as absent facts", () => {
  const parsed = parseJavaScriptSource(bundleSource, "bundle.js")!;
  const partition = partitionMetroBundle(parsed.program)!;
  const originalBody = parsed.program.body;
  const analyses: JavaScriptStaticAnalysis[] = [];
  try {
    parsed.program.body = [...partition.shards[1]!.statements];
    analyses.push(analyzeParsedJavaScriptStaticSource(bundleSource, parsed));
  } finally {
    parsed.program.body = originalBody;
  }
  const merged = mergeJavaScriptStaticAnalyses(analyses, [
    { moduleKey: "7", reason: "budget exceeded" },
  ]);
  expect(merged.analysis_coverage?.examination.status).toBe("limited");
  expect(merged.limitations.join(" ")).toContain(
    "Metro module 7 was not fully analyzed: budget exceeded",
  );
  expect(merged.analysis_coverage?.semantics.unknown_findings).toBeGreaterThan(
    0,
  );
});
