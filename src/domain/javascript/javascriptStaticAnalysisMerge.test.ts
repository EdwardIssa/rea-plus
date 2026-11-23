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
  // Without definition-statement facts there is nothing to salvage from.
  expect(merged.bundler_registrations[0]?.degraded_modules).toBeUndefined();
});

const LOCATION = {
  start: { line: 3, column: 0 },
  end: { line: 9, column: 2 },
} as const;

it("retains a budget-degraded module's identity as salvage on the folded registration", () => {
  const parsed = parseJavaScriptSource(bundleSource, "bundle.js")!;
  const partition = partitionMetroBundle(parsed.program)!;
  const originalBody = parsed.program.body;
  const analyses: JavaScriptStaticAnalysis[] = [];
  const degradedShard = partition.shards.find(
    ({ moduleKey }) => moduleKey === "7",
  )!;
  try {
    for (const shard of partition.shards) {
      if (shard.moduleKey === "7") continue;
      parsed.program.body = [...shard.statements];
      analyses.push(analyzeParsedJavaScriptStaticSource(bundleSource, parsed));
    }
  } finally {
    parsed.program.body = originalBody;
  }
  const merged = mergeJavaScriptStaticAnalyses(analyses, [
    {
      moduleKey: "7",
      reason: "budget exceeded",
      definition: {
        dependencyModuleKeys: degradedShard.dependencyModuleKeys,
        sourceBytes: degradedShard.bytes,
        location: LOCATION,
        defineOffset: degradedShard.statements[0]!.start ?? 0,
      },
    },
  ]);
  expect(merged.bundler_registrations).toHaveLength(1);
  const registration = merged.bundler_registrations[0]!;
  expect(registration.bundler).toBe("metro");
  // The nine analyzed modules keep their full facts; module 7 is not
  // silently folded into them and carries no invented analysis content.
  expect(
    registration.modules.map(({ module_key }) => module_key),
  ).not.toContain("7");
  expect(registration.modules).toHaveLength(MODULE_COUNT - 1);
  expect(registration.degraded_modules).toEqual([
    {
      module_key: "7",
      dependency_module_keys: [],
      source_bytes: degradedShard.bytes,
      location: LOCATION,
      reason: "budget exceeded",
    },
  ]);
  expect(merged.limitations.join(" ")).toContain(
    "Metro module 7 was not fully analyzed: budget exceeded",
  );
});

it("retains salvage when no analyzed shard produced a Metro registration", () => {
  const plain = analyzeParsedJavaScriptStaticSource(
    "var answer = 42;",
    parseJavaScriptSource("var answer = 42;", "plain.js")!,
  );
  expect(plain.bundler_registrations).toEqual([]);
  const merged = mergeJavaScriptStaticAnalyses(
    [plain],
    [
      {
        moduleKey: "3",
        reason: "budget exceeded",
        definition: {
          dependencyModuleKeys: ["4"],
          sourceBytes: 512,
          location: LOCATION,
          defineOffset: 128,
        },
      },
    ],
  );
  expect(merged.bundler_registrations).toHaveLength(1);
  const registration = merged.bundler_registrations[0]!;
  expect(registration.bundler).toBe("metro");
  expect(registration.chunk_keys).toEqual(["metro@128"]);
  expect(registration.modules).toEqual([]);
  expect(registration.degraded_modules).toEqual([
    {
      module_key: "3",
      dependency_module_keys: ["4"],
      source_bytes: 512,
      location: LOCATION,
      reason: "budget exceeded",
    },
  ]);
});
