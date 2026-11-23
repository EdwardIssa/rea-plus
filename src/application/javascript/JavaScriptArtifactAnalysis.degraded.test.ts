import { expect, it } from "vitest";
import { analyzeAndAdoptJavaScriptArtifactFiles } from "./JavaScriptArtifactAnalysis.js";
import { createJavaScriptSemanticGraphProjection } from "./JavaScriptSemanticGraphBuilder.js";
import { parseJavaScriptSource } from "../../domain/javascript/javascriptSourceParser.js";
import { partitionMetroBundle } from "../../domain/javascript/javascriptMetroBundlePartition.js";
import { analyzeParsedJavaScriptStaticSource } from "../../domain/javascript/javascriptStaticAnalysis.js";
import { mergeJavaScriptStaticAnalyses } from "../../domain/javascript/javascriptStaticAnalysisMerge.js";
import { range } from "../../domain/javascript/javascriptStaticAnalysisHelpers.js";
import type { JavaScriptStaticAnalysis } from "../../domain/javascript/javascriptStaticAnalysisTypes.js";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import { ok } from "../../domain/result.js";

const BUNDLE = [
  "var registry = {};",
  ...Array.from(
    { length: 10 },
    (_, i) =>
      `__d(function (global, require, module, exports) { exports.value = ${String(i)}; }, ${String(i)}, [${String((i + 1) % 10)}]);`,
  ),
  "__r(0);",
].join("\n");

const REASON =
  "static analysis exceeded its per-module time budget of 2000 ms; the module's facts remain unknown";

/** Merge per-shard analyses with module 7 degraded, as the worker does. */
const degradedBundleAnalysis = (): JavaScriptStaticAnalysis => {
  const parsed = parseJavaScriptSource(BUNDLE, "bundle.js")!;
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
      analyses.push(analyzeParsedJavaScriptStaticSource(BUNDLE, parsed));
    }
  } finally {
    parsed.program.body = originalBody;
  }
  return mergeJavaScriptStaticAnalyses(analyses, [
    {
      moduleKey: "7",
      reason: REASON,
      definition: {
        dependencyModuleKeys: degradedShard.dependencyModuleKeys,
        sourceBytes: degradedShard.bytes,
        location: range(degradedShard.statements[0]!),
        defineOffset: degradedShard.statements[0]!.start ?? 0,
      },
    },
  ]);
};

it("surfaces a degraded module in record limitations and statistics", async () => {
  const file: JavaScriptArtifactFile = {
    path: "bundle.js",
    container_sha256: "a".repeat(64),
    sha256: "b".repeat(64),
    bytes: BUNDLE.length,
    inventory_artifact_id: "bundle.js",
    kind: "javascript",
    unpacked: false,
    text: { included: true, value: BUNDLE },
  };
  const javascript = degradedBundleAnalysis();
  const worker = {
    analyze: async () => ok({ javascript, module: null, projection: null }),
  };
  const outcome = await analyzeAndAdoptJavaScriptArtifactFiles(
    {
      files: [file],
      unavailable_relevant_files: [],
      containers: [],
      text_bytes_read: BUNDLE.length,
      invalid_utf8_files: 0,
    },
    worker,
    createJavaScriptSemanticGraphProjection(),
    async () => {},
  );
  expect(outcome.interruption).toBeNull();
  // The salvaged module counts as present, and as degraded.
  expect(outcome.analysis.modules).toBe(10);
  expect(outcome.analysis.degraded_modules).toBe(1);
  // A consumer reading only the record's top level sees the degradation.
  expect(outcome.analysis.limitations).toContain(
    `Metro module 7 was not fully analyzed: ${REASON}`,
  );
});
