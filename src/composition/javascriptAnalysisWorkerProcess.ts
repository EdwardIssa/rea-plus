import { setImmediate } from "node:timers/promises";
import { getHeapStatistics } from "node:v8";
import { moduleResolutionModeForJavaScriptReference } from "../domain/javascript/javascriptModuleResolutionMode.js";
import {
  parseJavaScriptSource,
  type ParsedJavaScriptSource,
} from "../domain/javascript/javascriptSourceParser.js";
import { analyzeParsedJavaScriptStaticSourceSteps } from "../domain/javascript/javascriptStaticAnalysis.js";
import { analyzeParsedJavaScriptSemanticsSteps } from "../domain/javascript/javascriptSemanticAnalysis.js";
import { failedJavaScriptStaticAnalysis } from "../domain/javascript/javascriptStaticAnalysisHelpers.js";
import {
  mergeJavaScriptModuleSemantics,
  projectJavaScriptModuleSemantics,
  type JavaScriptModuleSemanticIr,
} from "../domain/javascript/javascriptModuleSemanticIr.js";
import {
  partitionMetroBundle,
  type JavaScriptBundleShard,
  type JavaScriptMetroBundlePartition,
} from "../domain/javascript/javascriptMetroBundlePartition.js";
import {
  mergeJavaScriptStaticAnalyses,
  type JavaScriptDegradedShard,
} from "../domain/javascript/javascriptStaticAnalysisMerge.js";
import { resolveCrossShardRpcEndpoints } from "../domain/javascript/javascriptCrossShardRpcResolution.js";
import {
  mergeJavaScriptSemanticFileProjections,
  type JavaScriptSemanticFileProjection,
  type JavaScriptSemanticProjectionCapacity,
} from "../domain/javascript/javascriptSemanticFileProjection.js";
import {
  JavaScriptAnalysisGovernor,
  type JavaScriptGovernorStaticSignals,
} from "../domain/javascript/javascriptAnalysisGovernor.js";
import type { JavaScriptStaticAnalysis } from "../domain/javascript/javascriptStaticAnalysisTypes.js";
import type { JavaScriptArtifactFile } from "../domain/javascript/javascriptArtifactFiles.js";
import {
  javaScriptTransferByteBudget,
  measureJavaScriptModuleTransfer,
} from "../javascript/analysis/JavaScriptAnalysisTransfer.js";
import { AnalysisResourceConstraintError } from "../domain/analysisErrorCore.js";
import { projectJavaScriptSemanticFileSteps } from "../application/javascript/JavaScriptSemanticGraphBuilder.js";
import { completeJavaScriptAnalysisSteps } from "../application/javascript/JavaScriptAnalysisControl.js";
import {
  serveJavaScriptAnalysisWorker,
  type JavaScriptSourceWorkerAnalyzer,
} from "../javascript/analysis/JavaScriptAnalysisWorkerServer.js";

/** Per-module analysis can be forced back to whole-file with REA_JAVASCRIPT_SHARDING=off. */
const shardingEnabled = (): boolean =>
  process.env.REA_JAVASCRIPT_SHARDING !== "off";
/** The governor ships behind REA_JAVASCRIPT_GOVERNOR=on until benchmarks clear it. */
const governorEnabled = (): boolean =>
  process.env.REA_JAVASCRIPT_GOVERNOR === "on";

/**
 * Backstop time budget for one shard. Healthy modules finish in tens of
 * milliseconds; the budget exists so one pathological module degrades alone
 * instead of consuming the file's whole deadline.
 */
const shardBudgetMs = (shard: JavaScriptBundleShard): number =>
  Math.min(30_000, Math.max(2_000, 1_500 + shard.bytes / 4));

type Driven<Value> =
  | { readonly completed: true; readonly value: Value }
  | { readonly completed: false };

/** Drive bounded steps like the whole-file driver, with a hard time budget. */
const driveStepsWithBudget = async <Value>(
  steps: Iterator<void, Value, void>,
  budgetMs: number,
): Promise<Driven<Value>> => {
  const deadline = performance.now() + budgetMs;
  let yieldDeadline = performance.now() + 8;
  try {
    for (;;) {
      const step = steps.next();
      if (step.done) return { completed: true, value: step.value };
      const now = performance.now();
      if (now >= deadline) {
        steps.return?.();
        return { completed: false };
      }
      if (now >= yieldDeadline) {
        await setImmediate();
        yieldDeadline = performance.now() + 8;
      }
    }
  } catch (cause) {
    steps.return?.();
    throw cause;
  }
};

/** Release shard state eagerly when the worker heap passes half its limit. */
const collectIfHeapPressured = (): void => {
  if (process.memoryUsage().heapUsed > getHeapStatistics().heap_size_limit / 2)
    global.gc?.();
};

interface ShardStaticOutcome {
  readonly shard: JavaScriptBundleShard;
  readonly analysis: JavaScriptStaticAnalysis | null;
  readonly signals: JavaScriptGovernorStaticSignals;
}

/**
 * Analyze one Metro bundle per module: the single parse is viewed through
 * one shard's statements at a time, so each module gets its own binding
 * index, mutation index and budgets, and its AST-derived state is released
 * before the next module starts. Merged results keep the whole-file shapes
 * (one static record, one module record, one projection per file).
 */
const analyzeSharded = async (
  file: JavaScriptArtifactFile,
  parsed: ParsedJavaScriptSource,
  capacity: JavaScriptSemanticProjectionCapacity,
  callbacks: Parameters<JavaScriptSourceWorkerAnalyzer>[2],
  partition: JavaScriptMetroBundlePartition,
): Promise<{
  readonly module: JavaScriptModuleSemanticIr;
  readonly projection: JavaScriptSemanticFileProjection;
} | null> => {
  if (!file.text.included)
    throw new TypeError("JavaScript worker requires decoded source text");
  const source = file.text.value;
  const filePath = file.path;
  const program = parsed.program;
  const originalBody = program.body;
  const governor = governorEnabled() ? new JavaScriptAnalysisGovernor() : null;
  const outcomes: ShardStaticOutcome[] = [];
  const degraded: JavaScriptDegradedShard[] = [];
  try {
    await callbacks.phase("static");
    for (const shard of partition.shards) {
      program.body = [...shard.statements];
      const budget = shardBudgetMs(shard);
      const started = performance.now();
      const driven = await driveStepsWithBudget(
        analyzeParsedJavaScriptStaticSourceSteps(source, parsed),
        budget,
      );
      const durationMs = performance.now() - started;
      if (driven.completed) {
        outcomes.push({
          shard,
          analysis: driven.value,
          signals: {
            limited:
              driven.value.analysis_coverage?.examination.status === "limited",
            timedOut: false,
            slow: durationMs > budget * 0.75,
          },
        });
      } else {
        degraded.push({
          moduleKey: shard.moduleKey,
          reason: `static analysis exceeded its per-module time budget of ${String(Math.round(budget))} ms; the module's facts remain unknown`,
        });
        outcomes.push({
          shard,
          analysis: null,
          signals: { limited: true, timedOut: true, slow: true },
        });
      }
      collectIfHeapPressured();
    }
  } finally {
    program.body = originalBody;
  }
  const analyses = outcomes.flatMap(({ analysis }) =>
    analysis === null ? [] : [analysis],
  );
  if (analyses.length === 0)
    throw new AnalysisResourceConstraintError(
      "analyze_javascript_application",
      "memory",
      `Every module shard of ${filePath} exceeded its per-module time budget; no static facts could be retained`,
      { shard_count: partition.shards.length },
    );
  const mergedFacts = mergeJavaScriptStaticAnalyses(analyses, degraded);
  // Cross-shard RPC resolution runs on the merged facts only, in the
  // sharded path only; whole-file analysis output is untouched.
  const resolvedEndpoints = resolveCrossShardRpcEndpoints(mergedFacts);
  const facts =
    resolvedEndpoints.length > 0
      ? {
          ...mergedFacts,
          endpoints: [...mergedFacts.endpoints, ...resolvedEndpoints],
        }
      : mergedFacts;
  const resultBudgetBytes = await callbacks.checkpoint(facts);
  if (facts.parse_status === "failed") return null;
  if (resultBudgetBytes === 0)
    throw new AnalysisResourceConstraintError(
      "analyze_javascript_application",
      "memory",
      `The parent reserved its remaining result capacity for static observations; semantic analysis of ${filePath} was not started`,
      { semantic_result_budget_bytes: 0 },
    );
  const semanticDegradations: string[] = [];
  const moduleIrs: JavaScriptModuleSemanticIr[] = [];
  const projections: JavaScriptSemanticFileProjection[] = [];
  let remainingNodes = capacity.nodes;
  let remainingUnknowns = capacity.unknowns;
  let callPathsPending = true;
  try {
    await callbacks.phase("semantic");
    for (const outcome of outcomes) {
      const { shard, analysis } = outcome;
      const decision =
        governor?.observeStatic(shard.moduleKey, outcome.signals) ?? null;
      if (analysis === null) {
        governor?.settleDegraded(shard.moduleKey);
        continue;
      }
      if (decision !== null && !decision.runSemantic) {
        semanticDegradations.push(
          `Metro module ${shard.moduleKey ?? "(prelude)"} semantic analysis skipped: ${decision.reason ?? "governor degradation"}`,
        );
        governor?.settleDegraded(shard.moduleKey);
        continue;
      }
      program.body = [...shard.statements];
      const budget = shardBudgetMs(shard);
      const driven = await driveStepsWithBudget(
        analyzeParsedJavaScriptSemanticsSteps(
          parsed,
          moduleResolutionModeForJavaScriptReference(filePath, "static-import"),
          capacity.nodes,
        ),
        budget,
      );
      if (!driven.completed) {
        semanticDegradations.push(
          `Metro module ${shard.moduleKey ?? "(prelude)"} semantic analysis exceeded its per-module time budget of ${String(Math.round(budget))} ms; its semantic facts remain unknown`,
        );
        governor?.observeSemantic(shard.moduleKey, true);
        collectIfHeapPressured();
        continue;
      }
      const ir = driven.value;
      const disagreement =
        outcome.signals.limited !== (ir.coverage.status !== "complete");
      governor?.observeSemantic(shard.moduleKey, disagreement);
      moduleIrs.push(projectJavaScriptModuleSemantics(ir));
      const projection = await driveStepsWithBudget(
        projectJavaScriptSemanticFileSteps(
          file,
          ir,
          { nodes: remainingNodes, unknowns: remainingUnknowns },
          callPathsPending ? facts.electron.call_paths : [],
        ),
        budget,
      );
      callPathsPending = false;
      if (projection.completed) {
        projections.push(projection.value);
        remainingNodes -= projection.value.nodes.length;
        remainingUnknowns -= projection.value.unknowns.length;
      } else
        semanticDegradations.push(
          `Metro module ${shard.moduleKey ?? "(prelude)"} semantic projection exceeded its per-module time budget of ${String(Math.round(budget))} ms; its graph facts remain unknown`,
        );
      collectIfHeapPressured();
    }
  } finally {
    program.body = originalBody;
  }
  const labels = [
    ...semanticDegradations,
    ...(governor?.limitations() ?? []),
    ...(governor !== null && governor.fileMode() !== "nominal"
      ? [`Governor mode for this file: ${governor.fileMode()}.`]
      : []),
  ];
  const module: JavaScriptModuleSemanticIr =
    moduleIrs.length > 0
      ? mergeJavaScriptModuleSemantics(moduleIrs, labels)
      : {
          scopes: [],
          bindings: [],
          callables: [],
          moduleLinks: [],
          coverage: { status: "partial", omittedCount: null },
          limitations: labels,
        };
  const measured = measureJavaScriptModuleTransfer(
    module,
    javaScriptTransferByteBudget(resultBudgetBytes),
  );
  if (measured.retentionBytes > resultBudgetBytes)
    throw new AnalysisResourceConstraintError(
      "analyze_javascript_application",
      "memory",
      `Completed module facts for ${filePath} exceed the parent's offered result budget; static facts were retained`,
      {
        semantic_result_budget_bytes: resultBudgetBytes,
        module_transfer_bytes: measured.bytes,
      },
    );
  await callbacks.phase("projection");
  const projection: JavaScriptSemanticFileProjection =
    projections.length > 0
      ? mergeJavaScriptSemanticFileProjections(projections)
      : {
          roots: [],
          evidenceContexts: [],
          nodes: [],
          relations: [],
          unknowns: [],
          fingerprints: [],
          nodesTruncated: false,
        };
  return { module, projection };
};

const analyze: JavaScriptSourceWorkerAnalyzer = async (
  file,
  capacity,
  callbacks,
) => {
  if (!file.text.included)
    throw new TypeError("JavaScript worker requires decoded source text");
  await callbacks.phase("parse");
  let parsed = parseJavaScriptSource(file.text.value, file.path);
  if (parsed === null) {
    await callbacks.checkpoint(failedJavaScriptStaticAnalysis());
    return null;
  }
  const partition = shardingEnabled()
    ? partitionMetroBundle(parsed.program)
    : null;
  if (partition !== null)
    return analyzeSharded(file, parsed, capacity, callbacks, partition);
  await callbacks.phase("static");
  const facts = await completeJavaScriptAnalysisSteps(
    analyzeParsedJavaScriptStaticSourceSteps(file.text.value, parsed),
  );
  const resultBudgetBytes = await callbacks.checkpoint(facts);
  if (facts.parse_status === "failed") return null;
  if (resultBudgetBytes === 0)
    throw new AnalysisResourceConstraintError(
      "analyze_javascript_application",
      "memory",
      `The parent reserved its remaining result capacity for static observations; semantic analysis of ${file.path} was not started`,
      { semantic_result_budget_bytes: 0 },
    );
  await callbacks.phase("semantic");
  const ir = await completeJavaScriptAnalysisSteps(
    analyzeParsedJavaScriptSemanticsSteps(
      parsed,
      moduleResolutionModeForJavaScriptReference(file.path, "static-import"),
      capacity.nodes,
    ),
  );
  parsed = null;
  const module = projectJavaScriptModuleSemantics(ir);
  const measured = measureJavaScriptModuleTransfer(
    module,
    javaScriptTransferByteBudget(resultBudgetBytes),
  );
  if (measured.retentionBytes > resultBudgetBytes)
    throw new AnalysisResourceConstraintError(
      "analyze_javascript_application",
      "memory",
      `Completed module facts for ${file.path} exceed the parent's offered result budget; static facts were retained`,
      {
        semantic_result_budget_bytes: resultBudgetBytes,
        module_transfer_bytes: measured.bytes,
      },
    );
  await callbacks.phase("projection");
  const projection = await completeJavaScriptAnalysisSteps(
    projectJavaScriptSemanticFileSteps(
      file,
      ir,
      capacity,
      facts.electron.call_paths,
    ),
  );
  return { module, projection };
};

try {
  await serveJavaScriptAnalysisWorker(analyze);
} catch (cause: unknown) {
  process.stderr.write(
    `${cause instanceof Error ? cause.message : String(cause)}\n`,
  );
  process.exitCode = 1;
}
