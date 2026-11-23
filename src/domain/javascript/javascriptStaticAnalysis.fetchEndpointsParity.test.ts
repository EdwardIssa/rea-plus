import { expect, it } from "vitest";
import { parseJavaScriptSource } from "./javascriptSourceParser.js";
import { partitionMetroBundle } from "./javascriptMetroBundlePartition.js";
import { analyzeParsedJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";
import type { JavaScriptStaticAnalysis } from "./javascriptStaticAnalysisTypes.js";
import { mergeJavaScriptStaticAnalyses } from "./javascriptStaticAnalysisMerge.js";

// Fetch calls are recognized as network requests only while `fetch` is
// provably the unmodified intrinsic: `isFetchCall` reads
// `isUnmodifiedGlobalReference(callee, bindings, "fetch")`, which fails
// when the ambient-write coverage store covers ["global", "fetch"]. In
// whole-file mode that store is program-wide, so one module whose global
// write widens to an unknown key must not disable fetch recognition for
// every other module. The benchmark bundle carries both widening shapes:
// module 703's Symbol-keyed `globalThis[t] = o` and module 739's
// `self.globalThis = self` polyfill. Before the retention fix that also
// guards storage and defineProperty export facts, whole-file analysis
// emitted none of the bundle's 15 partial fetch endpoints (the resolved
// population carries no bare-fetch endpoints on this target, so the
// partials were the whole loss), while the sharded path, where each
// widening module is its own analysis unit, emitted all 15.

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

interface EndpointProjection {
  readonly module_key: string | null;
  readonly value: string;
  readonly mechanism: string;
  readonly resolution: string | null;
  readonly start: string;
}

const endpointsOf = (
  analysis: JavaScriptStaticAnalysis,
): EndpointProjection[] =>
  analysis.endpoints
    .filter((endpoint) => endpoint.mechanism.startsWith("call:fetch"))
    .map((endpoint) => ({
      module_key: endpoint.module_key,
      value: endpoint.value,
      mechanism: endpoint.mechanism,
      resolution: endpoint.resolution ?? null,
      start: `${String(endpoint.location.start.line)}:${String(endpoint.location.start.column)}`,
    }))
    .sort((left, right) =>
      `${left.module_key}|${left.value}|${left.start}`.localeCompare(
        `${right.module_key}|${right.value}|${right.start}`,
      ),
    );

const fillers = Array.from({ length: 5 }, (_, i) =>
  [
    "__d(function (global, require, i, a, module, exports, d) {",
    `  function work${String(i)}() { return ${String(i)}; }`,
    `  module.exports = { work${String(i)} };`,
    `}, ${String(100 + i)}, []);`,
  ].join("\n"),
);

// The widening module (703), the namespace self-assignment module (739),
// and four fetch victims mirroring the benchmark bundle's call shapes: a
// reassigned identifier target, a parameter target with options, a
// rest-spread wrapper target, and an inline literal target.
const parityBundle = [
  [
    "__d(function (g, r, i, a, m, e, d) {",
    '  Object.defineProperty(e, "__esModule", { value: true });',
    "  e.n = function (o) { globalThis[t] = o; };",
    "  e.t = function () { return globalThis[t]; };",
    '  const t = Symbol.for("@supabase/supabase-js.traceContextExtractor");',
    "}, 703, []);",
  ].join("\n"),
  [
    "__d(function (g, r, i, a, m, e, d) {",
    "  function p() { self.globalThis = self; }",
    "  e.p = p;",
    "}, 739, []);",
  ].join("\n"),
  [
    "__d(function (g, r, i, a, m, e, d) {",
    "  async function load(t) {",
    "    let n = t;",
    "    try { n = await resizeMeasured(t, 1600, .8); } catch { n = t; }",
    "    const u = await fetch(n);",
    "    return u.blob();",
    "  }",
    "  e.load = load;",
    "}, 200, []);",
  ].join("\n"),
  [
    "__d(function (g, r, i, a, m, e, d) {",
    "  async function o(u, t) {",
    "    const a = new AbortController();",
    "    return fetch(u, Object.assign({}, t, { signal: a.signal }));",
    "  }",
    "  e.o = o;",
    "}, 201, []);",
  ].join("\n"),
  [
    "__d(function (g, r, i, a, m, e, d) {",
    "  e.resolveFetch = (o) => o ? (...t) => o(...t) : (...x) => fetch(...x);",
    "}, 202, []);",
  ].join("\n"),
  [
    "__d(function (g, r, i, a, m, e, d) {",
    '  e.direct = () => fetch("https://api.example.test/items");',
    "}, 203, []);",
  ].join("\n"),
  ...fillers,
].join("\n");

it("emits partial and literal fetch endpoints on both paths beside widening global writes", () => {
  const whole = endpointsOf(
    analyzeParsedJavaScriptStaticSource(
      parityBundle,
      parseJavaScriptSource(parityBundle, "bundle.js")!,
    ),
  );
  const merged = endpointsOf(shardAnalyze(parityBundle));
  expect(whole).toEqual([
    expect.objectContaining({
      module_key: "200",
      value: "n",
      resolution: "partial",
    }),
    expect.objectContaining({
      module_key: "201",
      value: "u",
      resolution: "partial",
    }),
    expect.objectContaining({
      module_key: "202",
      value: "...x",
      resolution: "partial",
    }),
    expect.objectContaining({
      module_key: "203",
      value: "https://api.example.test/items",
      resolution: null,
    }),
  ]);
  expect(merged).toEqual(whole);
});

// The intrinsic gate itself is honest: a module that genuinely overwrites
// `fetch` makes fetch calls unrecognizable as the built-in for the whole
// program, while the sharded path keeps the victim module's endpoints.
const overwriteBundle = [
  [
    "__d(function (g, r, i, a, m, e, d) {",
    "  globalThis.fetch = customFetch;",
    "  e.marker = 1;",
    "}, 300, []);",
  ].join("\n"),
  [
    "__d(function (g, r, i, a, m, e, d) {",
    "  async function load(t) {",
    "    let n = t;",
    "    try { n = await resizeMeasured(t, 1600, .8); } catch { n = t; }",
    "    const u = await fetch(n);",
    "    return u.blob();",
    "  }",
    "  e.load = load;",
    '  e.direct = () => fetch("https://api.example.test/items");',
    "}, 200, []);",
  ].join("\n"),
  ...Array.from({ length: 6 }, (_, i) =>
    [
      "__d(function (global, require, i, a, module, exports, d) {",
      `  function work${String(i)}() { return ${String(i)}; }`,
      `  module.exports = { work${String(i)} };`,
      `}, ${String(100 + i)}, []);`,
    ].join("\n"),
  ),
].join("\n");

it("keeps whole-file fetch endpoints suppressed beside a genuine fetch overwrite", () => {
  const whole = endpointsOf(
    analyzeParsedJavaScriptStaticSource(
      overwriteBundle,
      parseJavaScriptSource(overwriteBundle, "bundle.js")!,
    ),
  );
  const merged = endpointsOf(shardAnalyze(overwriteBundle));
  expect(whole).toEqual([]);
  expect(merged).toEqual([
    expect.objectContaining({
      module_key: "200",
      value: "https://api.example.test/items",
      resolution: null,
    }),
    expect.objectContaining({
      module_key: "200",
      value: "n",
      resolution: "partial",
    }),
  ]);
});
