import { expect, it } from "vitest";
import { parseJavaScriptSource } from "./javascriptSourceParser.js";
import { partitionMetroBundle } from "./javascriptMetroBundlePartition.js";
import {
  analyzeParsedJavaScriptStaticSource,
} from "./javascriptStaticAnalysis.js";
import type { JavaScriptStaticAnalysis } from "./javascriptStaticAnalysisTypes.js";
import { mergeJavaScriptStaticAnalyses } from "./javascriptStaticAnalysisMerge.js";

// Export declarations made through `Object.defineProperty` are recognized
// only while the reference is provably the unmodified intrinsic
// (javascriptAstFingerprint's intrinsic gate reads the ambient-write
// coverage store). In whole-file mode that store is program-wide, so one
// module whose global write widens to an unknown key must not disable
// defineProperty export collection for every other module. The benchmark
// bundle carries the widening shape in its Supabase trace-context module:
// `const t = Symbol.for("..."); globalThis[t] = o`. Before the retention
// fix that also guards storage facts, whole-file analysis lost the
// `__esModule` marker on 1,185 modules and every defineProperty re-export
// on the React Native index modules, while the sharded path (where the
// widening module is its own analysis unit) collected them all.

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

const exportsOf = (
  analysis: JavaScriptStaticAnalysis,
): Record<string, readonly string[]> => {
  const out: Record<string, readonly string[]> = {};
  for (const registration of analysis.bundler_registrations)
    for (const module of registration.modules)
      out[module.module_key] = module.exports;
  return out;
};

const fillers = Array.from({ length: 5 }, (_, i) =>
  [
    "__d(function (global, require, i, a, module, exports, d) {",
    `  function work${String(i)}() { return ${String(i)}; }`,
    `  module.exports = { work${String(i)} };`,
    `}, ${String(100 + i)}, []);`,
  ].join("\n"),
);

// The widening module (703), the namespace self-assignment module (739),
// and three victims declaring exports through defineProperty on the
// exports parameter, defineProperty on module.exports, and plain
// assignment forms.
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
    "  var t = r(d[0]);",
    '  Object.defineProperty(e, "__esModule", { value: !0 });',
    '  Object.defineProperty(e, "TouchableOpacity", { enumerable: !0, get: function () { return t.default; } });',
    '  Object.defineProperty(e, "TouchableHighlight", { enumerable: !0, get: function () { return t.default; } });',
    "}, 200, [100]);",
  ].join("\n"),
  [
    "__d(function (global, require, i, a, module, exports, d) {",
    '  Object.defineProperty(module.exports, "__esModule", { value: true });',
    '  Object.defineProperty(module.exports, "viaModule", { enumerable: true, get: function () { return 3; } });',
    "}, 201, []);",
  ].join("\n"),
  [
    "__d(function (g, r, i, a, m, e, d) {",
    "  m.exports.__esModule = !0;",
    "  e.bar = 1;",
    "  m.exports.baz = 2;",
    "}, 202, []);",
  ].join("\n"),
  ...fillers,
].join("\n");

it("collects defineProperty exports on both paths beside widening global writes", () => {
  const whole = exportsOf(
    analyzeParsedJavaScriptStaticSource(
      parityBundle,
      parseJavaScriptSource(parityBundle, "bundle.js")!,
    ),
  );
  const merged = exportsOf(shardAnalyze(parityBundle));
  expect(whole["200"]).toEqual([
    "TouchableHighlight",
    "TouchableOpacity",
    "__esModule",
  ]);
  expect(whole["201"]).toEqual(["__esModule", "viaModule"]);
  expect(whole["202"]).toEqual(["__esModule", "bar", "baz"]);
  expect(merged).toEqual(whole);
});

// The intrinsic gate itself is honest: a module that genuinely overwrites
// `Object.defineProperty` makes defineProperty calls unrecognizable as
// export declarations for the whole program, while assignment-form
// exports and the sharded path stay unaffected.
const overwriteBundle = [
  [
    "__d(function (g, r, i, a, m, e, d) {",
    "  Object.defineProperty = function () { return {}; };",
    "  e.marker = 1;",
    "}, 300, []);",
  ].join("\n"),
  [
    "__d(function (g, r, i, a, m, e, d) {",
    "  var t = r(d[0]);",
    '  Object.defineProperty(e, "__esModule", { value: !0 });',
    '  Object.defineProperty(e, "TouchableOpacity", { enumerable: !0, get: function () { return t.default; } });',
    "}, 200, [100]);",
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

it("keeps whole-file defineProperty exports suppressed beside a genuine intrinsic overwrite", () => {
  const whole = exportsOf(
    analyzeParsedJavaScriptStaticSource(
      overwriteBundle,
      parseJavaScriptSource(overwriteBundle, "bundle.js")!,
    ),
  );
  const merged = exportsOf(shardAnalyze(overwriteBundle));
  expect(whole["200"]).toEqual([]);
  expect(whole["300"]).toEqual(["marker"]);
  expect(merged["200"]).toEqual(["TouchableOpacity", "__esModule"]);
});
