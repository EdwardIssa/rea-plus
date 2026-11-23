import { expect, it } from "vitest";
import { parseJavaScriptSource } from "./javascriptSourceParser.js";
import { partitionMetroBundle } from "./javascriptMetroBundlePartition.js";
import {
  analyzeJavaScriptStaticSource,
  analyzeParsedJavaScriptStaticSource,
} from "./javascriptStaticAnalysis.js";
import type { JavaScriptStaticAnalysis } from "./javascriptStaticAnalysisTypes.js";
import { mergeJavaScriptStaticAnalyses } from "./javascriptStaticAnalysisMerge.js";

// A write through a provably Symbol key modifies no string-keyed property,
// so it must not widen to an unknown-key write covering every global
// property path. The benchmark bundle carries this shape in its Supabase
// trace-context module: `const t = Symbol.for("..."); globalThis[t] = o`.

it.each([
  // The bundle's shape: write inside a function, const Symbol.for key.
  'function install(o) { globalThis[t] = o; } const t = Symbol.for("@supabase/supabase-js.traceContextExtractor"); localStorage.getItem("mila_guest_token");',
  // A direct Symbol() key.
  'globalThis[Symbol("trace")] = {}; localStorage.setItem("plain", "v");',
  // A well-known Symbol member key.
  'globalThis[Symbol.iterator] = 1; sessionStorage.getItem("other");',
  // A const Symbol() key on another global object name.
  'const s = Symbol("trace"); window[s] = {}; localStorage.removeItem("gone");',
  // An immutable binding chain ending in a Symbol.for() call.
  'const a = Symbol.for("trace"); const b = a; globalThis[b] = {}; localStorage.getItem("chained");',
])(
  "keeps storage facts beside a provably Symbol-keyed global write: %s",
  (source) => {
    const storage = analyzeJavaScriptStaticSource(source).storage;
    expect(storage.length).toBeGreaterThan(0);
  },
);

it.each([
  // A const string key can name localStorage itself.
  'const t = "localStorage"; globalThis[t] = {}; localStorage.getItem("k");',
  // A reassigned binding can hold a string at the write.
  'let t = Symbol("trace"); t = "localStorage"; globalThis[t] = {}; localStorage.getItem("k");',
  // A var binding is mutable even with a Symbol initializer.
  'var t = Symbol("trace"); globalThis[t] = {}; localStorage.getItem("k");',
  // A computed string key still widens to an unknown key.
  'const k = "dyn" + "amic"; globalThis[k] = 1; localStorage.getItem("k");',
  // A direct write to the storage global itself.
  'globalThis.localStorage = {}; localStorage.getItem("k");',
  // A shadowed Symbol is not the global Symbol constructor.
  'function f(Symbol) { globalThis[Symbol.for("x")] = 1; } f(null); localStorage.getItem("k");',
])(
  "keeps storage suppressed beside a possibly string-keyed global write: %s",
  (source) => {
    expect(analyzeJavaScriptStaticSource(source).storage).toEqual([]);
  },
);

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

const bundleWith = (poisonModule: string): string =>
  [
    poisonModule,
    [
      "__d(function (global, require, module, exports) {",
      '  var token = localStorage.getItem("mila_guest_token");',
      '  localStorage.setItem("mila_recent_searches_v1", "[]");',
      '  globalThis.localStorage.removeItem("mila_pending_deep_link_poll");',
      "  module.exports = { token };",
      "}, 700, []);",
    ].join("\n"),
    ...Array.from({ length: 9 }, (_, i) =>
      [
        "__d(function (global, require, module, exports) {",
        `  function work${String(i)}() { return ${String(i)}; }`,
        `  module.exports = { work${String(i)} };`,
        `}, ${String(100 + i)}, []);`,
      ].join("\n"),
    ),
  ].join("\n");

it("emits the storage facts on both paths when one module writes through a Symbol key", () => {
  const source = bundleWith(
    [
      "__d(function (g, r, i, a, m, e, d) {",
      '  Object.defineProperty(e, "__esModule", { value: true });',
      "  e.n = function (o) { globalThis[t] = o; };",
      "  e.t = function () { return globalThis[t]; };",
      '  const t = Symbol.for("@supabase/supabase-js.traceContextExtractor");',
      "}, 703, []);",
    ].join("\n"),
  );
  const whole = analyzeParsedJavaScriptStaticSource(
    source,
    parseJavaScriptSource(source, "bundle.js")!,
  );
  const merged = shardAnalyze(source);
  expect(whole.storage.map(({ name }) => name).sort()).toEqual([
    "mila_guest_token",
    "mila_pending_deep_link_poll",
    "mila_recent_searches_v1",
  ]);
  expect(merged.storage).toEqual(whole.storage);
});

it("keeps whole-file storage suppressed when one module may write the storage global", () => {
  const source = bundleWith(
    [
      "__d(function (global, require, module, exports) {",
      '  const t = "localStorage";',
      "  globalThis[t] = { getItem() { return null; } };",
      "}, 701, []);",
    ].join("\n"),
  );
  const whole = analyzeParsedJavaScriptStaticSource(
    source,
    parseJavaScriptSource(source, "bundle.js")!,
  );
  const merged = shardAnalyze(source);
  expect(whole.storage).toEqual([]);
  expect(merged.storage.length).toBeGreaterThan(0);
});

// A global-object namespace slot written with the global object itself
// (the `self.globalThis = self` polyfill shape in the benchmark bundle's
// module 739) keeps denoting the global object, so references routed
// through it stay recognizable in the whole program, where the polyfill
// shares one analysis unit with the storage callers.

it.each([
  // The bundle's shape: the polyfill assignment inside a function.
  'function p() { self.globalThis = self; } globalThis.localStorage.getItem("supabase.gotrue-js.locks.debug");',
  // Another global-object name on both sides.
  'window.globalThis = window; globalThis.localStorage.setItem("k", "v");',
  // The full polyfill body, including the __magic__ write that retains
  // no namespace path of its own.
  'function p() { if ("object" == typeof globalThis) return; try { Object.defineProperty(Object.prototype, "__magic__", { get: function () { return this; }, configurable: true }); __magic__.globalThis = __magic__; delete Object.prototype.__magic__; } catch (e) { "undefined" != typeof self && (self.globalThis = self); } } globalThis.localStorage.removeItem("k");',
])(
  "keeps globalThis-routed storage facts beside a namespace self-assignment: %s",
  (source) => {
    expect(
      analyzeJavaScriptStaticSource(source).storage.length,
    ).toBeGreaterThan(0);
  },
);

it.each([
  // A different value replaces the namespace denotation.
  'self.globalThis = {}; globalThis.localStorage.getItem("k");',
  // An unresolvable value may replace it too.
  'self.globalThis = other; globalThis.localStorage.getItem("k");',
  // A compound assignment is not the polyfill shape.
  'self.globalThis ??= self; globalThis.localStorage.getItem("k");',
])(
  "keeps globalThis-routed storage suppressed beside a namespace overwrite: %s",
  (source) => {
    expect(analyzeJavaScriptStaticSource(source).storage).toEqual([]);
  },
);
