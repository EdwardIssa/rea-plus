import { expect, it } from "vitest";
import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

// Scenario tests for the bundler recovery bookkeeping, driven through the
// public source analysis with fixtures whose dynamic facts are non-zero:
// the registration unknown counters, the synthetic runtime/chunk keys, the
// recovered module ordering, the standalone bootstrap's entry discipline,
// the esbuild wrapper identities, and the Metro accumulator roll-up. These
// pin the behaviors the Stryker pilot found unmeasured in
// javascriptStaticAnalysisBundler.ts (see the goal's survivor inventory).

const push = (tail: string) =>
  `(globalThis.webpackChunkApp = globalThis.webpackChunkApp || []).push(${tail});`;

it("counts every dynamic registration fact in the coverage unknowns", () => {
  const result = analyzeJavaScriptStaticSource(
    push(`[
      [dynamicChunk, "chunk-b", "chunk-a"],
      {
        zeta(module, exports, require) { require.e(dynamicChunkKey); },
        alpha(module, exports, require) { require.e("async-a"); }
      },
      function(require) {
        require(dynamicEntry);
        require.e(dynamicAsync);
        require(9);
        require(3);
      }
    ]`),
  );
  expect(result.bundler_registrations).toHaveLength(1);
  const registration = result.bundler_registrations[0]!;
  // Chunk ids sort and the one dynamic id stays an unknown count.
  expect(registration.chunk_keys).toEqual(["chunk-a", "chunk-b"]);
  expect(registration.unknown_chunk_keys).toBe(1);
  // Entry keys sort by code point, not by call order (9 was called first).
  expect(registration.entry_module_keys).toEqual(["3", "9"]);
  expect(registration.unknown_entry_module_keys).toBe(1);
  // One unknown async chunk from the runtime callback plus one from a
  // recovered factory: the recovered sum reaches the registration.
  expect(registration.async_chunk_keys).toEqual(["async-a"]);
  expect(registration.unknown_async_chunk_keys).toBe(2);
  // Recovered modules sort by key, not by table order (zeta came first).
  expect(registration.modules.map((module) => module.module_key)).toEqual([
    "alpha",
    "zeta",
  ]);
  // One unknown chunk key + one unknown entry + two unknown async chunks.
  expect(result.analysis_coverage!.semantics.unknown_findings).toBe(4);
});

it("classifies a mixed-case rspack runtime by its lowercased name", () => {
  const result = analyzeJavaScriptStaticSource(
    `(globalThis.RspackChunkApp = globalThis.RspackChunkApp || []).push([[1], {a(module, exports, require) {}}, function(require) {}]);`,
  );
  expect(result.parse_status).toBe("complete");
  expect(result.bundler_registrations).toHaveLength(1);
  expect(result.bundler_registrations[0]).toMatchObject({
    bundler: "rspack",
    runtime: "RspackChunkApp",
  });
});

it("records an absent runtime callback as no unknown entries", () => {
  const result = analyzeJavaScriptStaticSource(
    push(`[[1], {a(module, exports, require) {}}]`),
  );
  expect(result.bundler_registrations).toHaveLength(1);
  expect(result.bundler_registrations[0]).toMatchObject({
    runtime_require_name: null,
    entry_module_keys: [],
    unknown_entry_module_keys: 0,
    async_chunk_keys: [],
    unknown_async_chunk_keys: 0,
  });
});

it("counts a non-function runtime callback as one unknown entry", () => {
  const result = analyzeJavaScriptStaticSource(
    push(`[[1], {a(module, exports, require) {}}, 42]`),
  );
  expect(result.bundler_registrations).toHaveLength(1);
  expect(result.bundler_registrations[0]).toMatchObject({
    runtime_require_name: null,
    entry_module_keys: [],
    unknown_entry_module_keys: 1,
  });
});

it("records a holed runtime callback slot as no unknown entries", () => {
  const result = analyzeJavaScriptStaticSource(
    push(`[[1], {a(module, exports, require) {}}, ,]`),
  );
  expect(result.bundler_registrations).toHaveLength(1);
  expect(result.bundler_registrations[0]).toMatchObject({
    runtime_require_name: null,
    entry_module_keys: [],
    unknown_entry_module_keys: 0,
  });
});

it.each([
  ["a parameterless callback", "function() {}"],
  ["a destructured callback parameter", "function({}) {}"],
])(
  "counts %s as one unknown entry with empty key lists",
  (_label, callback) => {
    const result = analyzeJavaScriptStaticSource(
      push(`[[1], {a(module, exports, require) {}}, ${callback}]`),
    );
    expect(result.bundler_registrations).toHaveLength(1);
    expect(result.bundler_registrations[0]).toMatchObject({
      runtime_require_name: null,
      entry_module_keys: [],
      unknown_entry_module_keys: 1,
      async_chunk_keys: [],
      unknown_async_chunk_keys: 0,
    });
  },
);

it("treats calls through a reassigned runtime loader as unknown", () => {
  const result = analyzeJavaScriptStaticSource(
    push(
      `[[1], {a(module, exports, require) {}}, function(r) { r = wrap(r); r(7); r.e("later"); }]`,
    ),
  );
  expect(result.bundler_registrations).toHaveLength(1);
  // The static arguments after the reassignment are not recovered facts:
  // the loader may have changed, so both calls count as unknown instead.
  expect(result.bundler_registrations[0]).toMatchObject({
    runtime_require_name: "r",
    entry_module_keys: [],
    unknown_entry_module_keys: 1,
    async_chunk_keys: [],
    unknown_async_chunk_keys: 1,
  });
});

const bootstrap = (entryCall: string, extraStatements: string) => `(() => {
  const modules = {
    23(module, exports, req) { exports.b = req(17); req.e(dynamicChunk); },
    17(module) { module.exports = 1; }
  };
  const cache = {};
  function load(id) {
    if (cache[id]) return cache[id].exports;
    const module = cache[id] = { exports: {} };
    modules[id](module, module.exports, load);
    return module.exports;
  }
  ${entryCall}
  ${extraStatements}
})();`;

it("pins the standalone bootstrap identity, entries and module order", () => {
  // The leading statement puts the bootstrap call at offset 18, so the
  // synthetic runtime and chunk keys carry that offset, not zero.
  const source =
    "const marker = 0;\n" +
    bootstrap(
      "load(23);\n  load(dynamicEntry);",
      "function helper() { load(17); }",
    );
  const result = analyzeJavaScriptStaticSource(source);
  expect(result.bundler_registrations).toHaveLength(1);
  const registration = result.bundler_registrations[0]!;
  expect(registration).toMatchObject({
    bundler: "webpack",
    runtime: "webpack-bootstrap@18",
    chunk_keys: ["bootstrap@18"],
    runtime_require_name: "load",
    // Only the top-level entry call counts; the call nested inside the
    // helper function is not an entry, and the dynamic call is unknown.
    entry_module_keys: ["23"],
    unknown_entry_module_keys: 1,
    async_chunk_keys: [],
    unknown_async_chunk_keys: 1,
  });
  // Recovered modules sort by key, not by table order (23 came first).
  expect(registration.modules.map((module) => module.module_key)).toEqual([
    "17",
    "23",
  ]);
  // One unknown entry call + one unknown async chunk from a factory.
  expect(result.analysis_coverage!.semantics.unknown_findings).toBe(2);
});

it("keeps two distinct standalone bootstraps as separate registrations", () => {
  const second = `(() => {
  const modules = { 42(module) { module.exports = 2; } };
  const cache = {};
  function load(id) {
    const module = cache[id] = { exports: {} };
    modules[id](module, module.exports, load);
    return module.exports;
  }
  load(42);
})();`;
  const result = analyzeJavaScriptStaticSource(
    bootstrap("load(23);", "") + "\n" + second,
  );
  expect(result.bundler_registrations).toHaveLength(2);
  expect(
    result.bundler_registrations.map((registration) =>
      registration.modules.map((module) => module.module_key),
    ),
  ).toEqual([["17", "23"], ["42"]]);
  expect(
    result.bundler_registrations.map(
      (registration) => registration.entry_module_keys,
    ),
  ).toEqual([["23"], ["42"]]);
});

it("pins esbuild wrapper identities for both wrapper kinds", () => {
  const source = `var modA = __commonJS({
  "b.js"(exports, module) { module.exports = 1; },
  "a.js"(exports, module) { module.exports = 2; }
});
var modB = __esm({
  "c.js"() {}
});`;
  const result = analyzeJavaScriptStaticSource(source);
  expect(result.bundler_registrations).toHaveLength(2);
  const [commonjs, esm] = result.bundler_registrations;
  expect(commonjs).toMatchObject({
    bundler: "esbuild",
    runtime: "esbuild-commonjs",
    chunk_keys: [`commonjs@${source.indexOf("__commonJS")}`],
    entry_module_keys: [],
    unknown_entry_module_keys: 0,
  });
  // Recovered modules sort by key, not by table order (b.js came first).
  expect(commonjs!.modules.map((module) => module.module_key)).toEqual([
    "a.js",
    "b.js",
  ]);
  expect(esm).toMatchObject({
    bundler: "esbuild",
    runtime: "esbuild-esm",
    chunk_keys: [`esm@${source.indexOf("__esm")}`],
    entry_module_keys: [],
    modules: [{ module_key: "c.js" }],
  });
});

it("emits no registration for an esbuild wrapper with an empty table", () => {
  const result = analyzeJavaScriptStaticSource(`var mod = __commonJS({});`);
  expect(result.bundler_registrations).toEqual([]);
});

it("counts computed and synthetic-prefixed module keys as unknown findings", () => {
  const result = analyzeJavaScriptStaticSource(
    push(`[[1], {
      [dynamicKey](module, exports, require) {},
      "[unknown@5]"(module, exports, require) {},
      known(module, exports, require) {}
    }, function(require) {}]`),
  );
  expect(result.bundler_registrations).toHaveLength(1);
  const keys = result.bundler_registrations[0]!.modules.map(
    (module) => module.module_key,
  );
  // The synthetic-key detection is textual: a computed key derives the
  // [computed@<offset>] form, and a literal key carrying the synthetic
  // [unknown@ prefix is indistinguishable from a derived one here.
  expect(keys).toHaveLength(3);
  expect(keys[0]).toMatch(/^\[computed@\d+\]$/);
  expect(keys.slice(1)).toEqual(["[unknown@5]", "known"]);
  expect(result.analysis_coverage!.semantics.unknown_findings).toBe(2);
});

it("rolls Metro async chunk keys and unknowns into the registration", () => {
  const result = analyzeJavaScriptStaticSource(
    `__d(function(g, r, i, a, m, e, d) { r.e("chunk-a"); r.e(dynamicChunk); m.exports = 1; }, 5, []);
__r(5);`,
  );
  expect(result.bundler_registrations).toHaveLength(1);
  expect(result.bundler_registrations[0]).toMatchObject({
    bundler: "metro",
    async_chunk_keys: ["chunk-a"],
    unknown_async_chunk_keys: 1,
  });
});

it("anchors a prelude-only Metro registration at the first entry call", () => {
  const result = analyzeJavaScriptStaticSource(`__r(5);
__r(6);`);
  expect(result.bundler_registrations).toHaveLength(1);
  const registration = result.bundler_registrations[0]!;
  expect(registration.entry_module_keys).toEqual(["5", "6"]);
  expect(registration.location.start.line).toBe(1);
  expect(registration.location.end.line).toBe(1);
});

it("counts a Metro factory with a rest role parameter as unknown", () => {
  const exact = analyzeJavaScriptStaticSource(
    `__d(function(g, r, i, a, m, e, d) { m.exports = 1; }, 9, []);`,
  );
  expect(exact.analysis_coverage!.semantics.unknown_findings).toBe(0);
  // A rest element in the loader position cannot be matched exactly, so
  // the module's facts are incomplete and count as an unknown finding.
  const inexact = analyzeJavaScriptStaticSource(
    `__d(function(g, ...rest) {}, 9, []);`,
  );
  expect(inexact.analysis_coverage!.semantics.unknown_findings).toBe(1);
  expect(inexact.bundler_registrations[0]?.modules).toMatchObject([
    { module_key: "9" },
  ]);
});

it("never traverses a Metro factory role parameter default", () => {
  const result = analyzeJavaScriptStaticSource(
    `__d(function(g, r, i, a, m = require("metro-default-ghost"), e, d) { m.exports = 1; }, 9, []);`,
  );
  expect(result.bundler_registrations[0]?.modules).toMatchObject([
    { module_key: "9" },
  ]);
  // The convention always supplies the module argument, so the default
  // expression never runs and yields no reference.
  expect(
    result.references.map((reference) => reference.specifier),
  ).not.toContain("metro-default-ghost");
});
