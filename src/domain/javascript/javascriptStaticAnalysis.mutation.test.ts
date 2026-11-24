import { expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

// Scenario tests for the analyze/finalize behaviors in
// javascriptStaticAnalysis.ts (lines 92-504) that the Stryker pilot
// measured at 93.04 with a 37% timeout share: the RPC fact collections
// retained for cross-shard joins, the finalized Metro registration
// (define-start fallback, async chunk keys, module order), the
// finalize limitation strings, the finalized rpc_export_provenance
// field, and the import-equals reference. Fixtures are shaped so each
// behavior is load-bearing in the finalized output, not just in the
// accumulator. The three RPC dedup-key mutants (lines 161, 172, 191)
// are pinned here by their observable consequence: addLocatedFinding
// appends the node start to every dedup key, so facts from distinct
// nodes never collapse — the member/value key text itself decides no
// dedup outcome (see the survivor inventory for the equivalence
// argument).

const metroRegistration = (source: string) => {
  const registrations =
    analyzeJavaScriptStaticSource(source).bundler_registrations;
  expect(registrations).toHaveLength(1);
  return registrations[0]!;
};

it("records each distinct RPC client member in the finalized output", () => {
  const result = analyzeJavaScriptStaticSource(
    [
      "const publishers = {};",
      'publishers.alpha = createClient("https://example.test", "k");',
      'publishers.beta = createClient("https://example.test", "k");',
    ].join("\n"),
  );
  expect(
    result.rpc_client_members?.map(({ member, module_key }) => ({
      member,
      module_key,
    })),
  ).toEqual([
    { member: "alpha", module_key: null },
    { member: "beta", module_key: null },
  ]);
});

it("keeps repeated assignments of one client member as separate facts", () => {
  const result = analyzeJavaScriptStaticSource(
    [
      "const publishers = {};",
      'publishers.alpha = createClient("https://example.test", "k");',
      'publishers.alpha = createClient("https://example.test", "k");',
    ].join("\n"),
  );
  expect(result.rpc_client_members?.map(({ member }) => member)).toEqual([
    "alpha",
    "alpha",
  ]);
});

it("records re-export provenance in the finalized output", () => {
  const result = analyzeJavaScriptStaticSource(
    [
      'const first = require("./a.js");',
      'const second = require("./b.js");',
      "const published = {};",
      "published.one = first.shared;",
      "published.two = second.shared;",
    ].join("\n"),
  );
  expect("rpc_export_provenance" in result).toBe(true);
  expect(
    result.rpc_export_provenance?.map(
      ({ member, source_member, source_module_key, module_key }) => ({
        member,
        source_member,
        source_module_key,
        module_key,
      }),
    ),
  ).toEqual([
    {
      member: "one",
      source_member: "shared",
      source_module_key: "./a.js",
      module_key: null,
    },
    {
      member: "two",
      source_member: "shared",
      source_module_key: "./b.js",
      module_key: null,
    },
  ]);
});

it("keeps repeated provenance assignments as separate facts", () => {
  const result = analyzeJavaScriptStaticSource(
    [
      'const first = require("./a.js");',
      "const published = {};",
      "published.one = first.shared;",
      "published.one = first.shared;",
    ].join("\n"),
  );
  expect(result.rpc_export_provenance).toHaveLength(2);
});

it("records unresolved cross-shard RPC calls as finalized candidates", () => {
  const result = analyzeJavaScriptStaticSource(
    [
      "__d(function (global, require, module, exports) {",
      "  var e = require(1);",
      '  e.supabase.rpc("first_proc");',
      '  e.supabase.rpc("second_proc");',
      "}, 2, [1]);",
    ].join("\n"),
  );
  expect(
    result.rpc_candidates?.map(
      ({ value, member_chain, requested_module_key, module_key }) => ({
        value,
        member_chain,
        requested_module_key,
        module_key,
      }),
    ),
  ).toEqual([
    {
      value: "first_proc",
      member_chain: ["supabase"],
      requested_module_key: "1",
      module_key: "2",
    },
    {
      value: "second_proc",
      member_chain: ["supabase"],
      requested_module_key: "1",
      module_key: "2",
    },
  ]);
});

it("keeps repeated calls to one procedure as separate candidates", () => {
  const result = analyzeJavaScriptStaticSource(
    [
      "__d(function (global, require, module, exports) {",
      "  var e = require(1);",
      '  e.supabase.rpc("same_proc");',
      '  e.supabase.rpc("same_proc");',
      "}, 2, [1]);",
    ].join("\n"),
  );
  expect(result.rpc_candidates?.map(({ value }) => value)).toEqual([
    "same_proc",
    "same_proc",
  ]);
});

it("emits a Metro registration for a prelude-only shard with the zero define-start fallback", () => {
  const registration = metroRegistration("__r(0);");
  expect(registration.chunk_keys).toEqual(["metro@0"]);
  expect(registration.entry_module_keys).toEqual(["0"]);
  expect(registration.modules).toEqual([]);
});

it("names the Metro chunk key from the first define start", () => {
  const registration = metroRegistration(
    "\n__d(function(g, r, i, a, m, e, d) { m.exports = 1; }, 5, []);\n__r(5);\n",
  );
  expect(registration.chunk_keys).toEqual(["metro@1"]);
});

it("carries deduplicated async chunk keys into the finalized Metro registration", () => {
  const registration = metroRegistration(
    '__d(function(g, r, i, a, m, e, d) { r.e("chunk-a"); r.e("chunk-b"); r.e("chunk-a"); m.exports = 1; }, 3, []);\n__r(3);\n',
  );
  expect(registration.async_chunk_keys).toEqual(["chunk-a", "chunk-b"]);
  expect(registration.unknown_async_chunk_keys).toBe(0);
});

it("sorts finalized Metro modules by module key, not definition order", () => {
  const registration = metroRegistration(
    "__d(function(g, r, i, a, m, e, d) { m.exports = 1; }, 1, []);\n__d(function(g, r, i, a, m, e, d) { m.exports = 2; }, 0, []);\n__r(0);\n",
  );
  expect(registration.modules.map(({ module_key }) => module_key)).toEqual([
    "0",
    "1",
  ]);
});

it("sorts finalized Metro modules in code-point order", () => {
  const registration = metroRegistration(
    "__d(function(g, r, i, a, m, e, d) { m.exports = 1; }, 2, []);\n__d(function(g, r, i, a, m, e, d) { m.exports = 2; }, 10, []);\n__r(2);\n",
  );
  expect(registration.modules.map(({ module_key }) => module_key)).toEqual([
    "10",
    "2",
  ]);
});

it("reports the parser-recovery limitation when the parser recovers", () => {
  const result = analyzeJavaScriptStaticSource("let value; let value;");
  expect(result.parse_error_count).toBe(1);
  expect(result.limitations).toEqual([
    "The parser recovered from syntax errors; affected facts are partial.",
    "JavaScript syntax was parsed as data and was never evaluated.",
  ]);
});

it("reports only the always-present limitation for a clean source", () => {
  const result = analyzeJavaScriptStaticSource("const value = 1;");
  expect(result.parse_error_count).toBe(0);
  expect(result.limitations).toEqual([
    "JavaScript syntax was parsed as data and was never evaluated.",
  ]);
});

it("reports the compiler-options limitation for an inline type-only import", () => {
  const result = analyzeJavaScriptStaticSource(
    'import { type Foo } from "./types.js";\nconst value = 1;',
  );
  expect(result.limitations).toEqual([
    "Compiler options are unavailable; inline type-only imports or re-exports may preserve a module side-effect dependency.",
    "JavaScript syntax was parsed as data and was never evaluated.",
  ]);
  expect(result.analysis_coverage?.semantics.uncertainty).toContain(
    "type-only-module-side-effect",
  );
});

it("reports the compiler-options limitation for an inline type-only re-export", () => {
  const result = analyzeJavaScriptStaticSource(
    'export { type Bar } from "./types.js";',
  );
  expect(result.limitations).toEqual([
    "Compiler options are unavailable; inline type-only imports or re-exports may preserve a module side-effect dependency.",
    "JavaScript syntax was parsed as data and was never evaluated.",
  ]);
});

it("records a require reference spanning an import-equals declaration", () => {
  const result = analyzeJavaScriptStaticSource(
    'import dep = require("./dep.js");',
  );
  expect(
    result.references.map(({ kind, specifier, module_key, location }) => ({
      kind,
      specifier,
      module_key,
      location,
    })),
  ).toEqual([
    {
      kind: "require",
      specifier: "./dep.js",
      module_key: null,
      location: {
        start: { line: 1, column: 0 },
        end: { line: 1, column: 33 },
      },
    },
  ]);
});

it("records no reference for a type-only import-equals declaration", () => {
  const result = analyzeJavaScriptStaticSource(
    'import type dep = require("./dep.js");',
  );
  expect(result.references).toEqual([]);
});

it("records no reference for a type-only import declaration", () => {
  const result = analyzeJavaScriptStaticSource(
    'import type { Foo } from "./types.js";',
  );
  expect(result.references).toEqual([]);
});

it("records no reference for a type-only export declaration", () => {
  const result = analyzeJavaScriptStaticSource(
    'export type { Bar } from "./types.js";',
  );
  expect(result.references).toEqual([]);
});

it("records no endpoint for a call in a declared class field's computed key", () => {
  // A declared field is erased syntax, key included: the traversal
  // must not inspect the key's call, or an endpoint would be invented
  // for code that never runs. This is the shape that makes the
  // erased-node guard in the traversal load-bearing — the module
  // source gate re-checks type-only declarations on its own, but no
  // second gate covers calls inside erased subtrees.
  const result = analyzeJavaScriptStaticSource(
    'class A { declare [fetch("/key")]: string; }',
  );
  expect(result.endpoints).toEqual([]);
});

it("records no endpoint for a call in an abstract class field's computed key", () => {
  const result = analyzeJavaScriptStaticSource(
    'abstract class A { abstract [fetch("/key")]: string; }',
  );
  expect(result.endpoints).toEqual([]);
});
