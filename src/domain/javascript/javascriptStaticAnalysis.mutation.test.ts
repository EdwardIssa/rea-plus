import { expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";
import { aliasSelectionBudgetSource } from "../../../tests/fixtures/javascriptAliasSelectionBudget.js";

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

// Follow-up fixtures for the survivors the long-timeout run of range
// 251-353 exposed (all 14 were pilot timeouts before conversion): the
// finalized resource-limit sort, the dynamic-findings uncertainty
// conjuncts, the examination-limited disjunction and the Electron
// call-path flag, the Metro emission condition, and the bundled
// Electron call-path limitation entry. Each fixture makes one of
// those finalize behaviors observable in the finalized output.

it("reports no dynamic-findings uncertainty when nothing is unknown", () => {
  const result = analyzeJavaScriptStaticSource("const value = 1;");
  expect(result.analysis_coverage?.semantics.unknown_findings).toBe(0);
  expect(result.analysis_coverage?.semantics.uncertainty).toEqual([]);
});

it("emits no bundler registration for a plain source", () => {
  const result = analyzeJavaScriptStaticSource("const value = 1;");
  expect(result.bundler_registrations).toEqual([]);
});

it("emits no Metro registration for a dynamic entry call with no modules", () => {
  // The entry call records a Metro location but no entry key and no
  // module; the emission condition must stay false on both counts.
  const result = analyzeJavaScriptStaticSource("__r(dynamicName);");
  expect(result.bundler_registrations).toEqual([]);
});

it("reports the bundled Electron call-path limitation", () => {
  const result = analyzeJavaScriptStaticSource(
    [
      'const { contextBridge, ipcRenderer } = require("electron");',
      'contextBridge.exposeInMainWorld("api", { ping: () => ipcRenderer.invoke("ping") });',
    ].join("\n"),
  );
  expect(result.electron.call_paths).toHaveLength(1);
  expect(result.limitations).toEqual([
    "Bundled Electron call paths use static argument and closure substitutions. Conditions, ambient helper overrides, runtime reachability and arbitrary side effects remain unproven.",
    "Electron API identity follows proven lexical module aliases and structurally verified module-namespace interop. Other reassignments, dynamic selections, and visibly overwritten namespace members are unresolved; missing findings do not establish absence. Arbitrary call side effects and runtime registration are not evaluated.",
    "JavaScript syntax was parsed as data and was never evaluated.",
  ]);
});

it("flags examination as limited when Electron wrapper expansion hits its budget", () => {
  // Nested bridge members past the depth-128 expansion budget: the
  // limit flag, not a semantic resource limit, drives the status.
  let inner = 'leaf: () => ipcRenderer.invoke("deep")';
  for (let level = 0; level < 140; level++) inner = `level: { ${inner} }`;
  const result = analyzeJavaScriptStaticSource(
    [
      'const { contextBridge, ipcRenderer } = require("electron");',
      `contextBridge.exposeInMainWorld("api", { ${inner} });`,
    ].join("\n"),
  );
  expect(result.analysis_coverage?.examination).toEqual({
    status: "limited",
    semantic_resource_limits: [],
    electron_call_paths_limited: true,
  });
  expect(result.limitations).toContain(
    "Electron wrapper expansion reached its resource budget (1000000 visits/substitutions or depth 128); additional paths remain unknown.",
  );
});

it("reports examination as limited from a semantic resource limit alone", () => {
  // 300 erased `as` wrappers exceed the expression-depth budget of
  // 256 when the value's provenance is queried at the fetch call.
  const result = analyzeJavaScriptStaticSource(
    `const v = 1${" as unknown".repeat(300)}; fetch(v);`,
  );
  expect(result.analysis_coverage?.examination).toEqual({
    status: "limited",
    semantic_resource_limits: ["expression-depth"],
    electron_call_paths_limited: false,
  });
});

it("omits rpc_candidates from the finalized output when none were recorded", () => {
  // The conditional spread must stay load-bearing: a source that
  // records client members but no cross-shard candidates finalizes
  // without the candidates field at all, not with an empty list.
  const result = analyzeJavaScriptStaticSource(
    [
      "const publishers = {};",
      'publishers.alpha = createClient("https://example.test", "k");',
    ].join("\n"),
  );
  expect(result.rpc_client_members).toHaveLength(1);
  expect("rpc_candidates" in result).toBe(false);
});

it("omits rpc_client_members from the finalized output when none were recorded", () => {
  const result = analyzeJavaScriptStaticSource(
    [
      "__d(function (global, require, module, exports) {",
      "  var e = require(1);",
      '  e.supabase.rpc("first_proc");',
      "}, 2, [1]);",
    ].join("\n"),
  );
  expect(result.rpc_candidates).toHaveLength(1);
  expect("rpc_client_members" in result).toBe(false);
});

it("omits rpc_export_provenance from the finalized output when none was recorded", () => {
  const result = analyzeJavaScriptStaticSource("const value = 1;");
  expect("rpc_export_provenance" in result).toBe(false);
});

it("omits electron app_path_changes when no app path was changed", () => {
  // Electron is observed and call paths finalize, but no app path
  // change was recorded, so the field stays out of the electron
  // section entirely.
  const result = analyzeJavaScriptStaticSource(
    [
      'const { contextBridge, ipcRenderer } = require("electron");',
      'contextBridge.exposeInMainWorld("api", { ping: () => ipcRenderer.invoke("ping") });',
    ].join("\n"),
  );
  expect(result.electron.call_paths).toHaveLength(1);
  expect("app_path_changes" in result.electron).toBe(false);
});

it("collects Metro exports declared through the factory require's d helper", () => {
  // Pins the production behavior behind the finalize gate on the
  // factory-loader flag: the declared export is collected in the
  // finalized registration. Note: this fixture does not separate
  // the gate mutants at 471:7 — the member-mutation facts pass is
  // idempotent per state and is driven earlier by the delegate-write
  // eligibility check whenever the program's calls are observed by
  // the ambient-writes walk, which every registration idiom
  // produces; in 17 probed arrangements (webpack and Metro, direct,
  // aliased, nested, and relocated d calls) the finalized output was
  // identical with the gate forced on, forced off, and inverted.
  // See the survivor inventory for the argued verdict.
  const result = analyzeJavaScriptStaticSource(
    "__d(function (g, r, i, a, m, e, d) { r.d(e, {declared: () => 1}); e.member = 1; }, 17, []); __r(17);",
  );
  expect(result.bundler_registrations).toHaveLength(1);
  expect(result.bundler_registrations[0]?.modules[0]?.exports).toEqual([
    "declared",
    "member",
  ]);
});

it("reports multiple semantic resource limits in sorted order", () => {
  // Pins the reported pair and its order. Note: through this entry
  // point the alias budget is spent while the branching require
  // receiver is processed, ahead of every traversal/finisher spend
  // probed (cast-chain depth, giant-string bytes, union candidates,
  // in both source orders), so insertion order matched sorted order
  // in every arrangement and the sort-drop mutant at 264:26 is not
  // separated by this fixture — see the lane report for the argued
  // verdict and the oracle measurements behind it.
  const source = [
    `const v = 1${" as unknown".repeat(300)}; fetch(v);`,
    aliasSelectionBudgetSource(),
  ].join("\n");
  const result = analyzeJavaScriptStaticSource(source);
  expect(
    result.analysis_coverage?.examination.semantic_resource_limits,
  ).toEqual(["alias-selections", "expression-depth"]);
});

it("joins deferred GraphQL source operations after traversal endpoints", () => {
  // The operation inside a graphql-js Source object is owned by
  // that object during traversal and is only joined by the RPC
  // scan's finish, after the fetch endpoint recorded during the
  // walk, so the finalized order is traversal-then-deferred even
  // though the operation sits earlier in the source. The pending
  // network and sqlite lists are both empty here, so this order
  // also pins the guards at 213/214: when either guard is weakened
  // the partial-endpoint finisher runs anyway and its offset sort
  // moves the deferred operation ahead of the fetch endpoint.
  const result = analyzeJavaScriptStaticSource(
    [
      'const source = { body: "query EarlyOp { viewer { id } }", name: "GraphQL request", locationOffset: { line: 1, column: 1 } };',
      'fetch("https://api.example.test/data");',
    ].join("\n"),
  );
  expect(result.endpoints.map(({ value }) => value)).toEqual([
    "https://api.example.test/data",
    "EarlyOp",
  ]);
});

it("keeps finalized references in source order across reference kinds", () => {
  // Pins the reference order the module-require finisher's offset
  // sort would preserve. Note: this fixture does not separate the
  // guard mutants at 208:7 — every reference appender runs during
  // the pre-order traversal (imports, re-exports, requires,
  // dynamic imports, import-equals), so the collection reaches
  // the guard already ordered by node start, and the finisher's
  // stable sort is the identity on it whether or not the guard
  // lets the finisher run with an empty pending list. See the
  // survivor inventory for the argued verdict.
  const result = analyzeJavaScriptStaticSource(
    [
      'import fs from "fs";',
      'export { x } from "./re.js";',
      'const a = require("./a.js");',
      "__d(function (global, require, module, exports) {",
      "  var e = require(1);",
      "}, 2, [1]);",
      'import("./dyn.js");',
      'const b = require("./b.js");',
      'import dep = require("./dep.js");',
    ].join("\n"),
  );
  expect(
    result.references.map(({ kind, specifier, location }) => ({
      kind,
      specifier,
      line: location.start.line,
    })),
  ).toEqual([
    { kind: "static-import", specifier: "fs", line: 1 },
    { kind: "static-import", specifier: "./re.js", line: 2 },
    { kind: "require", specifier: null, line: 3 },
    { kind: "require", specifier: "1", line: 5 },
    { kind: "dynamic-import", specifier: "./dyn.js", line: 7 },
    { kind: "require", specifier: null, line: 8 },
    { kind: "require", specifier: "./dep.js", line: 9 },
  ]);
});

it("leaves a mutation-built bridge exposure without call paths", () => {
  // Pins the production outcome behind the other half of the
  // 208:7 guard: with no pending module-require calls, the block
  // the guard protects would only add a member-mutation facts
  // pass ahead of the call-path collection. That pass is guarded
  // per state, and in this pipeline its recorded effects are
  // consumed after the guard only by finishers that re-run it
  // first (the 213 block) or not at all (the call-path collector
  // never queries reference effects), so an exposure assembled
  // by member writes finalizes the same whether the pass is
  // driven at the guard or left undriven. Measured identical
  // full output under both guard mutants across the probe
  // battery; see the survivor inventory for the argued verdict
  // and its stated limits.
  const result = analyzeJavaScriptStaticSource(
    [
      'const { contextBridge, ipcRenderer } = require("electron");',
      "const api = {};",
      'api.ping = () => ipcRenderer.invoke("ping");',
      'contextBridge.exposeInMainWorld("api", api);',
    ].join("\n"),
  );
  expect(result.electron.call_paths).toBeUndefined();
});
