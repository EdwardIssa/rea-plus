import { expect, it } from "vitest";
import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

const metroBundle = `
__d(function(g, r, i, a, m, e, d) {
  var dep = r(d[0]);
  m.exports = { run: function() { return dep.go(); } };
}, 0, [1]);
__d(function(g, r, i, a, m, e, d) {
  e.go = function() { return 42; };
}, 1, []);
__r(0);
`;

it("recovers a Metro module table from __d definitions and the __r entry", () => {
  const result = analyzeJavaScriptStaticSource(metroBundle);
  expect(result.parse_status).toBe("complete");
  expect(result.bundler_registrations).toHaveLength(1);
  const registration = result.bundler_registrations[0]!;
  expect(registration).toMatchObject({
    bundler: "metro",
    runtime: "metro",
    runtime_require_name: "__r",
    runtime_module_cache_status: "not-observed",
    entry_module_keys: ["0"],
    unknown_entry_module_keys: 0,
  });
  expect(registration.modules.map((module) => module.module_key)).toEqual([
    "0",
    "1",
  ]);
  expect(registration.modules[0]).toMatchObject({
    factory_require_name: "r",
    exports: ["run"],
  });
  expect(registration.modules[1]).toMatchObject({
    factory_require_name: "r",
    exports: ["go"],
  });
  for (const module of registration.modules) {
    expect(module.source_sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(module.structural_fingerprint_sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(module.location.end.line).toBeGreaterThanOrEqual(
      module.location.start.line,
    );
  }
});

it("attributes findings inside a factory to that module", () => {
  const result = analyzeJavaScriptStaticSource(metroBundle);
  const attributed = result.references.filter(
    (reference) => reference.module_key !== null,
  );
  expect(attributed.length).toBeGreaterThan(0);
  expect(attributed.every((reference) => reference.module_key === "0")).toBe(
    true,
  );
});

it("does not treat a locally bound __d as a Metro definition", () => {
  const result = analyzeJavaScriptStaticSource(`
    function __d(factory, id, deps) { return factory; }
    __d(function(g, r, i, a, m, e, d) { m.exports = 1; }, 7, []);
  `);
  expect(result.bundler_registrations).toHaveLength(0);
});

it("does not treat a locally bound __r as a Metro entry", () => {
  const result = analyzeJavaScriptStaticSource(`
    function __r(id) { return id; }
    __d(function(g, r, i, a, m, e, d) { m.exports = 1; }, 7, []);
    __r(7);
  `);
  expect(result.bundler_registrations).toHaveLength(1);
  expect(result.bundler_registrations[0]!.entry_module_keys).toEqual([]);
});

it("counts a definition whose module key is not a literal as unknown", () => {
  const result = analyzeJavaScriptStaticSource(`
    __d(function(g, r, i, a, m, e, d) { m.exports = 1; }, dynamicId, []);
  `);
  expect(result.bundler_registrations).toHaveLength(0);
  expect(result.analysis_coverage!.semantics.unknown_findings).toBeGreaterThan(
    0,
  );
});
