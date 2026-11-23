import { expect, it } from "vitest";

import { parseJavaScriptSource } from "./javascriptSourceParser.js";
import {
  analyzeJavaScriptStaticSource,
  analyzeParsedJavaScriptStaticSource,
} from "./javascriptStaticAnalysis.js";
import type { JavaScriptStaticAnalysis } from "./javascriptStaticAnalysisTypes.js";

// Scenario tests for the unmodified-global-reference gate
// (javascriptSemanticGlobalReference.ts), driven through the public
// static-analysis entry with fixtures shaped so each guard is
// load-bearing. The Stryker pilot left six survivors in this file; five
// of them are one missing scenario and the sixth is a length check no
// fixture made load-bearing (see the goal's survivor inventory).
//
// A fetch call through a named global namespace (window.fetch,
// self.fetch) is recognized only while the namespace slot itself
// carries no retained ambient write: once the slot is replaced, the
// reference may no longer denote the intrinsic, whatever the member
// under it spells. No lane fixture paired a named-namespace reference
// with a retained write to that namespace slot; the bare-assignment
// fixtures below are the discriminating shape, because a write through
// globalThis.window is also blocked by a second mechanism, while the
// bare slot replacement is blocked by the gate's namespace-slot check
// alone.
//
// A CommonJS export is collected through Object.defineProperty only
// when the callee's member path matches the intrinsic path in full. A
// bare Object(...) call and a window.Object(...) call share a strict
// prefix of ["Object", "defineProperty"] but are not the intrinsic, so
// they collect nothing; the full spellings collect the export. No lane
// fixture drove the gate with a callee whose member path shares the
// expected prefix but differs in length.

const fetchEndpoints = (source: string) =>
  analyzeJavaScriptStaticSource(source)
    .endpoints.filter((endpoint) => endpoint.mechanism.includes("fetch"))
    .map((endpoint) => ({
      kind: endpoint.kind,
      value: endpoint.value,
      mechanism: endpoint.mechanism,
      resolution: endpoint.resolution ?? null,
    }));

const exportsOf = (source: string): Record<string, readonly string[]> => {
  const analysis: JavaScriptStaticAnalysis =
    analyzeParsedJavaScriptStaticSource(
      source,
      parseJavaScriptSource(source, "bundle.js")!,
    );
  const out: Record<string, readonly string[]> = {};
  for (const registration of analysis.bundler_registrations)
    for (const module of registration.modules)
      out[module.module_key] = module.exports;
  return out;
};

const moduleWith = (body: string) =>
  `__d(function (g, r, i, a, m, e, d) { ${body} }, 300, []);`;

it("recognizes a fetch call through the window namespace while its slot is untouched", () => {
  expect(
    fetchEndpoints(`window.fetch("https://api.example.test/items");`),
  ).toEqual([
    {
      kind: "network",
      value: "https://api.example.test/items",
      mechanism: "call:window.fetch",
      resolution: null,
    },
  ]);
});

it("does not recognize window.fetch after a bare assignment replaces the window slot", () => {
  expect(
    fetchEndpoints(
      `window = replacement; window.fetch("https://api.example.test/items");`,
    ),
  ).toEqual([]);
});

it("does not recognize window.fetch after a globalThis.window assignment replaces the slot", () => {
  expect(
    fetchEndpoints(
      `globalThis.window = replacement; window.fetch("https://api.example.test/items");`,
    ),
  ).toEqual([]);
});

it("does not recognize self.fetch after a bare assignment replaces the self slot", () => {
  expect(
    fetchEndpoints(
      `self = replacement; self.fetch("https://api.example.test/items");`,
    ),
  ).toEqual([]);
});

it("recognizes fetch calls through the self and globalThis namespaces while their slots are untouched", () => {
  expect(
    fetchEndpoints(`self.fetch("https://api.example.test/items");`),
  ).toEqual([
    {
      kind: "network",
      value: "https://api.example.test/items",
      mechanism: "call:self.fetch",
      resolution: null,
    },
  ]);
  expect(
    fetchEndpoints(`globalThis.fetch("https://api.example.test/items");`),
  ).toEqual([
    {
      kind: "network",
      value: "https://api.example.test/items",
      mechanism: "call:globalThis.fetch",
      resolution: null,
    },
  ]);
});

it("collects an export defined through Object.defineProperty", () => {
  expect(
    exportsOf(moduleWith(`Object.defineProperty(e, "answer", { value: 42 });`)),
  ).toEqual({ "300": ["answer"] });
});

it("collects an export defined through window.Object.defineProperty", () => {
  expect(
    exportsOf(
      moduleWith(`window.Object.defineProperty(e, "answer", { value: 42 });`),
    ),
  ).toEqual({ "300": ["answer"] });
});

it("does not collect an export from a bare Object call whose member path is a strict prefix of the intrinsic path", () => {
  expect(exportsOf(moduleWith(`Object(e, "answer", { value: 42 });`))).toEqual({
    "300": [],
  });
});

it("does not collect an export from a window.Object call whose member path is a strict prefix of the intrinsic path", () => {
  expect(
    exportsOf(moduleWith(`window.Object(e, "answer", { value: 42 });`)),
  ).toEqual({ "300": [] });
});

it("does not collect an export from a self.Object call whose member path is a strict prefix of the intrinsic path", () => {
  expect(
    exportsOf(moduleWith(`self.Object(e, "answer", { value: 42 });`)),
  ).toEqual({ "300": [] });
});
