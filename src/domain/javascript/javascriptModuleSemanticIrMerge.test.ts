import { expect, it } from "vitest";
import { analyzeJavaScriptSemantics } from "./javascriptSemanticAnalysis.js";
import {
  mergeJavaScriptModuleSemantics,
  projectJavaScriptModuleSemantics,
  type JavaScriptModuleSemanticIr,
} from "./javascriptModuleSemanticIr.js";

const project = (source: string): JavaScriptModuleSemanticIr =>
  projectJavaScriptModuleSemantics(analyzeJavaScriptSemantics(source));

it("folds identical shard facts by identity", () => {
  const shard = project(
    'import { readFile } from "node:fs";\nexport const load = readFile;',
  );
  const merged = mergeJavaScriptModuleSemantics([shard, shard]);
  expect(merged.scopes).toEqual(shard.scopes);
  expect(merged.bindings).toEqual(shard.bindings);
  expect(merged.callables).toEqual(shard.callables);
  expect(merged.coverage.status).toBe(shard.coverage.status);
});

it("unions module links across shards", () => {
  const left = project('import { a } from "./a.js";\nexport const x = a;');
  const right = project('import { b } from "./b.js";\nexport const y = b;');
  const merged = mergeJavaScriptModuleSemantics([left, right]);
  expect(merged.moduleLinks.length).toBe(
    left.moduleLinks.length + right.moduleLinks.length,
  );
});

it("degrades coverage conservatively and dedupes limitations", () => {
  const complete = project("export const a = 1;");
  const partial: JavaScriptModuleSemanticIr = {
    ...project("export const b = 2;"),
    coverage: { status: "partial", omittedCount: null },
    limitations: ["shard limit"],
  };
  const merged = mergeJavaScriptModuleSemantics(
    [complete, partial],
    ["shard limit", "extra"],
  );
  expect(merged.coverage.status).toBe("partial");
  expect(merged.coverage.omittedCount).toBeNull();
  expect(merged.limitations).toEqual([
    ...complete.limitations,
    "shard limit",
    "extra",
  ]);
});

it("fails the merged coverage when any shard failed", () => {
  const failed: JavaScriptModuleSemanticIr = {
    ...project("export const a = 1;"),
    coverage: { status: "failed", omittedCount: null },
  };
  const merged = mergeJavaScriptModuleSemantics([
    project("export const b = 2;"),
    failed,
  ]);
  expect(merged.coverage.status).toBe("failed");
});
