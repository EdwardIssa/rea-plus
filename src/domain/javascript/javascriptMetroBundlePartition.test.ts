import { expect, it } from "vitest";
import { parseJavaScriptSource } from "./javascriptSourceParser.js";
import { partitionMetroBundle } from "./javascriptMetroBundlePartition.js";

const bundle = (modules: number, body = "exports.value = 1;"): string =>
  [
    "var modules = {};",
    ...Array.from(
      { length: modules },
      (_, i) =>
        `__d(function (global, require, module, exports) { ${body} }, ${String(i)}, []);`,
    ),
    "__r(0);",
  ].join("\n");

it("partitions a Metro bundle into a prelude and one shard per module", () => {
  const parsed = parseJavaScriptSource(bundle(12), "bundle.js");
  expect(parsed).not.toBeNull();
  const partition = partitionMetroBundle(parsed!.program);
  expect(partition).not.toBeNull();
  expect(partition!.moduleCount).toBe(12);
  expect(partition!.shards).toHaveLength(13);
  expect(partition!.shards[0]!.kind).toBe("prelude");
  expect(partition!.shards[0]!.statements).toHaveLength(2);
  expect(partition!.moduleByteShare).toBeGreaterThan(0.5);
  expect(partition!.shards[1]!.moduleKey).toBe("0");
  expect(partition!.shards[12]!.moduleKey).toBe("11");
});

it("records the dependency keys each module definition declares", () => {
  const source = [
    "var modules = {};",
    ...Array.from(
      { length: 10 },
      (_, i) =>
        `__d(function (global, require, module, exports) { exports.v = 1; }, ${String(i)}, [${String((i + 1) % 10)}, ${String((i + 2) % 10)}]);`,
    ),
    "__r(0);",
  ].join("\n");
  const partition = partitionMetroBundle(
    parseJavaScriptSource(source, "bundle.js")!.program,
  );
  expect(partition).not.toBeNull();
  expect(partition!.shards[0]!.dependencyModuleKeys).toBeNull();
  expect(partition!.shards[1]!.dependencyModuleKeys).toEqual(["1", "2"]);
  expect(partition!.shards[10]!.dependencyModuleKeys).toEqual(["0", "1"]);
});

it("leaves dependency keys unknown when the argument is not a static array", () => {
  const source = [
    "var modules = {};",
    "var deps = [1];",
    ...Array.from({ length: 10 }, (_, i) =>
      i === 3
        ? `__d(function (global, require, module, exports) { exports.v = 1; }, 3, deps);`
        : `__d(function (global, require, module, exports) { exports.v = 1; }, ${String(i)});`,
    ),
    "__r(0);",
  ].join("\n");
  const partition = partitionMetroBundle(
    parseJavaScriptSource(source, "bundle.js")!.program,
  );
  expect(partition).not.toBeNull();
  // A dynamic dependency argument stays unknown, never guessed.
  expect(partition!.shards[4]!.dependencyModuleKeys).toBeNull();
  // An absent dependency argument declares no dependencies.
  expect(partition!.shards[1]!.dependencyModuleKeys).toEqual([]);
});

it("returns null below the module threshold", () => {
  const parsed = parseJavaScriptSource(bundle(4), "bundle.js");
  expect(partitionMetroBundle(parsed!.program)).toBeNull();
});

it("returns null when module definitions do not dominate", () => {
  const filler = `function filler() { return "${"x".repeat(4000)}"; }`;
  const source = [filler, ...Array.from({ length: 10 }, () => filler)].join(
    "\n",
  );
  const parsed = parseJavaScriptSource(
    `${source}\n${bundle(10, "exports.v = 1;")}`,
    "bundle.js",
  );
  const partition = partitionMetroBundle(parsed!.program);
  // 44 KB of filler against ~1 KB of modules: not a module-table bundle.
  expect(partition).toBeNull();
});

it("returns null for ordinary sources", () => {
  const parsed = parseJavaScriptSource(
    "export const answer = 42;\nconsole.log(answer);",
    "plain.js",
  );
  expect(partitionMetroBundle(parsed!.program)).toBeNull();
});
