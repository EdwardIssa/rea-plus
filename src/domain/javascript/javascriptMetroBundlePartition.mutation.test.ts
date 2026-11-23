import { expect, it } from "vitest";
import { parseJavaScriptSource } from "./javascriptSourceParser.js";
import { partitionMetroBundle } from "./javascriptMetroBundlePartition.js";

// Scenario tests for the Metro partition guards and bookkeeping, driven
// through the public partition entry with fixtures shaped so each guard
// is load-bearing: a definition-shaped call the callee guard alone keeps
// out, a readable key behind a non-function factory, an arrow-function
// factory, per-element unreadable dependency arrays, a zero-span
// program, a byte share sitting on the dominance threshold, and shard
// byte totals pinned against the parsed statement spans. These pin the
// behaviors the Stryker pilot found unmeasured in
// javascriptMetroBundlePartition.ts (see the goal's survivor inventory).

const factory =
  "function (global, require, module, exports) { exports.v = 1; }";

const moduleStatement = (key: number, deps = "[]"): string =>
  `__d(${factory}, ${String(key)}, ${deps});`;

const parse = (source: string) =>
  parseJavaScriptSource(source, "bundle.js")!.program;

it("does not count a definition-shaped call with a renamed callee", () => {
  const source = [
    "var modules = {};",
    ...Array.from({ length: 7 }, (_, i) => moduleStatement(i)),
    // Shaped like a definition (function factory, readable key) under a
    // different callee name: only the callee-name guard keeps it out,
    // and seven genuine definitions stay below the module threshold.
    `register(${factory}, 7, []);`,
    "__r(0);",
  ].join("\n");
  expect(partitionMetroBundle(parse(source))).toBeNull();
});

it("does not count a definition-shaped call with a member callee", () => {
  const source = [
    "var modules = {};",
    ...Array.from({ length: 7 }, (_, i) => moduleStatement(i)),
    // A member-expression callee is not the runtime global, however the
    // call is shaped; the identifier half of the callee guard decides.
    `runtime.__d(${factory}, 7, []);`,
    "__r(0);",
  ].join("\n");
  expect(partitionMetroBundle(parse(source))).toBeNull();
});

it("does not count a definition whose first argument is not a function", () => {
  const source = [
    "var modules = {};",
    ...Array.from({ length: 7 }, (_, i) => moduleStatement(i)),
    // The module key stays readable, so only the factory-kind guard
    // keeps this call out of the module table.
    "__d({}, 7, []);",
    "__r(0);",
  ].join("\n");
  expect(partitionMetroBundle(parse(source))).toBeNull();
});

it("partitions modules whose factories are arrow functions", () => {
  const source = [
    "var modules = {};",
    ...Array.from(
      { length: 10 },
      (_, i) =>
        `__d((global, require, module, exports) => { exports.v = 1; }, ${String(i)}, [${String((i + 1) % 10)}]);`,
    ),
    "__r(0);",
  ].join("\n");
  const partition = partitionMetroBundle(parse(source));
  expect(partition).not.toBeNull();
  expect(partition!.moduleCount).toBe(10);
  expect(partition!.shards[1]!.moduleKey).toBe("0");
  expect(partition!.shards[1]!.dependencyModuleKeys).toEqual(["1"]);
});

it("leaves dependency keys unknown when any array element is unreadable", () => {
  const source = [
    "var modules = {};",
    ...Array.from({ length: 10 }, (_, i) => {
      if (i === 1) return moduleStatement(1, "[0, dynamicDep]");
      if (i === 2) return moduleStatement(2, "[0, , 3]");
      if (i === 3) return moduleStatement(3, "[...sharedDeps]");
      return moduleStatement(i, `[${String((i + 1) % 10)}]`);
    }),
    "__r(0);",
  ].join("\n");
  const partition = partitionMetroBundle(parse(source));
  expect(partition).not.toBeNull();
  // Control: a fully static array still yields its keys.
  expect(partition!.shards[1]!.dependencyModuleKeys).toEqual(["1"]);
  // One unreadable element anywhere in the array, an identifier, a
  // hole, or a spread, makes the whole declaration unknown: the keys
  // read before it are not kept as a partial answer.
  expect(partition!.shards[2]!.dependencyModuleKeys).toBeNull();
  expect(partition!.shards[3]!.dependencyModuleKeys).toBeNull();
  expect(partition!.shards[4]!.dependencyModuleKeys).toBeNull();
});

it("returns null when the program's statements carry no source span", () => {
  const source = [
    "var modules = {};",
    ...Array.from({ length: 8 }, (_, i) => moduleStatement(i)),
    "__r(0);",
  ].join("\n");
  const program = parse(source);
  expect(partitionMetroBundle(program)).not.toBeNull();
  // Zeroing every statement span leaves eight definitions over zero
  // total bytes. The partition must refuse: the byte share would be
  // 0 / 0 (NaN), which does not fall below the dominance threshold.
  for (const statement of program.body) {
    statement.start = 0;
    statement.end = 0;
  }
  expect(partitionMetroBundle(program)).toBeNull();
});

it("partitions when module bytes are exactly half the program bytes", () => {
  const modules = Array.from({ length: 8 }, (_, i) => moduleStatement(i));
  const build = (padLength: number): string =>
    [`var pad = "${"x".repeat(padLength)}";`, ...modules].join("\n");
  // The partition sums each top-level statement's (end - start) span,
  // and the padding sits inside the prelude statement's own span, so
  // growing the pad string by one character grows the prelude total by
  // one byte while the module total is unchanged. Measure the spans
  // with an empty pad, then solve the pad length that makes prelude
  // bytes equal module bytes: the share lands on the 0.5 threshold.
  const probe = parse(build(0));
  const spans = probe.body.map(
    (statement) => (statement.end ?? 0) - (statement.start ?? 0),
  );
  const moduleBytes = spans.slice(1).reduce((sum, bytes) => sum + bytes, 0);
  const padLength = moduleBytes - spans[0]!;
  expect(padLength).toBeGreaterThan(0);
  const partition = partitionMetroBundle(parse(build(padLength)));
  expect(partition).not.toBeNull();
  expect(partition!.moduleByteShare).toBe(0.5);
  // One more pad byte tips the share below the threshold.
  expect(partitionMetroBundle(parse(build(padLength + 1)))).toBeNull();
});

it("reports shard bytes matching the parsed statement spans", () => {
  const source = [
    "var modules = {};",
    ...Array.from({ length: 12 }, (_, i) => moduleStatement(i)),
    "__r(0);",
  ].join("\n");
  const program = parse(source);
  const spans = program.body.map(
    (statement) => (statement.end ?? 0) - (statement.start ?? 0),
  );
  const totalBytes = spans.reduce((sum, bytes) => sum + bytes, 0);
  // The prelude holds the first and last statements; the rest are the
  // twelve module definitions in order.
  const preludeBytes = spans[0]! + spans[spans.length - 1]!;
  const partition = partitionMetroBundle(program);
  expect(partition).not.toBeNull();
  expect(partition!.shards[0]!.kind).toBe("prelude");
  expect(partition!.shards[0]!.bytes).toBe(preludeBytes);
  partition!.shards.slice(1).forEach((shard, index) => {
    expect(shard.bytes).toBe(spans[index + 1]);
  });
  expect(partition!.moduleByteShare).toBe(
    (totalBytes - preludeBytes) / totalBytes,
  );
});
