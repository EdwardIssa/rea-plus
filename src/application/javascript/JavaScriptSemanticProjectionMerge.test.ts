import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import { analyzeJavaScriptSemantics } from "../../domain/javascript/javascriptSemanticAnalysis.js";
import { mergeJavaScriptSemanticFileProjections } from "../../domain/javascript/javascriptSemanticFileProjection.js";
import {
  analyzeJavaScriptStaticSource,
  analyzeParsedJavaScriptStaticSourceSteps,
} from "../../domain/javascript/javascriptStaticAnalysis.js";
import { mergeJavaScriptStaticAnalyses } from "../../domain/javascript/javascriptStaticAnalysisMerge.js";
import { partitionMetroBundle } from "../../domain/javascript/javascriptMetroBundlePartition.js";
import { parseJavaScriptSource } from "../../domain/javascript/javascriptSourceParser.js";
import { resolveCrossShardRpcEndpoints } from "../../domain/javascript/javascriptCrossShardRpcResolution.js";
import type { JavaScriptStaticEndpoint } from "../../domain/javascript/javascriptStaticAnalysisTypes.js";
import { projectJavaScriptSemanticFileSteps } from "./JavaScriptSemanticGraphBuilder.js";
import { completeJavaScriptAnalysisSteps } from "./JavaScriptAnalysisControl.js";

const digest = "a".repeat(64);
const source = (value: string): JavaScriptArtifactFile => ({
  path: "app.js",
  sha256: createHash("sha256").update(value).digest("hex"),
  container_sha256: digest,
  bytes: Buffer.byteLength(value),
  inventory_artifact_id: `art_${digest}`,
  kind: "javascript",
  unpacked: false,
  text: { included: true, value },
});

const projectFile = async (value: string, nodes = 20_000, unknowns = 2_000) => {
  const file = source(value);
  if (!file.text.included) throw new Error("Expected inert source");
  return completeJavaScriptAnalysisSteps(
    projectJavaScriptSemanticFileSteps(
      file,
      analyzeJavaScriptSemantics(value),
      { nodes, unknowns },
    ),
  );
};

it("dedupes a shard projection merged with itself", async () => {
  const projection = await projectFile(
    "globalThis.alpha.run(globalThis.beta);\n",
  );
  const merged = mergeJavaScriptSemanticFileProjections([
    projection,
    projection,
  ]);
  expect(merged.nodes).toEqual(projection.nodes);
  expect(merged.relations).toEqual(projection.relations);
  expect(merged.unknowns).toEqual(projection.unknowns);
  expect(merged.roots).toEqual(projection.roots);
});

it("sums omitted unknown occurrences across shards", async () => {
  const text = "globalThis.u.p(globalThis.v[k]);\n".repeat(4);
  const bounded = await projectFile(text, 200, 2);
  expect(bounded.omittedUnknownOccurrences?.length).toBeGreaterThan(0);
  const merged = mergeJavaScriptSemanticFileProjections([bounded, bounded]);
  const total = (rows: typeof bounded.omittedUnknownOccurrences) =>
    (rows ?? []).reduce((sum, row) => sum + row.occurrences, 0);
  expect(total(merged.omittedUnknownOccurrences)).toBe(
    2 * total(bounded.omittedUnknownOccurrences),
  );
});

it("propagates node truncation from any shard", async () => {
  const complete = await projectFile("globalThis.a.b();\n");
  const truncated = { ...complete, nodesTruncated: true };
  const merged = mergeJavaScriptSemanticFileProjections([complete, truncated]);
  expect(merged.nodesTruncated).toBe(true);
});

// A Metro bundle whose generic RPC client is published by one module and
// consumed from two others: module 100 assigns a createClient result to its
// `supabase` export; module 101 reads it through a namespace member and
// module 102 destructures it. Whole-file analysis surfaces both `.rpc()`
// endpoints; per-shard analysis cannot classify either receiver locally.
const crossModuleBundle = [
  `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
     _exports.supabase = createClient("https://example.supabase.co", "anon-key");
   }, 100, []);`,
  `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
     var _ns = _r(_deps[0]);
     var dynamicName = "ignored";
     _exports.load = function () {
       _ns.supabase.rpc(dynamicName);
       return _ns.supabase.rpc("cast_guest_vote", { ballot: 1 });
     };
   }, 101, [100]);`,
  `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
     var { supabase } = _r(_deps[0]);
     _exports.issue = function () {
       return supabase.rpc("issue_guest_token", {});
     };
   }, 102, [100]);`,
  ...[103, 104, 105, 106, 107].map(
    (key) =>
      `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
         _exports.filler${String(key)} = ${String(key)};
       }, ${String(key)}, []);`,
  ),
  `__r(101);`,
].join("\n");

const rpcEndpoints = (
  endpoints: readonly JavaScriptStaticEndpoint[],
): string[] =>
  endpoints
    .filter(({ mechanism }) => mechanism === "rpc:call")
    .map(
      ({ value, interpretation, module_key }) =>
        `${value}|${interpretation ?? ""}|${module_key ?? ""}`,
    )
    .sort();

const shardedStaticFacts = async (value: string) => {
  const parsed = parseJavaScriptSource(value, "app.js");
  if (parsed === null) throw new Error("Expected the fixture to parse");
  const partition = partitionMetroBundle(parsed.program);
  if (partition === null) throw new Error("Expected a Metro partition");
  const original = parsed.program.body;
  try {
    const analyses = [];
    for (const shard of partition.shards) {
      parsed.program.body = [...shard.statements];
      analyses.push(
        await completeJavaScriptAnalysisSteps(
          analyzeParsedJavaScriptStaticSourceSteps(value, parsed),
        ),
      );
    }
    return mergeJavaScriptStaticAnalyses(analyses);
  } finally {
    parsed.program.body = original;
  }
};

it("resolves cross-shard RPC endpoints to whole-file parity", async () => {
  const whole = analyzeJavaScriptStaticSource(crossModuleBundle);
  const expected = rpcEndpoints(whole.endpoints);
  expect(expected).toEqual([
    "cast_guest_vote|candidate|101",
    "issue_guest_token|candidate|102",
  ]);
  const merged = await shardedStaticFacts(crossModuleBundle);
  // The gap the join closes: neither receiver classifies inside its shard,
  // and the non-literal call in module 101 is never recorded.
  expect(rpcEndpoints(merged.endpoints)).toEqual([]);
  expect(
    (merged.rpc_candidates ?? []).map(({ value }) => value).sort(),
  ).toEqual(["cast_guest_vote", "issue_guest_token"]);
  const resolved = resolveCrossShardRpcEndpoints(merged);
  expect(rpcEndpoints([...merged.endpoints, ...resolved])).toEqual(expected);
});

// Object-form dependency maps: Metro emits `__d(factory, id, {"0": 200,
// "paths": {}})` instead of an array for sparse maps. The requested module
// of a `_r(_deps[0])` binding must still resolve through the map's numeric
// keys so namespace and destructured candidates reach whole-file parity.
const objectFormBundle = [
  `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
     _exports.supabase = createClient("https://example.supabase.co", "anon-key");
   }, 200, []);`,
  `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
     var _ns = _r(_deps[0]);
     _exports.load = function () {
       return _ns.supabase.rpc("object_form_rpc", {});
     };
   }, 201, {"0": 200, "paths": {}});`,
  `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
     var { supabase } = _r(_deps[0]);
     _exports.issue = function () {
       return supabase.rpc("object_form_destructured", {});
     };
   }, 202, {"0": 200, "paths": {}});`,
  ...[203, 204, 205, 206, 207].map(
    (key) =>
      `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
         _exports.filler${String(key)} = ${String(key)};
       }, ${String(key)}, []);`,
  ),
  `__r(201);`,
].join("\n");

it("resolves object-form dependency maps to whole-file parity", async () => {
  const whole = analyzeJavaScriptStaticSource(objectFormBundle);
  const expected = rpcEndpoints(whole.endpoints);
  expect(expected).toEqual([
    "object_form_destructured|candidate|202",
    "object_form_rpc|candidate|201",
  ]);
  const merged = await shardedStaticFacts(objectFormBundle);
  expect(rpcEndpoints(merged.endpoints)).toEqual([]);
  const candidates = new Map(
    (merged.rpc_candidates ?? []).map((candidate) => [
      candidate.value,
      candidate.requested_module_key,
    ]),
  );
  expect(candidates.get("object_form_rpc")).toBe("200");
  expect(candidates.get("object_form_destructured")).toBe("200");
  const resolved = resolveCrossShardRpcEndpoints(merged);
  expect(rpcEndpoints([...merged.endpoints, ...resolved])).toEqual(expected);
});

// A repeated index key in an object-form map resolves to its last
// property, as in object evaluation: the first key names a module that
// publishes nothing, the last names the client module.
const repeatedKeyBundle = [
  `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
     _exports.supabase = createClient("https://example.supabase.co", "anon-key");
   }, 200, []);`,
  `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
     var _ns = _r(_deps[0]);
     _exports.load = function () {
       return _ns.supabase.rpc("object_form_repeated_key", {});
     };
   }, 201, {"0": 999, "0": 200, "paths": {}});`,
  ...[202, 203, 204, 205, 206, 207].map(
    (key) =>
      `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
         _exports.filler${String(key)} = ${String(key)};
       }, ${String(key)}, []);`,
  ),
  `__r(201);`,
].join("\n");

it("resolves a repeated object-form dependency key to its last value", async () => {
  const merged = await shardedStaticFacts(repeatedKeyBundle);
  const candidate = (merged.rpc_candidates ?? []).find(
    ({ value }) => value === "object_form_repeated_key",
  );
  expect(candidate?.requested_module_key).toBe("200");
  const resolved = resolveCrossShardRpcEndpoints(merged);
  expect(rpcEndpoints(resolved)).toEqual([
    "object_form_repeated_key|candidate|201",
  ]);
});

// An object-form map that lacks the index a require call uses leaves the
// requested module unproven: the candidate is retained with a null key and
// the join emits nothing. Whole-file analysis still surfaces the call —
// it classifies the receiver from the member name without consulting the
// map — so this divergence is the join's conservative boundary, pinned
// here rather than treated as a defect.
const missingIndexBundle = [
  `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
     _exports.supabase = createClient("https://example.supabase.co", "anon-key");
   }, 200, []);`,
  `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
     var _ns = _r(_deps[0]);
     _exports.load = function () {
       return _ns.supabase.rpc("object_form_missing_index", {});
     };
   }, 201, {"1": 200, "paths": {}});`,
  ...[202, 203, 204, 205, 206, 207].map(
    (key) =>
      `__d(function (global, _r, _importDefault, _importAll, _module, _exports, _deps) {
         _exports.filler${String(key)} = ${String(key)};
       }, ${String(key)}, []);`,
  ),
  `__r(201);`,
].join("\n");

it("leaves an object-form candidate unresolved when its index is absent", async () => {
  const whole = analyzeJavaScriptStaticSource(missingIndexBundle);
  expect(rpcEndpoints(whole.endpoints)).toEqual([
    "object_form_missing_index|candidate|201",
  ]);
  const merged = await shardedStaticFacts(missingIndexBundle);
  const candidate = (merged.rpc_candidates ?? []).find(
    ({ value }) => value === "object_form_missing_index",
  );
  expect(candidate?.requested_module_key).toBeNull();
  expect(rpcEndpoints(resolveCrossShardRpcEndpoints(merged))).toEqual([]);
});
