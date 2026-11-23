import { expect, it } from "vitest";
import type {
  ElectronAppPathChangeFinding,
  ElectronCallPath,
  ElectronStaticFindings,
} from "./electronStaticAnalysisTypes.js";
import type { JavaScriptRouteSourceFacts } from "./javascriptRouteFacts.js";
import type { JavaScriptStaticCoverage } from "./javascriptStaticCoverage.js";
import {
  mergeJavaScriptStaticAnalyses,
  type JavaScriptDegradedShard,
} from "./javascriptStaticAnalysisMerge.js";
import {
  JAVASCRIPT_AST_FINGERPRINT_ALGORITHM,
  type JavaScriptBundlerModule,
  type JavaScriptBundlerRegistration,
  type JavaScriptSourceRange,
  type JavaScriptStaticAnalysis,
} from "./javascriptStaticAnalysisTypes.js";

// Scenario tests for the shard merge's bookkeeping behavior, built from
// direct shard fixtures rather than parsed bundles: the coverage envelope,
// the folded Metro registration's counters and anchoring, degraded-module
// salvage placement, route-capacity selection, and the presence/absence
// contract for shard-optional findings (routes, RPC, Electron). These pin
// the behaviors the Stryker pilot found unmeasured in
// javascriptStaticAnalysisMerge.ts (see the goal's survivor inventory).

const locationAt = (line: number): JavaScriptSourceRange => ({
  start: { line, column: 0 },
  end: { line, column: 8 },
});

const coverage = (
  options: {
    unknownFindings?: number | null;
    examinationStatus?: "complete" | "limited" | "not-examined";
    resourceLimits?: JavaScriptStaticCoverage["examination"]["semantic_resource_limits"];
    electronCallPathsLimited?: boolean;
    electronApplicability?: "observed" | "unknown";
  } = {},
): JavaScriptStaticCoverage => ({
  syntax: { status: "complete", error_count: 0 },
  semantics: {
    unknown_findings: options.unknownFindings ?? 0,
    uncertainty: [],
  },
  examination: {
    status: options.examinationStatus ?? "complete",
    semantic_resource_limits: options.resourceLimits ?? [],
    electron_call_paths_limited: options.electronCallPathsLimited ?? false,
  },
  applicability: { electron: options.electronApplicability ?? "unknown" },
});

const electronFindings = (
  options: {
    appPathChanges?: readonly ElectronAppPathChangeFinding[];
    callPaths?: readonly ElectronCallPath[];
  } = {},
): ElectronStaticFindings => ({
  ...(options.appPathChanges !== undefined
    ? { app_path_changes: options.appPathChanges }
    : {}),
  browser_windows: [],
  context_bridge_apis: [],
  ipc: [],
  sender_validations: [],
  utility_processes: [],
  native_addon_bindings: [],
  protocols: [],
  ...(options.callPaths !== undefined ? { call_paths: options.callPaths } : {}),
});

const shard = (
  overrides: Partial<JavaScriptStaticAnalysis> = {},
): JavaScriptStaticAnalysis => ({
  parse_status: "complete",
  analysis_coverage: coverage(),
  parse_error_count: 0,
  visited_ast_nodes: 10,
  references: [],
  endpoints: [],
  storage: [],
  bundler_registrations: [],
  role_paths: [],
  source_map_urls: [],
  vendors: [],
  electron: electronFindings(),
  limitations: [],
  ...overrides,
});

const bundlerModule = (moduleKey: string): JavaScriptBundlerModule => ({
  module_key: moduleKey,
  factory_require_name: null,
  source_sha256: "a".repeat(64),
  exports: [],
  location: locationAt(1),
  structural_fingerprint_sha256: "b".repeat(64),
  structural_fingerprint_algorithm: JAVASCRIPT_AST_FINGERPRINT_ALGORITHM,
});

const metroRegistration = (
  overrides: Partial<JavaScriptBundlerRegistration> = {},
): JavaScriptBundlerRegistration => ({
  bundler: "metro",
  runtime: "metro",
  chunk_keys: ["metro@0"],
  unknown_chunk_keys: 0,
  runtime_require_name: "__r",
  runtime_module_cache_status: "not-observed",
  entry_module_keys: [],
  unknown_entry_module_keys: 0,
  async_chunk_keys: [],
  unknown_async_chunk_keys: 0,
  modules: [],
  location: locationAt(1),
  ...overrides,
});

const otherRegistration = (
  bundler: "webpack" | "esbuild",
  overrides: Partial<JavaScriptBundlerRegistration> = {},
): JavaScriptBundlerRegistration => ({
  bundler,
  runtime: bundler,
  chunk_keys: [`${bundler}@0`],
  unknown_chunk_keys: 0,
  runtime_require_name: null,
  runtime_module_cache_status: "observed",
  entry_module_keys: [],
  unknown_entry_module_keys: 0,
  async_chunk_keys: [],
  unknown_async_chunk_keys: 0,
  modules: [],
  location: locationAt(1),
  ...overrides,
});

const degradedModule = (
  moduleKey: string,
  defineOffset: number,
  locationLine: number,
): JavaScriptDegradedShard => ({
  moduleKey,
  reason: "budget exceeded",
  definition: {
    dependencyModuleKeys: [],
    sourceBytes: 100,
    location: locationAt(locationLine),
    defineOffset,
  },
});

// --- Coverage rollup -------------------------------------------------------

it("rolls up a limited examination status from any shard", () => {
  const merged = mergeJavaScriptStaticAnalyses([
    shard({ analysis_coverage: coverage({ examinationStatus: "complete" }) }),
    shard({ analysis_coverage: coverage({ examinationStatus: "limited" }) }),
  ]);
  expect(merged.analysis_coverage?.examination.status).toBe("limited");
  const unmerged = mergeJavaScriptStaticAnalyses([
    shard({ analysis_coverage: coverage({ examinationStatus: "complete" }) }),
    shard({ analysis_coverage: coverage({ examinationStatus: "complete" }) }),
  ]);
  expect(unmerged.analysis_coverage?.examination.status).toBe("complete");
});

it("sums unknown findings across shards, counting null as zero", () => {
  const merged = mergeJavaScriptStaticAnalyses([
    shard({ analysis_coverage: coverage({ unknownFindings: 3 }) }),
    shard({ analysis_coverage: coverage({ unknownFindings: null }) }),
    shard({ analysis_coverage: coverage({ unknownFindings: 5 }) }),
  ]);
  expect(merged.analysis_coverage?.semantics.unknown_findings).toBe(8);
});

it("counts each degraded shard as one more unknown finding", () => {
  const merged = mergeJavaScriptStaticAnalyses(
    [
      shard({ analysis_coverage: coverage({ unknownFindings: 3 }) }),
      shard({ analysis_coverage: coverage({ unknownFindings: null }) }),
    ],
    [
      { moduleKey: "1", reason: "budget exceeded" },
      { moduleKey: null, reason: "budget exceeded" },
    ],
  );
  expect(merged.analysis_coverage?.semantics.unknown_findings).toBe(5);
});

it("unions semantic resource limits sorted and deduplicated", () => {
  const merged = mergeJavaScriptStaticAnalyses([
    shard({
      analysis_coverage: coverage({
        resourceLimits: ["member-mutation-work"],
      }),
    }),
    shard({
      analysis_coverage: coverage({
        resourceLimits: ["alias-selections", "member-mutation-work"],
      }),
    }),
  ]);
  expect(
    merged.analysis_coverage?.examination.semantic_resource_limits,
  ).toEqual(["alias-selections", "member-mutation-work"]);
});

it("rolls up Electron call-path limiting from any shard", () => {
  const merged = mergeJavaScriptStaticAnalyses([
    shard({
      analysis_coverage: coverage({ electronCallPathsLimited: true }),
    }),
    shard({
      analysis_coverage: coverage({ electronCallPathsLimited: false }),
    }),
  ]);
  expect(
    merged.analysis_coverage?.examination.electron_call_paths_limited,
  ).toBe(true);
  const unmerged = mergeJavaScriptStaticAnalyses([
    shard({
      analysis_coverage: coverage({ electronCallPathsLimited: false }),
    }),
    shard({
      analysis_coverage: coverage({ electronCallPathsLimited: false }),
    }),
  ]);
  expect(
    unmerged.analysis_coverage?.examination.electron_call_paths_limited,
  ).toBe(false);
});

it("reports Electron applicability observed when any shard observed it", () => {
  const mixed = mergeJavaScriptStaticAnalyses([
    shard({
      analysis_coverage: coverage({ electronApplicability: "observed" }),
    }),
    shard({
      analysis_coverage: coverage({ electronApplicability: "unknown" }),
    }),
  ]);
  expect(mixed.analysis_coverage?.applicability.electron).toBe("observed");
  const allObserved = mergeJavaScriptStaticAnalyses([
    shard({
      analysis_coverage: coverage({ electronApplicability: "observed" }),
    }),
    shard({
      analysis_coverage: coverage({ electronApplicability: "observed" }),
    }),
  ]);
  expect(allObserved.analysis_coverage?.applicability.electron).toBe(
    "observed",
  );
  const noneObserved = mergeJavaScriptStaticAnalyses([
    shard({
      analysis_coverage: coverage({ electronApplicability: "unknown" }),
    }),
    shard({
      analysis_coverage: coverage({ electronApplicability: "unknown" }),
    }),
  ]);
  expect(noneObserved.analysis_coverage?.applicability.electron).toBe(
    "unknown",
  );
});

// --- Metro registration selection and folding ------------------------------

it("folds only Metro registrations and preserves other bundlers", () => {
  const webpack = otherRegistration("webpack", {
    chunk_keys: ["main"],
    location: locationAt(2),
  });
  const merged = mergeJavaScriptStaticAnalyses([
    shard({ bundler_registrations: [webpack] }),
    shard({
      bundler_registrations: [
        metroRegistration({
          chunk_keys: ["metro@0"],
          modules: [bundlerModule("m1")],
        }),
        metroRegistration({
          chunk_keys: ["metro@100"],
          modules: [bundlerModule("m2")],
        }),
      ],
    }),
  ]);
  expect(merged.bundler_registrations).toHaveLength(2);
  const preserved = merged.bundler_registrations.find(
    ({ bundler }) => bundler === "webpack",
  );
  expect(preserved).toEqual(webpack);
  const folded = merged.bundler_registrations.find(
    ({ bundler }) => bundler === "metro",
  );
  expect(folded?.modules.map(({ module_key }) => module_key)).toEqual([
    "m1",
    "m2",
  ]);
});

it("passes a single Metro registration through unfolded", () => {
  const webpack = otherRegistration("webpack", { location: locationAt(2) });
  const single = metroRegistration({
    chunk_keys: ["metro@500", "metro@900"],
    runtime_require_name: "customRequire",
    runtime_module_cache_status: "observed",
    modules: [bundlerModule("z"), bundlerModule("a")],
    location: locationAt(3),
  });
  const merged = mergeJavaScriptStaticAnalyses([
    shard({ bundler_registrations: [webpack, single] }),
  ]);
  expect(merged.bundler_registrations).toEqual([single, webpack]);
});

it("sums unknown key counters across folded Metro registrations", () => {
  const merged = mergeJavaScriptStaticAnalyses([
    shard({
      bundler_registrations: [
        metroRegistration({
          chunk_keys: ["metro@0"],
          unknown_chunk_keys: 2,
          entry_module_keys: ["e1"],
          unknown_entry_module_keys: 4,
          async_chunk_keys: ["a1"],
          unknown_async_chunk_keys: 1,
        }),
        metroRegistration({
          chunk_keys: ["metro@100"],
          unknown_chunk_keys: 3,
          entry_module_keys: ["e2"],
          unknown_entry_module_keys: 1,
          async_chunk_keys: ["a2"],
          unknown_async_chunk_keys: 6,
        }),
      ],
    }),
  ]);
  const folded = merged.bundler_registrations[0]!;
  expect(folded.unknown_chunk_keys).toBe(5);
  expect(folded.unknown_entry_module_keys).toBe(5);
  expect(folded.unknown_async_chunk_keys).toBe(7);
  expect(folded.entry_module_keys).toEqual(["e1", "e2"]);
  expect(folded.async_chunk_keys).toEqual(["a1", "a2"]);
});

it("sorts folded modules by module key across registrations", () => {
  const merged = mergeJavaScriptStaticAnalyses([
    shard({
      bundler_registrations: [
        metroRegistration({
          chunk_keys: ["metro@0"],
          modules: [bundlerModule("b"), bundlerModule("d")],
        }),
        metroRegistration({
          chunk_keys: ["metro@100"],
          modules: [bundlerModule("a"), bundlerModule("c")],
        }),
      ],
    }),
  ]);
  expect(
    merged.bundler_registrations[0]?.modules.map(
      ({ module_key }) => module_key,
    ),
  ).toEqual(["a", "b", "c", "d"]);
});

it("anchors the folded registration on the earliest define start", () => {
  const merged = mergeJavaScriptStaticAnalyses([
    shard({
      bundler_registrations: [
        metroRegistration({
          chunk_keys: ["metro@300"],
          modules: [bundlerModule("a1")],
          location: locationAt(30),
        }),
      ],
    }),
    shard({
      bundler_registrations: [
        metroRegistration({
          chunk_keys: ["metro@100"],
          modules: [bundlerModule("b1")],
          location: locationAt(10),
        }),
      ],
    }),
  ]);
  const folded = merged.bundler_registrations[0]!;
  expect(folded.chunk_keys).toEqual(["metro@100"]);
  expect(folded.location).toEqual(locationAt(10));
});

it("breaks define-start ties toward the earlier registration", () => {
  const merged = mergeJavaScriptStaticAnalyses([
    shard({
      bundler_registrations: [
        metroRegistration({
          chunk_keys: ["metro@100"],
          modules: [bundlerModule("a1")],
          location: locationAt(10),
        }),
        metroRegistration({
          chunk_keys: ["metro@100"],
          modules: [bundlerModule("b1")],
          location: locationAt(20),
        }),
      ],
    }),
  ]);
  expect(merged.bundler_registrations[0]?.location).toEqual(locationAt(10));
});

it("anchors on entry-only registrations when none carry modules", () => {
  const merged = mergeJavaScriptStaticAnalyses([
    shard({
      bundler_registrations: [
        metroRegistration({
          chunk_keys: ["metro@300"],
          location: locationAt(30),
        }),
        metroRegistration({
          chunk_keys: ["metro@100"],
          location: locationAt(10),
        }),
      ],
    }),
  ]);
  const folded = merged.bundler_registrations[0]!;
  expect(folded.chunk_keys).toEqual(["metro@100"]);
  expect(folded.location).toEqual(locationAt(10));
  expect(folded.modules).toEqual([]);
});

it("treats a Metro registration without chunk keys as define start zero", () => {
  const merged = mergeJavaScriptStaticAnalyses([
    shard({
      bundler_registrations: [
        metroRegistration({ chunk_keys: [], location: locationAt(5) }),
        metroRegistration({
          chunk_keys: ["metro@50"],
          location: locationAt(50),
        }),
      ],
    }),
  ]);
  const folded = merged.bundler_registrations[0]!;
  expect(folded.chunk_keys).toEqual(["metro@0"]);
  expect(folded.location).toEqual(locationAt(5));
});

// --- Degraded-module salvage ------------------------------------------------

it("sorts salvaged modules by module key in code-point order", () => {
  const merged = mergeJavaScriptStaticAnalyses(
    [shard()],
    [
      degradedModule("9", 900, 90),
      degradedModule("10", 100, 10),
      degradedModule("5", 500, 50),
    ],
  );
  expect(merged.bundler_registrations).toHaveLength(1);
  const skeleton = merged.bundler_registrations[0]!;
  expect(
    skeleton.degraded_modules?.map(({ module_key }) => module_key),
  ).toEqual(["10", "5", "9"]);
  // The skeleton anchors on the first salvageable shard in degraded order.
  expect(skeleton.chunk_keys).toEqual(["metro@900"]);
  expect(skeleton.location).toEqual(locationAt(90));
});

it("builds the skeleton registration with the folder's own constants", () => {
  const merged = mergeJavaScriptStaticAnalyses(
    [shard()],
    [
      {
        moduleKey: "3",
        reason: "budget exceeded",
        definition: {
          dependencyModuleKeys: ["4"],
          sourceBytes: 512,
          location: locationAt(7),
          defineOffset: 128,
        },
      },
    ],
  );
  expect(merged.bundler_registrations).toEqual([
    {
      bundler: "metro",
      runtime: "metro",
      chunk_keys: ["metro@128"],
      unknown_chunk_keys: 0,
      runtime_require_name: "__r",
      runtime_module_cache_status: "not-observed",
      entry_module_keys: [],
      unknown_entry_module_keys: 0,
      async_chunk_keys: [],
      unknown_async_chunk_keys: 0,
      modules: [],
      degraded_modules: [
        {
          module_key: "3",
          dependency_module_keys: ["4"],
          source_bytes: 512,
          location: locationAt(7),
          reason: "budget exceeded",
        },
      ],
      location: locationAt(7),
    },
  ]);
});

it("attaches salvage to the Metro registration, not the first registration", () => {
  const esbuild = otherRegistration("esbuild", { location: locationAt(3) });
  const existing = {
    module_key: "1",
    dependency_module_keys: null,
    source_bytes: 10,
    location: locationAt(2),
    reason: "earlier degradation",
  };
  const metro = metroRegistration({
    location: locationAt(4),
    degraded_modules: [existing],
  });
  const merged = mergeJavaScriptStaticAnalyses(
    [shard({ bundler_registrations: [esbuild, metro] })],
    [degradedModule("7", 700, 70)],
  );
  const preserved = merged.bundler_registrations.find(
    ({ bundler }) => bundler === "esbuild",
  );
  expect(preserved).toEqual(esbuild);
  const carrier = merged.bundler_registrations.find(
    ({ bundler }) => bundler === "metro",
  );
  expect(carrier?.degraded_modules).toEqual([
    existing,
    {
      module_key: "7",
      dependency_module_keys: [],
      source_bytes: 100,
      location: locationAt(70),
      reason: "budget exceeded",
    },
  ]);
});

it("skips unsalvageable shards when choosing the skeleton anchor", () => {
  const merged = mergeJavaScriptStaticAnalyses(
    [shard()],
    [
      {
        moduleKey: null,
        reason: "prelude degraded",
        definition: {
          dependencyModuleKeys: [],
          sourceBytes: 10,
          location: locationAt(11),
          defineOffset: 111,
        },
      },
      { moduleKey: "4", reason: "definition not retained" },
      degradedModule("8", 888, 88),
    ],
  );
  expect(merged.bundler_registrations).toHaveLength(1);
  const skeleton = merged.bundler_registrations[0]!;
  expect(skeleton.chunk_keys).toEqual(["metro@888"]);
  expect(skeleton.location).toEqual(locationAt(88));
  expect(
    skeleton.degraded_modules?.map(({ module_key }) => module_key),
  ).toEqual(["8"]);
});

it("names a degraded prelude shard in the merged limitations", () => {
  const merged = mergeJavaScriptStaticAnalyses(
    [shard()],
    [{ moduleKey: null, reason: "budget exceeded" }],
  );
  expect(merged.limitations).toContain(
    "Metro module (prelude) was not fully analyzed: budget exceeded",
  );
  expect(merged.analysis_coverage?.examination.status).toBe("limited");
  expect(merged.analysis_coverage?.semantics.unknown_findings).toBe(1);
});

// --- Route facts -------------------------------------------------------------

const routeCandidate = (
  path: string,
): JavaScriptRouteSourceFacts["candidates"][number] => ({
  path,
  mechanism: "router-call",
  confidence: "high",
  derivation: "literal",
  location: locationAt(1),
  segments: [],
});

const routeWorkCapacity = (
  limitBytes: number,
  workBytes: number,
): JavaScriptRouteSourceFacts["capacity"] => ({
  kind: "route-work-or-facts",
  limit_bytes: limitBytes,
  accounted_fact_bytes: 0,
  accounted_work_bytes: workBytes,
});

it("omits routes when no shard recorded route facts", () => {
  const merged = mergeJavaScriptStaticAnalyses([shard(), shard()]);
  expect(merged.routes).toBeUndefined();
  expect("routes" in merged).toBe(false);
});

it("keeps a result-bytes capacity over larger route-work accounting", () => {
  const exhausted: JavaScriptRouteSourceFacts = {
    candidates: [routeCandidate("/b")],
    unresolved: [
      { mechanism: "router-call", location: locationAt(2), reason: "dynamic" },
    ],
    capacity: {
      kind: "result-bytes",
      limit_bytes: 2048,
      preceding_work_capacity: null,
    },
  };
  const merged = mergeJavaScriptStaticAnalyses([
    shard({
      routes: {
        candidates: [routeCandidate("/a")],
        unresolved: [],
        capacity: routeWorkCapacity(4096, 1000),
      },
    }),
    shard({ routes: exhausted }),
  ]);
  expect(merged.routes?.capacity).toEqual(exhausted.capacity);
  expect(merged.routes?.candidates).toEqual([
    routeCandidate("/a"),
    routeCandidate("/b"),
  ]);
  expect(merged.routes?.unresolved).toEqual(exhausted.unresolved);
});

it("keeps the largest route-work capacity across shards", () => {
  const ascending = mergeJavaScriptStaticAnalyses([
    shard({
      routes: {
        candidates: [],
        unresolved: [],
        capacity: routeWorkCapacity(1000, 500),
      },
    }),
    shard({
      routes: {
        candidates: [],
        unresolved: [],
        capacity: routeWorkCapacity(2000, 900),
      },
    }),
  ]);
  expect(ascending.routes?.capacity).toEqual(routeWorkCapacity(2000, 900));
  const descending = mergeJavaScriptStaticAnalyses([
    shard({
      routes: {
        candidates: [],
        unresolved: [],
        capacity: routeWorkCapacity(2000, 900),
      },
    }),
    shard({
      routes: {
        candidates: [],
        unresolved: [],
        capacity: routeWorkCapacity(1000, 500),
      },
    }),
  ]);
  expect(descending.routes?.capacity).toEqual(routeWorkCapacity(2000, 900));
  const tied = mergeJavaScriptStaticAnalyses([
    shard({
      routes: {
        candidates: [],
        unresolved: [],
        capacity: routeWorkCapacity(1111, 700),
      },
    }),
    shard({
      routes: {
        candidates: [],
        unresolved: [],
        capacity: routeWorkCapacity(2222, 700),
      },
    }),
  ]);
  // Equal accounted work keeps the first shard's record.
  expect(tied.routes?.capacity).toEqual(routeWorkCapacity(1111, 700));
});

// --- Electron findings --------------------------------------------------------

it("carries Electron path facts from the shards that recorded them", () => {
  const appPathChange: ElectronAppPathChangeFinding = {
    module_key: "m1",
    location: locationAt(2),
  };
  const callPath: ElectronCallPath = {
    entry_kind: "ipc-handler",
    entry: "open-file",
    channel: "open-file",
    terminal: "dialog.showOpenDialog",
    resolution: "candidate",
    steps: [],
    conditions: [],
  };
  const merged = mergeJavaScriptStaticAnalyses([
    shard({ electron: electronFindings({ appPathChanges: [appPathChange] }) }),
    shard({ electron: electronFindings({ callPaths: [callPath] }) }),
    shard(),
  ]);
  expect(merged.electron.app_path_changes).toEqual([appPathChange]);
  expect(merged.electron.call_paths).toEqual([callPath]);
});

it("omits Electron path facts when no shard recorded them", () => {
  const merged = mergeJavaScriptStaticAnalyses([shard(), shard()]);
  expect("app_path_changes" in merged.electron).toBe(false);
  expect("call_paths" in merged.electron).toBe(false);
});

// --- RPC working facts ---------------------------------------------------------

it("omits RPC working facts when no shard recorded them", () => {
  const merged = mergeJavaScriptStaticAnalyses([shard(), shard()]);
  expect("rpc_candidates" in merged).toBe(false);
  expect("rpc_client_members" in merged).toBe(false);
  expect("rpc_export_provenance" in merged).toBe(false);
});

it("concatenates RPC working facts across shards in shard order", () => {
  const candidateA = {
    value: "alpha",
    member_chain: ["a"],
    requested_module_key: null,
    dependency_index: null,
    module_key: "m1",
    location: locationAt(1),
  };
  const candidateB = { ...candidateA, value: "beta", location: locationAt(2) };
  const member = { member: "ping", module_key: "m1", location: locationAt(1) };
  const provenanceA = {
    member: "pong",
    source_member: "pongImpl",
    source_module_key: "m2",
    module_key: "m1",
    location: locationAt(1),
  };
  const provenanceB = {
    ...provenanceA,
    member: "pong2",
    location: locationAt(2),
  };
  const merged = mergeJavaScriptStaticAnalyses([
    shard({
      rpc_candidates: [candidateA],
      rpc_client_members: [member],
      rpc_export_provenance: [provenanceA],
    }),
    shard({
      rpc_candidates: [candidateB],
      rpc_export_provenance: [provenanceB],
    }),
  ]);
  expect(merged.rpc_candidates).toEqual([candidateA, candidateB]);
  expect(merged.rpc_client_members).toEqual([member]);
  expect(merged.rpc_export_provenance).toEqual([provenanceA, provenanceB]);
});

// --- Merge guard ---------------------------------------------------------------

it("rejects merging zero shards", () => {
  expect(() => mergeJavaScriptStaticAnalyses([])).toThrow(
    "Merging static analyses requires at least one shard",
  );
});
