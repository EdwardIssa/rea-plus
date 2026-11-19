import { uniqueSortedBy } from "../canonicalOrdering.js";
import { compareUnicodeCodePoints } from "../unicodeCodePointOrder.js";
import { registrationKey } from "./javascriptStaticAnalysisHelpers.js";
import type {
  JavaScriptBundlerRegistration,
  JavaScriptStaticAnalysis,
} from "./javascriptStaticAnalysisTypes.js";
import {
  javaScriptStaticParseStatus,
  type JavaScriptStaticCoverage,
} from "./javascriptStaticCoverage.js";
import type { JavaScriptRouteSourceFacts } from "./javascriptRouteFacts.js";

/** A shard that produced no analysis because its budget was exhausted. */
export interface JavaScriptDegradedShard {
  /** Metro module key, or null for the prelude shard. */
  readonly moduleKey: string | null;
  /** Why the shard degraded, in analyst-facing words. */
  readonly reason: string;
}

const orderedUnion = (groups: readonly (readonly string[])[]): string[] => {
  const seen = new Set<string>();
  const merged: string[] = [];
  for (const group of groups)
    for (const value of group)
      if (!seen.has(value)) {
        seen.add(value);
        merged.push(value);
      }
  return merged;
};

const mergeCoverage = (
  coverages: readonly JavaScriptStaticCoverage[],
  degraded: readonly JavaScriptDegradedShard[],
): JavaScriptStaticCoverage => {
  const first = coverages[0]!;
  const limited =
    degraded.length > 0 ||
    coverages.some(({ examination }) => examination.status === "limited");
  return {
    // Syntax coverage comes from the one shared parse, identical per shard.
    syntax: first.syntax,
    semantics: {
      // Each degraded shard's unexamined facts count as unknown, never absent.
      unknown_findings:
        coverages.reduce(
          (total, { semantics }) => total + (semantics.unknown_findings ?? 0),
          0,
        ) + degraded.length,
      uncertainty: orderedUnion(
        coverages.map(({ semantics }) => semantics.uncertainty),
      ) as JavaScriptStaticCoverage["semantics"]["uncertainty"],
    },
    examination: {
      status: limited ? "limited" : first.examination.status,
      semantic_resource_limits: [
        ...new Set(
          coverages.flatMap(
            ({ examination }) => examination.semantic_resource_limits,
          ),
        ),
      ].sort(),
      electron_call_paths_limited: coverages.some(
        ({ examination }) => examination.electron_call_paths_limited,
      ),
    },
    applicability: {
      electron: coverages.some(
        ({ applicability }) => applicability.electron === "observed",
      )
        ? "observed"
        : "unknown",
    },
  };
};

const mergeMetroRegistrations = (
  registrations: readonly JavaScriptBundlerRegistration[],
): JavaScriptBundlerRegistration[] => {
  const metro = registrations.filter(({ bundler }) => bundler === "metro");
  const others = registrations.filter(({ bundler }) => bundler !== "metro");
  if (metro.length <= 1) return [...others, ...metro];
  const firstDefineStart = (registration: JavaScriptBundlerRegistration) =>
    Number.parseInt(
      registration.chunk_keys[0]?.slice("metro@".length) ?? "0",
      10,
    );
  // Entry-only registrations (from a prelude shard) carry no define offset;
  // anchor the folded chunk identity on the earliest module-bearing one.
  const anchored = metro.filter(({ modules }) => modules.length > 0);
  const earliest = (anchored.length > 0 ? anchored : metro).reduce((a, b) =>
    firstDefineStart(a) <= firstDefineStart(b) ? a : b,
  );
  const merged: JavaScriptBundlerRegistration = {
    bundler: "metro",
    runtime: "metro",
    chunk_keys: [`metro@${String(firstDefineStart(earliest))}`],
    unknown_chunk_keys: metro.reduce(
      (total, { unknown_chunk_keys }) => total + unknown_chunk_keys,
      0,
    ),
    runtime_require_name: "__r",
    runtime_module_cache_status: "not-observed",
    entry_module_keys: orderedUnion(
      metro.map(({ entry_module_keys }) => entry_module_keys),
    ),
    unknown_entry_module_keys: metro.reduce(
      (total, { unknown_entry_module_keys }) =>
        total + unknown_entry_module_keys,
      0,
    ),
    async_chunk_keys: orderedUnion(
      metro.map(({ async_chunk_keys }) => async_chunk_keys),
    ),
    unknown_async_chunk_keys: metro.reduce(
      (total, { unknown_async_chunk_keys }) => total + unknown_async_chunk_keys,
      0,
    ),
    modules: metro
      .flatMap(({ modules }) => modules)
      .sort((left, right) =>
        compareUnicodeCodePoints(left.module_key, right.module_key),
      ),
    location: earliest.location,
  };
  return [...others, merged];
};

const mergeRoutes = (
  groups: readonly (JavaScriptRouteSourceFacts | undefined)[],
): JavaScriptRouteSourceFacts | undefined => {
  const present = groups.filter(
    (facts): facts is JavaScriptRouteSourceFacts => facts !== undefined,
  );
  if (present.length === 0) return undefined;
  // A shard that exhausted its result-bytes budget reports the terminal
  // capacity form; keep the first such record rather than inventing a sum.
  // Otherwise keep the largest work accounting, which never overstates the
  // completeness a single whole-file scan would have reported.
  const exhausted = present.find(
    ({ capacity }) => capacity?.kind === "result-bytes",
  );
  const capacity =
    exhausted?.capacity ??
    present.reduce<JavaScriptRouteSourceFacts["capacity"]>(
      (largest, { capacity: candidate }) => {
        if (candidate === null) return largest;
        if (largest === null || largest.kind !== "route-work-or-facts")
          return candidate;
        return candidate.kind === "route-work-or-facts" &&
          candidate.accounted_work_bytes > largest.accounted_work_bytes
          ? candidate
          : largest;
      },
      null,
    );
  return {
    candidates: present.flatMap(({ candidates }) => candidates),
    unresolved: present.flatMap(({ unresolved }) => unresolved),
    capacity,
  };
};

/**
 * Merge per-shard static analyses of one parsed source into the equivalent
 * whole-file result. Shards partition the program's statements; findings
 * concatenate in shard order (the prelude shard first, then modules in
 * source order), and registrations fold back into the single per-file
 * records whole-file analysis emits.
 * Degraded shards contribute no findings; they are named in the merged
 * limitations and force the examination status to limited, so their absence
 * is explicit rather than silent.
 */
export const mergeJavaScriptStaticAnalyses = (
  analyses: readonly JavaScriptStaticAnalysis[],
  degraded: readonly JavaScriptDegradedShard[] = [],
): JavaScriptStaticAnalysis => {
  if (analyses.length === 0)
    throw new TypeError("Merging static analyses requires at least one shard");
  const first = analyses[0]!;
  const coverage = mergeCoverage(
    analyses.map(({ analysis_coverage }) => analysis_coverage!),
    degraded,
  );
  const routes = mergeRoutes(analyses.map(({ routes }) => routes));
  const rpcCandidates = analyses.flatMap(
    ({ rpc_candidates }) => rpc_candidates ?? [],
  );
  const rpcClientMembers = analyses.flatMap(
    ({ rpc_client_members }) => rpc_client_members ?? [],
  );
  const rpcExportProvenance = analyses.flatMap(
    ({ rpc_export_provenance }) => rpc_export_provenance ?? [],
  );
  const registrations = uniqueSortedBy(
    mergeMetroRegistrations(
      analyses.flatMap(({ bundler_registrations }) => bundler_registrations),
    ),
    registrationKey,
  );
  const sourceMapUrls = orderedUnion(
    analyses.map(({ source_map_urls }) =>
      source_map_urls.map((entry) => JSON.stringify(entry)),
    ),
  ).map(
    (entry) =>
      JSON.parse(entry) as JavaScriptStaticAnalysis["source_map_urls"][number],
  );
  const electron = {
    ...(analyses.some(({ electron }) => electron.app_path_changes !== undefined)
      ? {
          app_path_changes: analyses.flatMap(
            ({ electron }) => electron.app_path_changes ?? [],
          ),
        }
      : {}),
    ...(analyses.some(({ electron }) => electron.call_paths !== undefined)
      ? {
          call_paths: analyses.flatMap(
            ({ electron }) => electron.call_paths ?? [],
          ),
        }
      : {}),
    browser_windows: analyses.flatMap(
      ({ electron }) => electron.browser_windows,
    ),
    context_bridge_apis: analyses.flatMap(
      ({ electron }) => electron.context_bridge_apis,
    ),
    ipc: analyses.flatMap(({ electron }) => electron.ipc),
    sender_validations: analyses.flatMap(
      ({ electron }) => electron.sender_validations,
    ),
    utility_processes: analyses.flatMap(
      ({ electron }) => electron.utility_processes,
    ),
    native_addon_bindings: analyses.flatMap(
      ({ electron }) => electron.native_addon_bindings,
    ),
    protocols: analyses.flatMap(({ electron }) => electron.protocols),
  };
  return {
    parse_status: javaScriptStaticParseStatus(coverage),
    analysis_coverage: coverage,
    parse_error_count: first.parse_error_count,
    // Each shard traversal re-counts the shared File and Program roots;
    // subtract the duplicates so the metric matches a whole-file pass.
    visited_ast_nodes: Math.max(
      0,
      analyses.reduce(
        (total, { visited_ast_nodes }) => total + visited_ast_nodes,
        0,
      ) -
        2 * (analyses.length - 1),
    ),
    references: analyses.flatMap(({ references }) => references),
    endpoints: analyses.flatMap(({ endpoints }) => endpoints),
    ...(rpcCandidates.length > 0 ? { rpc_candidates: rpcCandidates } : {}),
    ...(rpcClientMembers.length > 0
      ? { rpc_client_members: rpcClientMembers }
      : {}),
    ...(rpcExportProvenance.length > 0
      ? { rpc_export_provenance: rpcExportProvenance }
      : {}),
    ...(routes !== undefined ? { routes } : {}),
    storage: analyses.flatMap(({ storage }) => storage),
    bundler_registrations: registrations,
    role_paths: analyses.flatMap(({ role_paths }) => role_paths),
    source_map_urls: sourceMapUrls,
    vendors: first.vendors,
    electron,
    limitations: [
      ...orderedUnion(analyses.map(({ limitations }) => limitations)),
      ...degraded.map(
        ({ moduleKey, reason }) =>
          `Metro module ${moduleKey ?? "(prelude)"} was not fully analyzed: ${reason}`,
      ),
    ],
  };
};
