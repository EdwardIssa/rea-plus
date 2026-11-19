import { sanitizeEndpointCandidate } from "../browserObservation.js";
import type {
  JavaScriptStaticAnalysis,
  JavaScriptStaticEndpoint,
  JavaScriptStaticRpcCandidate,
} from "./javascriptStaticAnalysisTypes.js";

interface RpcResolutionFacts {
  readonly exportsByModule: ReadonlyMap<string, ReadonlySet<string>>;
  readonly clientMembersByModule: ReadonlyMap<string, ReadonlySet<string>>;
  readonly provenanceByModuleMember: ReadonlyMap<
    string,
    { readonly sourceModuleKey: string; readonly sourceMember: string }
  >;
}

/** Whether the candidate's receiver chain fully resolves in the merged facts. */
const chainResolves = (
  candidate: JavaScriptStaticRpcCandidate,
  facts: RpcResolutionFacts,
): boolean => {
  const member = candidate.member_chain[0];
  const requested = candidate.requested_module_key;
  if (member === undefined || requested === null) return false;
  if (
    facts.exportsByModule.get(requested)?.has(member) === true &&
    facts.clientMembersByModule.get(requested)?.has(member) === true
  )
    return true;
  const provenance = facts.provenanceByModuleMember.get(
    `${requested}\0${member}`,
  );
  return (
    provenance !== undefined &&
    facts.exportsByModule.get(requested)?.has(member) === true &&
    facts.exportsByModule
      .get(provenance.sourceModuleKey)
      ?.has(provenance.sourceMember) === true &&
    facts.clientMembersByModule
      .get(provenance.sourceModuleKey)
      ?.has(provenance.sourceMember) === true
  );
};

/**
 * Resolve `.rpc()` candidates recorded by per-shard analyses against the
 * merged cross-module facts of the same file.
 *
 * A candidate is promoted to the endpoint fact whole-file analysis emits
 * (`rpc:call`, interpretation "candidate") only when the full chain
 * resolves: the candidate's requested module exports the receiver member,
 * and that member is proven in that same module to hold an RPC client
 * factory result. One re-export hop is followed when provenance facts
 * record it: the requested module's export of the member is read from a
 * source module that itself exports the member with a factory proof.
 * Partial chains emit nothing, and a candidate whose endpoint already
 * exists (same value, mechanism and call location) is never duplicated.
 */
export const resolveCrossShardRpcEndpoints = (
  facts: JavaScriptStaticAnalysis,
): readonly JavaScriptStaticEndpoint[] => {
  const candidates = facts.rpc_candidates ?? [];
  if (candidates.length === 0) return [];
  const exportsByModule = new Map<string, ReadonlySet<string>>();
  for (const registration of facts.bundler_registrations)
    for (const module of registration.modules)
      exportsByModule.set(module.module_key, new Set(module.exports));
  const clientMembersByModule = new Map<string, Set<string>>();
  for (const fact of facts.rpc_client_members ?? []) {
    if (fact.module_key === null) continue;
    let members = clientMembersByModule.get(fact.module_key);
    if (members === undefined) {
      members = new Set();
      clientMembersByModule.set(fact.module_key, members);
    }
    members.add(fact.member);
  }
  const provenanceByModuleMember = new Map<
    string,
    { readonly sourceModuleKey: string; readonly sourceMember: string }
  >();
  for (const fact of facts.rpc_export_provenance ?? []) {
    if (fact.module_key === null) continue;
    provenanceByModuleMember.set(`${fact.module_key}\0${fact.member}`, {
      sourceModuleKey: fact.source_module_key,
      sourceMember: fact.source_member,
    });
  }
  const locationKey = (location: JavaScriptStaticEndpoint["location"]) =>
    `${String(location.start.line)}:${String(location.start.column)}-${String(location.end.line)}:${String(location.end.column)}`;
  const existing = new Set(
    facts.endpoints
      .filter(({ mechanism }) => mechanism === "rpc:call")
      .map(({ value, location }) => `${value}\0${locationKey(location)}`),
  );
  const resolutionFacts: RpcResolutionFacts = {
    exportsByModule,
    clientMembersByModule,
    provenanceByModuleMember,
  };
  const resolved: JavaScriptStaticEndpoint[] = [];
  for (const candidate of candidates) {
    if (!chainResolves(candidate, resolutionFacts)) continue;
    const value = sanitizeEndpointCandidate(candidate.value);
    const key = `${value}\0${locationKey(candidate.location)}`;
    if (existing.has(key)) continue;
    existing.add(key);
    resolved.push({
      kind: "network",
      value,
      mechanism: "rpc:call",
      interpretation: "candidate",
      module_key: candidate.module_key,
      ...(candidate.module_runtime === undefined
        ? {}
        : { module_runtime: candidate.module_runtime }),
      location: candidate.location,
    });
  }
  return resolved;
};
