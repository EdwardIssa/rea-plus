import { expect, it } from "vitest";
import { resolveCrossShardRpcEndpoints } from "./javascriptCrossShardRpcResolution.js";
import type {
  JavaScriptStaticAnalysis,
  JavaScriptStaticEndpoint,
  JavaScriptStaticRpcCandidate,
} from "./javascriptStaticAnalysisTypes.js";

const at = (line: number, column: number) => ({
  start: { line, column },
  end: { line, column: column + 4 },
});

const candidate = (
  overrides: Partial<JavaScriptStaticRpcCandidate> = {},
): JavaScriptStaticRpcCandidate => ({
  value: "cast_guest_vote",
  member_chain: ["supabase"],
  requested_module_key: "100",
  dependency_index: 0,
  module_key: "101",
  location: at(10, 2),
  ...overrides,
});

const facts = (
  overrides: Partial<JavaScriptStaticAnalysis> = {},
): JavaScriptStaticAnalysis => ({
  parse_status: "complete",
  parse_error_count: 0,
  visited_ast_nodes: 0,
  references: [],
  endpoints: [],
  storage: [],
  bundler_registrations: [
    {
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
      modules: [
        {
          module_key: "100",
          factory_require_name: "_r",
          source_sha256: "a".repeat(64),
          exports: ["supabase"],
          location: at(1, 0),
          structural_fingerprint_sha256: "b".repeat(64),
          structural_fingerprint_algorithm: "babel-ast-v3",
        },
      ],
      location: at(1, 0),
    },
  ],
  role_paths: [],
  source_map_urls: [],
  vendors: [],
  electron: {
    browser_windows: [],
    context_bridge_apis: [],
    ipc: [],
    sender_validations: [],
    utility_processes: [],
    native_addon_bindings: [],
    protocols: [],
  },
  limitations: [],
  ...overrides,
});

const clientMember = (member = "supabase", moduleKey: string | null = "100") => ({
  member,
  module_key: moduleKey,
  location: at(2, 2),
});

it("promotes a candidate whose full chain resolves", () => {
  const resolved = resolveCrossShardRpcEndpoints(
    facts({
      rpc_candidates: [candidate()],
      rpc_client_members: [clientMember()],
    }),
  );
  expect(resolved).toEqual([
    {
      kind: "network",
      value: "cast_guest_vote",
      mechanism: "rpc:call",
      interpretation: "candidate",
      module_key: "101",
      location: at(10, 2),
    },
  ]);
});

it("emits nothing when the requested module does not export the member", () => {
  const resolved = resolveCrossShardRpcEndpoints(
    facts({
      rpc_candidates: [candidate()],
      rpc_client_members: [clientMember()],
      bundler_registrations: [
        {
          ...facts().bundler_registrations[0]!,
          modules: [
            {
              ...facts().bundler_registrations[0]!.modules[0]!,
              exports: ["other"],
            },
          ],
        },
      ],
    }),
  );
  expect(resolved).toEqual([]);
});

it("emits nothing when the member is not a proven client in that module", () => {
  // The module exports the member, but no factory proof exists there: the
  // receiver is a non-client value with an `.rpc` member.
  const resolved = resolveCrossShardRpcEndpoints(
    facts({
      rpc_candidates: [candidate()],
      rpc_client_members: [clientMember("other", "100")],
    }),
  );
  expect(resolved).toEqual([]);
});

it("emits nothing when a factory proof exists only in another module", () => {
  const resolved = resolveCrossShardRpcEndpoints(
    facts({
      rpc_candidates: [candidate()],
      rpc_client_members: [clientMember("supabase", "999")],
    }),
  );
  expect(resolved).toEqual([]);
});

it("emits nothing when the requested module is unknown or unreadable", () => {
  expect(
    resolveCrossShardRpcEndpoints(
      facts({
        rpc_candidates: [candidate({ requested_module_key: null })],
        rpc_client_members: [clientMember()],
      }),
    ),
  ).toEqual([]);
  expect(
    resolveCrossShardRpcEndpoints(
      facts({
        rpc_candidates: [candidate({ requested_module_key: "404" })],
        rpc_client_members: [clientMember()],
      }),
    ),
  ).toEqual([]);
});

it("emits nothing for a candidate with an empty member chain", () => {
  const resolved = resolveCrossShardRpcEndpoints(
    facts({
      rpc_candidates: [candidate({ member_chain: [] })],
      rpc_client_members: [clientMember()],
    }),
  );
  expect(resolved).toEqual([]);
});

it("never duplicates an endpoint that already exists", () => {
  const existing: JavaScriptStaticEndpoint = {
    kind: "network",
    value: "cast_guest_vote",
    mechanism: "rpc:call",
    interpretation: "candidate",
    module_key: "101",
    location: at(10, 2),
  };
  const resolved = resolveCrossShardRpcEndpoints(
    facts({
      endpoints: [existing],
      rpc_candidates: [candidate(), candidate()],
      rpc_client_members: [clientMember()],
    }),
  );
  expect(resolved).toEqual([]);
});

it("resolves one client consumed by many modules, per call site", () => {
  const resolved = resolveCrossShardRpcEndpoints(
    facts({
      rpc_candidates: [
        candidate(),
        candidate({
          value: "issue_guest_token",
          module_key: "102",
          location: at(20, 4),
        }),
      ],
      rpc_client_members: [clientMember()],
    }),
  );
  expect(resolved.map(({ value }) => value)).toEqual([
    "cast_guest_vote",
    "issue_guest_token",
  ]);
});

it("follows one recorded re-export hop", () => {
  const base = facts();
  const resolved = resolveCrossShardRpcEndpoints(
    facts({
      rpc_candidates: [candidate({ requested_module_key: "200" })],
      rpc_client_members: [clientMember("supabase", "100")],
      rpc_export_provenance: [
        {
          member: "supabase",
          source_member: "supabase",
          source_module_key: "100",
          module_key: "200",
          location: at(5, 2),
        },
      ],
      bundler_registrations: [
        {
          ...base.bundler_registrations[0]!,
          modules: [
            ...base.bundler_registrations[0]!.modules,
            {
              ...base.bundler_registrations[0]!.modules[0]!,
              module_key: "200",
              exports: ["supabase"],
            },
          ],
        },
      ],
    }),
  );
  expect(resolved.map(({ value }) => value)).toEqual(["cast_guest_vote"]);
});

it("emits nothing when the re-export hop has no factory proof at its source", () => {
  const base = facts();
  const resolved = resolveCrossShardRpcEndpoints(
    facts({
      rpc_candidates: [candidate({ requested_module_key: "200" })],
      rpc_client_members: [],
      rpc_export_provenance: [
        {
          member: "supabase",
          source_member: "supabase",
          source_module_key: "100",
          module_key: "200",
          location: at(5, 2),
        },
      ],
      bundler_registrations: [
        {
          ...base.bundler_registrations[0]!,
          modules: [
            ...base.bundler_registrations[0]!.modules,
            {
              ...base.bundler_registrations[0]!.modules[0]!,
              module_key: "200",
              exports: ["supabase"],
            },
          ],
        },
      ],
    }),
  );
  expect(resolved).toEqual([]);
});

it("keeps a prelude candidate's null module attribution", () => {
  const resolved = resolveCrossShardRpcEndpoints(
    facts({
      rpc_candidates: [candidate({ module_key: null })],
      rpc_client_members: [clientMember()],
    }),
  );
  expect(resolved).toHaveLength(1);
  expect(resolved[0]?.module_key).toBeNull();
});

it("is a no-op when no candidates were recorded", () => {
  expect(resolveCrossShardRpcEndpoints(facts())).toEqual([]);
  expect(
    resolveCrossShardRpcEndpoints(
      facts({ rpc_client_members: [clientMember()] }),
    ),
  ).toEqual([]);
});
