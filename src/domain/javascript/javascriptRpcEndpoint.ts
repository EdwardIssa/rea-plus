import type * as t from "@babel/types";

/** One RPC operation or transport URL recovered from client-side syntax. */
export interface JavaScriptRpcEndpoint {
  readonly value: string;
  readonly mechanism: string;
  /** Set when the client identity behind the call was inferred, not proven. */
  readonly interpretation?: "candidate";
}

/** Feed every AST node in pre-order, then drain finish() for Source findings. */
export interface JavaScriptRpcScan {
  inspect(node: t.Node): JavaScriptRpcEndpoint | undefined;
  finish(): Iterable<
    (JavaScriptRpcEndpoint & { readonly node: t.Node }) | void
  >;
}

/**
 * A namespace member read (`ns.member`) whose root loads a module but whose
 * member was not proven within the analyzed unit to hold an RPC client.
 * Cross-unit resolution may still prove it from another unit's facts.
 */
export interface JavaScriptRpcUnresolvedNamespaceRead {
  readonly root: t.Node;
  readonly member: string;
  /** Metro module key the root's loader call requests; null when unreadable. */
  readonly requestedModuleKey: string | null;
  /** Dependency-array index of the request; null for a direct literal key. */
  readonly dependencyIndex: number | null;
}

/**
 * A destructured client read (`const { member } = load(...)`) whose member
 * was not proven within the analyzed unit to hold an RPC client.
 */
export interface JavaScriptRpcUnresolvedDestructuredRead {
  readonly bindingId: string;
  readonly member: string;
  readonly requestedModuleKey: string | null;
  readonly dependencyIndex: number | null;
}

/**
 * A `.rpc(name)` call site recorded because its receiver chain did not
 * resolve within the analyzed unit. Carries no endpoint claim by itself;
 * a cross-unit join may promote it to an endpoint fact.
 */
export interface JavaScriptRpcCandidate {
  readonly node: t.Node;
  readonly value: string;
  /** Member names between the receiver root and the trailing `rpc`. */
  readonly memberChain: readonly string[];
  readonly requestedModuleKey: string | null;
  readonly dependencyIndex: number | null;
}

/** A member name proven within the analyzed unit to hold an RPC client factory result. */
export interface JavaScriptRpcClientMemberFact {
  readonly member: string;
  readonly node: t.Node;
}

/** A member export whose value is read from another module's namespace. */
export interface JavaScriptRpcExportProvenanceFact {
  readonly member: string;
  readonly sourceMember: string;
  readonly sourceModuleKey: string;
  readonly node: t.Node;
}
