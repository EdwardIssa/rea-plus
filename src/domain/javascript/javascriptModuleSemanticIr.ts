import type { JavaScriptSemanticIr } from "./javascriptSemanticIr.js";

/** Module facts needed after file-local semantic projection has finished. */
export type JavaScriptModuleSemanticIr = Pick<
  JavaScriptSemanticIr,
  | "scopes"
  | "bindings"
  | "callables"
  | "moduleLinks"
  | "coverage"
  | "limitations"
>;

/**
 * Merge per-shard module facts of one partitioned source. Shards share the
 * whole-file program scope identity (scope IDs are source-range derived), so
 * scopes and bindings fold by identity; links and callables are disjoint by
 * construction and concatenate. Coverage degrades conservatively: any failed
 * shard fails the merge, any partial shard makes it partial.
 */
export const mergeJavaScriptModuleSemantics = (
  modules: readonly JavaScriptModuleSemanticIr[],
  extraLimitations: readonly string[] = [],
): JavaScriptModuleSemanticIr => {
  if (modules.length === 0)
    throw new TypeError("Merging module semantics requires at least one shard");
  const scopes = new Map<
    string,
    JavaScriptModuleSemanticIr["scopes"][number]
  >();
  for (const module of modules)
    for (const scope of module.scopes)
      if (!scopes.has(scope.scopeId)) scopes.set(scope.scopeId, scope);
  const bindings = new Map<
    string,
    JavaScriptModuleSemanticIr["bindings"][number]
  >();
  for (const module of modules)
    for (const binding of module.bindings)
      if (!bindings.has(binding.bindingId))
        bindings.set(binding.bindingId, binding);
  const callables = new Map<
    string,
    JavaScriptModuleSemanticIr["callables"][number]
  >();
  for (const module of modules)
    for (const callable of module.callables)
      if (!callables.has(callable.callableId))
        callables.set(callable.callableId, callable);
  const coverages = modules.map(({ coverage }) => coverage);
  const status = coverages.some(({ status }) => status === "failed")
    ? "failed"
    : coverages.some(({ status }) => status === "partial")
      ? "partial"
      : "complete";
  // Per-shard omitted counts are 0 (fully counted) or null (unknown); an
  // unknown count in any shard makes the merged count unknown.
  const omittedCount: 0 | null = coverages.some(
    ({ omittedCount }) => omittedCount === null,
  )
    ? null
    : 0;
  const resourceLimits = [
    ...new Set(coverages.flatMap(({ resourceLimits }) => resourceLimits ?? [])),
  ];
  const widenedReturnedReferences = coverages.flatMap(
    ({ widenedReturnedReferences }) => widenedReturnedReferences ?? [],
  );
  const coverage: JavaScriptModuleSemanticIr["coverage"] =
    status === "failed"
      ? {
          status,
          omittedCount: null,
          resourceLimits,
          widenedReturnedReferences,
        }
      : status === "partial"
        ? { status, omittedCount, resourceLimits, widenedReturnedReferences }
        : {
            status,
            omittedCount: 0,
            resourceLimits,
            widenedReturnedReferences,
          };
  const limitations: string[] = [];
  const seenLimitations = new Set<string>();
  for (const limitation of [
    ...modules.flatMap(({ limitations }) => limitations),
    ...extraLimitations,
  ])
    if (!seenLimitations.has(limitation)) {
      seenLimitations.add(limitation);
      limitations.push(limitation);
    }
  return {
    scopes: [...scopes.values()],
    bindings: [...bindings.values()],
    callables: [...callables.values()],
    moduleLinks: modules.flatMap(({ moduleLinks }) => moduleLinks),
    coverage,
    limitations,
  };
};

/** Retain facts consumed by source-module and export-return composition. */
export const projectJavaScriptModuleSemantics = (
  ir: JavaScriptSemanticIr,
): JavaScriptModuleSemanticIr => {
  const scopes = ir.scopes.filter(({ kind }) => kind === "program");
  const programScopeId = scopes[0]?.scopeId;
  const localNames = new Set(ir.moduleLinks.map(({ localName }) => localName));
  const callableIds = new Set(
    ir.moduleLinks.map(({ callableId }) => callableId),
  );
  return {
    scopes,
    bindings: ir.bindings.filter(
      ({ name, scopeId }) => scopeId === programScopeId && localNames.has(name),
    ),
    callables: ir.callables.filter(({ callableId }) =>
      callableIds.has(callableId),
    ),
    moduleLinks: ir.moduleLinks,
    coverage: ir.coverage,
    limitations: ir.limitations,
  };
};
