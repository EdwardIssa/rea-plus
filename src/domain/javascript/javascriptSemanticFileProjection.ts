import type {
  JavaScriptSemanticEvidenceContext,
  JavaScriptSemanticFingerprint,
  JavaScriptSemanticGraphNode,
  JavaScriptSemanticGraphRelation,
  JavaScriptSemanticGraphUnknown,
  JavaScriptSemanticUnknownOmission,
} from "./javascriptSemanticGraphSchemas.js";

/** File-local facts transported before binding them to the containing application graph. */
export interface JavaScriptSemanticFileProjection {
  readonly roots: readonly string[];
  readonly evidenceContexts: readonly JavaScriptSemanticEvidenceContext[];
  readonly nodes: readonly JavaScriptSemanticGraphNode[];
  readonly relations: readonly JavaScriptSemanticGraphRelation[];
  readonly unknowns: readonly JavaScriptSemanticGraphUnknown[];
  readonly omittedUnknownOccurrences?: readonly JavaScriptSemanticUnknownOmission[];
  readonly fingerprints: readonly JavaScriptSemanticFingerprint[];
  readonly nodesTruncated: boolean;
}

/** Independent retained capacities offered to one source projection. */
export interface JavaScriptSemanticProjectionCapacity {
  readonly nodes: number;
  readonly unknowns: number;
}

/**
 * Merge per-shard projections of one partitioned source. Node, relation,
 * unknown, context and fingerprint identities are canonical digests of
 * their content, so identical facts fold and disjoint facts concatenate;
 * the shared per-file module node appears in every shard and folds to one.
 * Unknown omissions merge by family and reason with summed occurrences.
 */
export const mergeJavaScriptSemanticFileProjections = (
  projections: readonly JavaScriptSemanticFileProjection[],
): JavaScriptSemanticFileProjection => {
  if (projections.length === 0)
    throw new TypeError("Merging file projections requires at least one shard");
  const dedupeBy = <Value>(
    values: readonly Value[],
    key: (value: Value) => string,
  ): Value[] => {
    const seen = new Set<string>();
    const merged: Value[] = [];
    for (const value of values) {
      const id = key(value);
      if (seen.has(id)) continue;
      seen.add(id);
      merged.push(value);
    }
    return merged;
  };
  const omissions = new Map<
    string,
    JavaScriptSemanticUnknownOmission & { occurrences: number }
  >();
  for (const projection of projections)
    for (const omission of projection.omittedUnknownOccurrences ?? []) {
      const key = `${omission.family}\0${omission.reason}`;
      const existing = omissions.get(key);
      if (existing === undefined) omissions.set(key, { ...omission });
      else existing.occurrences += omission.occurrences;
    }
  return {
    roots: dedupeBy(
      projections.flatMap(({ roots }) => roots),
      (root) => root,
    ),
    evidenceContexts: dedupeBy(
      projections.flatMap(({ evidenceContexts }) => evidenceContexts),
      ({ context_id }) => context_id,
    ),
    nodes: dedupeBy(
      projections.flatMap(({ nodes }) => nodes),
      ({ node_id }) => node_id,
    ),
    relations: dedupeBy(
      projections.flatMap(({ relations }) => relations),
      ({ relation_id }) => relation_id,
    ),
    unknowns: dedupeBy(
      projections.flatMap(({ unknowns }) => unknowns),
      ({ unknown_id }) => unknown_id,
    ),
    ...(omissions.size > 0
      ? { omittedUnknownOccurrences: [...omissions.values()] }
      : {}),
    fingerprints: dedupeBy(
      projections.flatMap(({ fingerprints }) => fingerprints),
      ({ fingerprint_id }) => fingerprint_id,
    ),
    nodesTruncated: projections.some(({ nodesTruncated }) => nodesTruncated),
  };
};
