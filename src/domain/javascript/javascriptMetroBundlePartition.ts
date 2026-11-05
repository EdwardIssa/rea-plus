import * as t from "@babel/types";
import { argumentValue } from "./javascriptStaticAnalysisHelpers.js";

/**
 * One shard of a partitioned Metro bundle: either the shared prelude (every
 * top-level statement that is not a module definition) or one module
 * definition. Statement nodes are shared with the whole-file parse; a shard
 * is analyzed by viewing the program through only its own statements, so all
 * source offsets, scope identities and locations stay whole-file exact.
 */
export interface JavaScriptBundleShard {
  readonly kind: "prelude" | "module";
  /** Metro module key for module shards; null for the prelude. */
  readonly moduleKey: string | null;
  readonly statements: readonly t.Statement[];
  /** Source bytes covered by this shard's statements. */
  readonly bytes: number;
}

/** A program partitioned into a prelude shard plus one shard per module. */
export interface JavaScriptMetroBundlePartition {
  readonly shards: readonly JavaScriptBundleShard[];
  readonly moduleCount: number;
  /** Share of program bytes covered by module definitions (0..1). */
  readonly moduleByteShare: number;
}

/** Fewer modules than this never justify per-module analysis overhead. */
export const METRO_BUNDLE_MIN_MODULES = 8;
/** Module definitions must dominate the program for the partition to apply. */
export const METRO_BUNDLE_MIN_MODULE_BYTE_SHARE = 0.5;

const isMetroModuleDefinition = (
  statement: t.Statement,
): { readonly moduleKey: string } | null => {
  if (!t.isExpressionStatement(statement)) return null;
  const call = statement.expression;
  if (!t.isCallExpression(call)) return null;
  if (!t.isIdentifier(call.callee) || call.callee.name !== "__d") return null;
  const factory = call.arguments[0];
  if (
    factory === undefined ||
    (!t.isFunctionExpression(factory) && !t.isArrowFunctionExpression(factory))
  )
    return null;
  const moduleKey = argumentValue(call.arguments[1]);
  return moduleKey === undefined ? null : { moduleKey };
};

const statementBytes = (statement: t.Statement): number =>
  Math.max(0, (statement.end ?? 0) - (statement.start ?? 0));

/**
 * Partition a parsed program into Metro module shards when module
 * definitions dominate it. Returns null when the program is not a
 * module-table bundle, so callers fall back to whole-file analysis.
 * The binding-level proof that `__d` is the runtime global happens inside
 * each shard's own static analysis, exactly as in whole-file analysis; a
 * shard whose `__d` is locally bound simply yields no registration.
 */
export const partitionMetroBundle = (
  program: t.Program,
): JavaScriptMetroBundlePartition | null => {
  const prelude: t.Statement[] = [];
  const modules: JavaScriptBundleShard[] = [];
  let moduleBytes = 0;
  let totalBytes = 0;
  for (const statement of program.body) {
    const bytes = statementBytes(statement);
    totalBytes += bytes;
    const definition = isMetroModuleDefinition(statement);
    if (definition === null) {
      prelude.push(statement);
    } else {
      moduleBytes += bytes;
      modules.push({
        kind: "module",
        moduleKey: definition.moduleKey,
        statements: [statement],
        bytes,
      });
    }
  }
  if (modules.length < METRO_BUNDLE_MIN_MODULES || totalBytes === 0)
    return null;
  const moduleByteShare = moduleBytes / totalBytes;
  if (moduleByteShare < METRO_BUNDLE_MIN_MODULE_BYTE_SHARE) return null;
  return {
    shards: [
      {
        kind: "prelude",
        moduleKey: null,
        statements: prelude,
        bytes: totalBytes - moduleBytes,
      },
      ...modules,
    ],
    moduleCount: modules.length,
    moduleByteShare,
  };
};
