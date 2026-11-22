import { z } from "zod";

import { jsonValueSchema, type JsonValue } from "../jsonValue.js";

/**
 * Observation model for one supervised dynamic-execution run. Rows are filed
 * under the one-kind-per-observation vocabulary proven by the ablation's
 * EXTEND follow-up (scripts/ablation/claims.mjs): a dlopen path is a module
 * row only, a dlsym name a symbol row only, the stdout/stderr streams are
 * the output only, and string rows come only from output-function argument
 * captures. The raw hook-pack message log is preserved in the Evidence
 * raw_result, so every row here can be re-derived without re-executing.
 */

export const dynamicStringRowSchema = z.strictObject({
  value: z.string(),
  channel: z.enum(["puts", "fputs", "printf_fmt"]),
});
export type DynamicStringRow = z.infer<typeof dynamicStringRowSchema>;

export const dynamicModuleRowSchema = z.strictObject({
  /** The dlopen path exactly as the target passed it. */
  path: z.string(),
  /** Derived `.so` basename (claims.mjs `soBasename`); null when not `.so`-shaped. */
  basename: z.string().nullable(),
  ok: z.boolean(),
});
export type DynamicModuleRow = z.infer<typeof dynamicModuleRowSchema>;

export const dynamicSymbolRowSchema = z.strictObject({
  name: z.string(),
  ok: z.boolean(),
});
export type DynamicSymbolRow = z.infer<typeof dynamicSymbolRowSchema>;

export const dynamicOutputSchema = z.strictObject({
  stdout: z.string(),
  stderr: z.string(),
  exit_code: z.int().nullable(),
});
export type DynamicOutput = z.infer<typeof dynamicOutputSchema>;

export const dynamicSupervisorOutcomeSchema = z.strictObject({
  reason: z.enum(["deadline", "memory", "exited", "crashed", "stopped"]),
  peak_rss_bytes: z.int().min(0).nullable(),
  wall_ms: z.int().min(0),
});
export type DynamicSupervisorOutcome = z.infer<
  typeof dynamicSupervisorOutcomeSchema
>;

/** One process in the subreaper worker's descendant accounting. */
export const dynamicAccountedProcessSchema = z.strictObject({
  pid: z.int().min(0),
  exe: z.string().min(1),
});
export type DynamicAccountedProcess = z.infer<
  typeof dynamicAccountedProcessSchema
>;

/**
 * Descendant accounting kept by the dynamic worker in its subreaper role:
 * every process that reparented to the worker (an escapee's only path) is
 * visible here regardless of the image it exec'd, which is what makes this
 * accounting authoritative for the containment verdict where a scan for
 * the target's own exe image is structurally blind. `observed` is the
 * union of descendants recorded from the moment the session ended
 * (bounded; the count carries the true total), `remaining` is the set
 * present at the most recent accounting refresh — refreshes also run
 * during the session, so a worker ended mid-session still leaves a
 * current remaining set behind. The target process itself is never
 * accounted: it is the session's own process, not a descendant escapee.
 * Null on a worker result means no accounting was ever taken (the worker
 * was ended before its first refresh, or a build without accounting
 * published the snapshot): the containment verdict for such a run is
 * unverified, never clean.
 */
export const dynamicDescendantAccountingSchema = z.strictObject({
  /** True when the shim's marker proves this worker holds the subreaper role. */
  subreaper_armed: z.boolean(),
  observed: z.array(dynamicAccountedProcessSchema),
  observed_count: z.int().min(0),
  remaining: z.array(dynamicAccountedProcessSchema),
  remaining_count: z.int().min(0),
});
export type DynamicDescendantAccounting = z.infer<
  typeof dynamicDescendantAccountingSchema
>;

/**
 * The containment verdict written into Evidence. Sourced from the
 * subreaper descendant accounting (see composeContainmentVerdict): when
 * no armed accounting exists, `verified` is false and `breach` is null —
 * an unmeasured verdict is never written as a clean one.
 */
export const dynamicContainmentSchema = z.strictObject({
  verified: z.boolean(),
  source: z.enum(["subreaper_accounting", "unavailable"]),
  survivors_after: z.array(z.string()),
  breach: z.boolean().nullable(),
  reaped_descendants: z.array(z.string()),
});
export type DynamicContainment = z.infer<typeof dynamicContainmentSchema>;

export const dynamicExecutionBlockSchema = z.strictObject({
  hook_pack_version: z.string().min(1),
  frida_version: z.string().min(1),
  target_pid: z.int().min(0).nullable(),
  resume_observed: z.boolean(),
  pack_ready: z
    .strictObject({
      hooked: z.array(z.string()),
      missing: z.array(z.string()),
    })
    .nullable(),
  supervisor: dynamicSupervisorOutcomeSchema,
  budgets: z.strictObject({
    session_timeout_ms: z.int().min(0),
    deadline_ms: z.int().min(0),
    rss_cap_bytes: z.int().min(0),
  }),
  containment: dynamicContainmentSchema,
});
export type DynamicExecutionBlock = z.infer<typeof dynamicExecutionBlockSchema>;

/** The normalized_result of one execute_dynamically Evidence record. */
export const dynamicNormalizedResultSchema = z.strictObject({
  strings: z.array(dynamicStringRowSchema),
  modules: z.array(dynamicModuleRowSchema),
  symbols: z.array(dynamicSymbolRowSchema),
  output: dynamicOutputSchema,
  execution: dynamicExecutionBlockSchema,
});
export type DynamicNormalizedResult = z.infer<
  typeof dynamicNormalizedResultSchema
>;

/**
 * What the dynamic worker publishes (atomically, temp file + rename) for the
 * application service. Interim publishes carry status `running` with the
 * longest message snapshot seen so far, so a supervisor-ended run still has
 * a published result to file.
 */
export const dynamicWorkerResultSchema = z.strictObject({
  status: z.enum([
    "running",
    "complete",
    "session_timeout",
    "holding",
    "failed",
    "unavailable",
    "version_skew",
  ]),
  failure_reason: z.string().nullable(),
  frida_version: z.string().nullable(),
  hook_pack_version: z.string().min(1),
  script_source_sha256: z.string().nullable(),
  target_pid: z.int().min(0).nullable(),
  resume_observed: z.boolean(),
  /** True when the target detached and its final stream snapshot settled. */
  stream_settled: z.boolean(),
  messages: z.array(jsonValueSchema),
  messages_truncated: z.boolean(),
  /**
   * The worker's subreaper descendant accounting, refreshed from the
   * moment the session ends; null until the first accounting is taken.
   */
  descendant_accounting: dynamicDescendantAccountingSchema.nullable(),
});
export type DynamicWorkerResult = z.infer<typeof dynamicWorkerResultSchema>;

const SO_BASENAME = /^[^/]*\.so(\.\d+)*$/u;

/** The claims.mjs `soBasename` derivation: the `.so` basename, or null. */
export const soBasename = (path: string): string | null => {
  const base = path.split("/").pop() ?? "";
  return SO_BASENAME.test(base) ? base : null;
};

export interface DynamicObservationFiling {
  readonly strings: readonly DynamicStringRow[];
  readonly modules: readonly DynamicModuleRow[];
  readonly symbols: readonly DynamicSymbolRow[];
  readonly output: DynamicOutput;
  readonly packReady: {
    readonly hooked: readonly string[];
    readonly missing: readonly string[];
  } | null;
  readonly packVersion: string | null;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Unwrap one session message to its hook-pack payload, when it is one. */
const payloadOf = (message: JsonValue): Record<string, unknown> | null => {
  if (!isRecord(message) || message.type !== "send") return null;
  return isRecord(message.payload) ? message.payload : null;
};

const stringField = (value: unknown): string | null =>
  typeof value === "string" ? value : null;

const stringList = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];

/**
 * File hook-pack messages into observation rows. Pure: the same message log
 * always files the same rows, which is what makes the claim-check runtime
 * class follow-up mechanical. Fixture attribution lines (`MARK:`) are not
 * content strings (the claims.mjs rule); the raw log preserves them.
 */
export const fileDynamicObservations = (
  messages: readonly JsonValue[],
): DynamicObservationFiling => {
  const strings: DynamicStringRow[] = [];
  const seenStrings = new Set<string>();
  const modules: DynamicModuleRow[] = [];
  const symbols: DynamicSymbolRow[] = [];
  const stdoutChunks: Buffer[] = [];
  const stderrChunks: Buffer[] = [];
  let exitCode: number | null = null;
  let packReady: DynamicObservationFiling["packReady"] = null;
  let packVersion: string | null = null;
  for (const message of messages) {
    const payload = payloadOf(message);
    if (payload === null) continue;
    switch (payload.t) {
      case "pack_ready": {
        packVersion = stringField(payload.version);
        packReady = {
          hooked: stringList(payload.hooked),
          missing: stringList(payload.missing),
        };
        break;
      }
      case "puts":
      case "fputs":
      case "printf_fmt": {
        const text = stringField(payload.text);
        if (text === null || text.startsWith("MARK:")) break;
        const key = `${payload.t}\0${text}`;
        if (seenStrings.has(key)) break;
        seenStrings.add(key);
        strings.push({ value: text, channel: payload.t });
        break;
      }
      case "write": {
        const fd = payload.fd;
        if (fd !== 1 && fd !== 2) break;
        if (!Array.isArray(payload.data)) break;
        const bytes = payload.data.filter(
          (entry): entry is number =>
            typeof entry === "number" &&
            Number.isInteger(entry) &&
            entry >= 0 &&
            entry <= 255,
        );
        if (bytes.length !== payload.data.length) break;
        (fd === 1 ? stdoutChunks : stderrChunks).push(Buffer.from(bytes));
        break;
      }
      case "dlopen": {
        const path = stringField(payload.path);
        if (path === null) break;
        modules.push({
          path,
          basename: soBasename(path),
          ok: payload.ok === true,
        });
        break;
      }
      case "dlsym": {
        const name = stringField(payload.name);
        if (name === null) break;
        symbols.push({ name, ok: payload.ok === true });
        break;
      }
      case "exit": {
        if (typeof payload.code === "number" && Number.isInteger(payload.code))
          exitCode = payload.code;
        break;
      }
      default:
        break;
    }
  }
  return {
    strings,
    modules,
    symbols,
    output: {
      stdout: Buffer.concat(stdoutChunks).toString("utf8"),
      stderr: Buffer.concat(stderrChunks).toString("utf8"),
      exit_code: exitCode,
    },
    packReady,
    packVersion,
  };
};
