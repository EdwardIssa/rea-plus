import { spawn } from "node:child_process";
import {
  closeSync,
  existsSync,
  openSync,
  readFileSync,
  readlinkSync,
  readdirSync,
} from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisProtocolError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { artifactTargetSelectedPath } from "../../domain/binaryTargetTypes.js";
import { createEvidence } from "../../domain/evidence.js";
import {
  dynamicWorkerResultSchema,
  fileDynamicObservations,
  type DynamicWorkerResult,
} from "../../domain/dynamicExecution/dynamicObservation.js";
import {
  DYNAMIC_EXECUTION_MAX_DEADLINE_MS,
  DYNAMIC_EXECUTION_MAX_SESSION_TIMEOUT_MS,
  DYNAMIC_EXECUTION_MIN_RSS_CAP_BYTES,
  DYNAMIC_EXECUTION_MIN_SESSION_TIMEOUT_MS,
  dynamicExecutionRunOutcomeSchema,
  resolveDynamicExecutionBudgets,
  type DynamicExecutionRunOutcome,
} from "../../domain/dynamicExecution/dynamicExecutionReport.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  fridaProviderState,
  type FridaProviderState,
} from "../../frida/FridaProviderState.js";
import { SUBREAPER_SHIM_SOURCE } from "../../frida/subreaperShim.js";
import type { ProviderProcessHandle } from "../../process/ProviderProcess.js";
import { WorkerSupervisor } from "../../process/WorkerSupervisor.js";
import { parseBinaryTarget } from "../BinaryTargetResolver.js";

const OPERATION = "execute_dynamically";

/**
 * Fixed process-count rlimit for the namespace chain, from the ablation
 * harness's proven containment configuration: a fork bomb exhausts its
 * process budget instead of the host's pid space, so the supervisor
 * deadline (not host exhaustion) ends the run.
 */
const CHAIN_RLIMIT_NPROC = 512;

export interface DynamicExecutionRequest {
  /** Caller-designated local target path; preserved verbatim in Evidence parameters. */
  readonly targetPath: string;
  readonly argv?: readonly string[];
  readonly envSet?: Readonly<Record<string, string>>;
  readonly sessionTimeoutMs?: number;
  readonly deadlineMs?: number;
  readonly rssCapBytes?: number;
  readonly evidencePath: string;
}

const inputError = (
  code: string,
  userMessage: string,
  path: readonly (string | number)[],
): AnalysisInputError =>
  new AnalysisInputError(OPERATION, { userMessage }, [
    {
      path: [...path],
      reason: "invalid_value",
      message: `${code}: ${userMessage}`,
    },
  ]);

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

const readParentMap = (): Map<number, number> => {
  const parents = new Map<number, number>();
  for (const entry of readdirSync("/proc")) {
    if (!/^\d+$/u.test(entry)) continue;
    try {
      const stat = readFileSync(`/proc/${entry}/stat`, "utf8");
      const tail = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      parents.set(Number(entry), Number(tail[1]));
    } catch {
      // Exited mid-scan.
    }
  }
  return parents;
};

const descendantsOf = (
  rootPid: number,
  parents: Map<number, number> = readParentMap(),
): number[] => {
  const found: number[] = [];
  for (const pid of parents.keys()) {
    if (pid === rootPid) continue;
    let cursor: number | undefined = pid;
    const seen = new Set<number>();
    while (cursor !== undefined && cursor !== 0 && !seen.has(cursor)) {
      if (cursor === rootPid) {
        found.push(pid);
        break;
      }
      seen.add(cursor);
      cursor = parents.get(cursor);
    }
  }
  return found;
};

const processesWithExe = (exePaths: readonly string[]): number[] => {
  const found: number[] = [];
  for (const entry of readdirSync("/proc")) {
    if (!/^\d+$/u.test(entry)) continue;
    try {
      if (exePaths.includes(readlinkSync(`/proc/${entry}/exe`)))
        found.push(Number(entry));
    } catch {
      // Zombie, kernel thread, or not ours to inspect.
    }
  }
  return found;
};

const exeOf = (pid: number): string => {
  try {
    return readlinkSync(`/proc/${pid}/exe`);
  } catch {
    return `pid:${pid}`;
  }
};

const killPid = (pid: number): void => {
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // Already gone.
  }
};

/**
 * Termination cascade used as the supervisor's terminateGroup (ported from
 * the ablation harness): group kill, then repeated parentage sweeps
 * (orphans reparent to the subreaper worker, so the sweep keeps finding
 * them), then a target-exe sweep.
 */
const makeTerminateGroup =
  (rootPid: number, targetExePaths: readonly string[]) =>
  async (): Promise<void> => {
    try {
      process.kill(-rootPid, "SIGKILL");
    } catch {
      // Group already gone.
    }
    killPid(rootPid);
    for (let round = 0; round < 4; round++) {
      for (const pid of descendantsOf(rootPid)) killPid(pid);
      for (const pid of processesWithExe(targetExePaths)) killPid(pid);
      await sleep(200);
    }
  };

const shellQuote = (value: string): string =>
  `'${value.replaceAll("'", "'\\''")}'`;

export interface DynamicExecutionService {
  run(
    request: DynamicExecutionRequest,
    signal?: AbortSignal,
  ): Promise<Result<DynamicExecutionRunOutcome, AnalysisError>>;
  providerState(): FridaProviderState;
}

/**
 * One dynamic-execution workflow instance. The concurrency-1 guard and the
 * last known binding availability live here, so one instance serves one
 * server/CLI process (the spec's concurrency scope).
 */
export const createDynamicExecutionService = (): DynamicExecutionService => {
  let inFlight = false;
  let bindingAvailable = true;

  const providerState = (): FridaProviderState =>
    fridaProviderState({ bindingAvailable, runInFlight: inFlight });

  const run = async (
    request: DynamicExecutionRequest,
    signal?: AbortSignal,
  ): Promise<Result<DynamicExecutionRunOutcome, AnalysisError>> => {
    const budgets = resolveDynamicExecutionBudgets({
      ...(request.sessionTimeoutMs === undefined
        ? {}
        : { sessionTimeoutMs: request.sessionTimeoutMs }),
      ...(request.deadlineMs === undefined
        ? {}
        : { deadlineMs: request.deadlineMs }),
      ...(request.rssCapBytes === undefined
        ? {}
        : { rssCapBytes: request.rssCapBytes }),
    });
    if (
      budgets.sessionTimeoutMs < DYNAMIC_EXECUTION_MIN_SESSION_TIMEOUT_MS ||
      budgets.sessionTimeoutMs > DYNAMIC_EXECUTION_MAX_SESSION_TIMEOUT_MS
    )
      return err(
        inputError(
          "session_timeout_out_of_range",
          `session_timeout_ms must be between ${DYNAMIC_EXECUTION_MIN_SESSION_TIMEOUT_MS} and ${DYNAMIC_EXECUTION_MAX_SESSION_TIMEOUT_MS}; got ${budgets.sessionTimeoutMs}.`,
          ["session_timeout_ms"],
        ),
      );
    if (budgets.deadlineMs <= budgets.sessionTimeoutMs)
      return err(
        inputError(
          "deadline_not_after_session_timeout",
          `deadline_ms (${budgets.deadlineMs}) must exceed session_timeout_ms (${budgets.sessionTimeoutMs}).`,
          ["deadline_ms"],
        ),
      );
    if (budgets.deadlineMs > DYNAMIC_EXECUTION_MAX_DEADLINE_MS)
      return err(
        inputError(
          "deadline_out_of_range",
          `deadline_ms must not exceed ${DYNAMIC_EXECUTION_MAX_DEADLINE_MS}; got ${budgets.deadlineMs}.`,
          ["deadline_ms"],
        ),
      );
    if (budgets.rssCapBytes < DYNAMIC_EXECUTION_MIN_RSS_CAP_BYTES)
      return err(
        inputError(
          "rss_cap_too_small",
          `rss_cap_bytes must be at least ${DYNAMIC_EXECUTION_MIN_RSS_CAP_BYTES}; got ${budgets.rssCapBytes}.`,
          ["rss_cap_bytes"],
        ),
      );
    if (process.platform !== "linux")
      return err(
        new AnalysisCapabilityUnavailableError(
          "frida",
          OPERATION,
          `dynamic execution requires Linux (user/net/mount namespaces and /proc accounting); this host is ${process.platform}`,
          { retryable: false },
        ),
      );
    if (inFlight)
      return err(
        new AnalysisResourceConstraintError(
          OPERATION,
          "capacity",
          "a dynamic execution run is already in flight; concurrent runs are refused, not queued",
          null,
          { retryable: true },
        ),
      );

    // The flag is claimed before the first await so the busy check above
    // and this claim are atomic with respect to concurrent calls.
    inFlight = true;
    let runDir: string | undefined;
    try {
      const resolvedTarget = await parseBinaryTarget(
        request.targetPath,
        signal === undefined ? {} : { signal },
      );
      if (!resolvedTarget.ok) return err(resolvedTarget.error);
      const target = resolvedTarget.value;
      const program = artifactTargetSelectedPath(target);
      const targetDir = dirname(program);

      const workerPath = fileURLToPath(
        new URL("../../../dist/frida/dynamicWorkerMain.js", import.meta.url),
      );
      if (!existsSync(workerPath))
        return err(
          new AnalysisProtocolError(
            `Dynamic execution worker is not built: ${workerPath} does not exist. Build the product (npm run compile) before running dynamic execution.`,
          ),
        );

      runDir = await mkdtemp(join(tmpdir(), "rea-dynexec-"));
      const scratchDir = join(runDir, "scratch");
      await mkdir(scratchDir, { recursive: true });
      const jobPath = join(runDir, "job.json");
      const resultPath = join(runDir, "result.json");
      const shimPath = join(runDir, "subreaper.py");
      await writeFile(shimPath, SUBREAPER_SHIM_SOURCE);
      await writeFile(
        jobPath,
        JSON.stringify(
          {
            program,
            argv: [...(request.argv ?? [])],
            env_set: { ...request.envSet },
            cwd: targetDir,
            session_timeout_ms: budgets.sessionTimeoutMs,
            result_path: resultPath,
          },
          null,
          1,
        ),
      );
      const prefix = [
        `mount -t tmpfs tmpfs ${shellQuote(scratchDir)}`,
        `mount --bind ${shellQuote(targetDir)} ${shellQuote(targetDir)}`,
        `mount -o remount,ro,bind ${shellQuote(targetDir)}`,
      ].join(" && ");
      const inner =
        `${prefix} && ulimit -u ${CHAIN_RLIMIT_NPROC} && ` +
        `exec python3 ${shellQuote(shimPath)} ${shellQuote(workerPath)} ${shellQuote(jobPath)}`;
      const stdoutFd = openSync(join(runDir, "chain-stdout.log"), "w");
      const stderrFd = openSync(join(runDir, "chain-stderr.log"), "w");
      let outcome: Awaited<ReturnType<WorkerSupervisor["outcome"]>>;
      let survivorsAfter: string[] = [];
      let breach = false;
      try {
        const child = spawn(
          "unshare",
          [
            "--user",
            "--map-root-user",
            "--net",
            "--mount",
            "--propagation",
            "private",
            "bash",
            "-c",
            inner,
          ],
          {
            detached: true,
            stdio: ["ignore", stdoutFd, stderrFd],
            env: {
              PATH: process.env.PATH ?? "",
              HOME: process.env.HOME ?? "",
              TMPDIR: scratchDir,
            },
          },
        );
        const supervisor = new WorkerSupervisor(
          child as unknown as ProviderProcessHandle,
          {
            rssCapBytes: budgets.rssCapBytes,
            deadlineMs: budgets.deadlineMs,
            pollIntervalMs: 200,
            terminateGroup: makeTerminateGroup(child.pid ?? 0, [program]),
          },
        );
        supervisor.start();
        const onAbort = (): void => {
          void supervisor.stop();
        };
        signal?.addEventListener("abort", onAbort, { once: true });
        try {
          outcome = await supervisor.outcome();
        } finally {
          signal?.removeEventListener("abort", onAbort);
        }
        // Settle, then verify: no process running the target binary may
        // survive. A survivor is a containment breach and is reported.
        await sleep(600);
        let survivors = processesWithExe([program]);
        breach = survivors.length > 0;
        if (breach) {
          for (const pid of survivors) killPid(pid);
          await sleep(400);
          survivors = processesWithExe([program]);
          for (const pid of survivors) killPid(pid);
        }
        survivorsAfter = survivors.map(exeOf);
      } finally {
        closeSync(stdoutFd);
        closeSync(stderrFd);
      }

      if (signal?.aborted)
        return err(
          new AnalysisCancelledError(OPERATION, { cause: signal.reason }),
        );

      let workerResult: DynamicWorkerResult | undefined;
      if (existsSync(resultPath)) {
        const parsed = dynamicWorkerResultSchema.safeParse(
          JSON.parse(await readFile(resultPath, "utf8")),
        );
        if (!parsed.success)
          return err(
            new AnalysisProtocolError(
              `Dynamic execution worker published a malformed result for ${request.targetPath}; no Evidence was written.`,
            ),
          );
        workerResult = parsed.data;
      }
      if (workerResult === undefined)
        return err(
          new AnalysisProtocolError(
            `Dynamic execution worker exited without publishing a result for ${request.targetPath} (supervisor outcome: ${outcome.reason}); no Evidence was written.`,
          ),
        );
      if (workerResult.status === "unavailable") {
        bindingAvailable = false;
        return err(
          new AnalysisCapabilityUnavailableError(
            "frida",
            OPERATION,
            workerResult.failure_reason ?? "Frida binding unavailable",
            { retryable: false },
          ),
        );
      }
      if (workerResult.status === "version_skew") {
        return err(
          new AnalysisCapabilityUnavailableError(
            "frida",
            OPERATION,
            workerResult.failure_reason ?? "Frida version skew",
            { retryable: false },
          ),
        );
      }
      if (workerResult.status === "failed")
        return err(
          new AnalysisProtocolError(
            `Dynamic execution failed for ${request.targetPath}: ${workerResult.failure_reason ?? "worker reported failure"}`,
          ),
        );
      bindingAvailable = true;

      const filing = fileDynamicObservations(workerResult.messages);
      const limitations: string[] = [];
      const missing = filing.packReady?.missing ?? [];
      if (missing.length > 0)
        limitations.push(`hooks_unavailable: ${missing.join(", ")}`);
      if (workerResult.messages_truncated)
        limitations.push("messages_truncated");
      if (outcome.reason === "deadline")
        limitations.push("run_terminated: deadline");
      if (outcome.reason === "memory")
        limitations.push("run_terminated: memory");
      if (workerResult.status === "session_timeout")
        limitations.push("run_terminated: session_timeout");
      if (!workerResult.stream_settled) limitations.push("stdout_incomplete");
      if (breach)
        limitations.push(
          `containment_breach: target processes survived the termination cascade: ${survivorsAfter.join(", ")}`,
        );
      const status: DynamicExecutionRunOutcome["status"] =
        workerResult.status === "complete" && outcome.reason === "exited"
          ? "complete"
          : "terminated";
      const normalizedResult = {
        strings: filing.strings.map((row) => ({ ...row })),
        modules: filing.modules.map((row) => ({ ...row })),
        symbols: filing.symbols.map((row) => ({ ...row })),
        output: filing.output,
        execution: {
          hook_pack_version: workerResult.hook_pack_version,
          frida_version: workerResult.frida_version ?? "unknown",
          target_pid: workerResult.target_pid,
          resume_observed: workerResult.resume_observed,
          pack_ready:
            filing.packReady === null
              ? null
              : {
                  hooked: [...filing.packReady.hooked],
                  missing: [...filing.packReady.missing],
                },
          supervisor: {
            reason: outcome.reason,
            peak_rss_bytes: outcome.peakRssBytes ?? null,
            wall_ms: outcome.wallMs,
          },
          budgets: {
            session_timeout_ms: budgets.sessionTimeoutMs,
            deadline_ms: budgets.deadlineMs,
            rss_cap_bytes: budgets.rssCapBytes,
          },
          containment: { survivors_after: survivorsAfter, breach },
        },
      };
      const evidence = createEvidence(
        target,
        {
          id: "frida",
          name: "Frida",
          version: workerResult.frida_version,
        },
        {
          operation: OPERATION,
          parameters: {
            target_path: request.targetPath,
            argv: [...(request.argv ?? [])],
            env_set: { ...request.envSet },
            session_timeout_ms: budgets.sessionTimeoutMs,
            deadline_ms: budgets.deadlineMs,
            rss_cap_bytes: budgets.rssCapBytes,
            evidence_path: request.evidencePath,
          },
          result: normalizedResult,
          rawResult: [...workerResult.messages],
          confidence: "observed",
          authority: "controlled-replay",
          environment: null,
          limitations,
          evidenceLinks: [],
        },
      );
      try {
        await writeFile(
          request.evidencePath,
          `${JSON.stringify(evidence, null, 2)}\n`,
        );
      } catch (cause) {
        return err(
          inputError(
            "evidence_write_failed",
            `Evidence could not be written: ${request.evidencePath} (${cause instanceof Error ? cause.message : String(cause)})`,
            ["evidence_path"],
          ),
        );
      }
      return ok(
        dynamicExecutionRunOutcomeSchema.parse({
          // The outcome is delivered as the run settles, so the projected
          // state is the post-run state, not the in-flight one.
          provider_state: fridaProviderState({
            bindingAvailable,
            runInFlight: false,
          }),
          status,
          evidence_id: evidence.evidence_id,
          evidence_path: request.evidencePath,
          script_source_sha256: workerResult.script_source_sha256,
          counts: {
            strings: normalizedResult.strings.length,
            modules: normalizedResult.modules.length,
            symbols: normalizedResult.symbols.length,
          },
          supervisor: {
            reason: outcome.reason,
            peak_rss_bytes: outcome.peakRssBytes ?? null,
            wall_ms: outcome.wallMs,
          },
          limitations,
        }),
      );
    } finally {
      inFlight = false;
      if (runDir !== undefined)
        await rm(runDir, { recursive: true, force: true }).catch(() => {});
    }
  };

  return { run, providerState };
};

/** One-shot entry point shared by the CLI command (fresh service per process). */
export const runDynamicExecutionCommand = (
  request: DynamicExecutionRequest,
  signal?: AbortSignal,
): Promise<Result<DynamicExecutionRunOutcome, AnalysisError>> =>
  createDynamicExecutionService().run(request, signal);
