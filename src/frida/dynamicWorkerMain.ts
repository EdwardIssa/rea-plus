/**
 * Dynamic-execution worker entry. Runs INSIDE the namespace + supervisor
 * isolation the application builds (see runDynamicExecution): drives the
 * Frida composition (spawn paused -> load hook pack -> resume -> collect
 * with the settle discipline) and publishes its result atomically (temp
 * file + rename) to job.result_path. It publishes early and re-publishes
 * as the message snapshot grows, so a run the supervisor ends still has a
 * published result to file. Failures are recorded in the result, never
 * thrown past it. Never a registered surface itself.
 *
 * Usage: node dynamicWorkerMain.js <job.json>
 * Job: { program, argv, env_set, cwd, session_timeout_ms, result_path }
 */
import {
  existsSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  dynamicWorkerResultSchema,
  type DynamicAccountedProcess,
  type DynamicWorkerResult,
} from "../domain/dynamicExecution/dynamicObservation.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { FridaInstrumentationManager } from "./FridaInstrumentationManager.js";
import {
  HOOK_PACK_SOURCE,
  HOOK_PACK_TESTED_FRIDA_MAJOR,
  HOOK_PACK_VERSION,
} from "./hookPack.js";
import { SUBREAPER_MARKER_FILE } from "./subreaperShim.js";

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/** Live descendants of a pid, from /proc parentage (harness worker port). */
const descendantsOf = (rootPid: number): number[] => {
  const parents = new Map<number, number>();
  for (const entry of readdirSync("/proc")) {
    if (!/^\d+$/u.test(entry)) continue;
    try {
      const stat = readFileSync(`/proc/${entry}/stat`, "utf8");
      const tail = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      parents.set(Number(entry), Number(tail[1]));
    } catch {
      // Process exited mid-scan.
    }
  }
  const found: number[] = [];
  for (const pid of parents.keys()) {
    let cursor: number | undefined = pid;
    const seen = new Set<number>();
    while (cursor !== undefined && !seen.has(cursor)) {
      if (cursor === rootPid && pid !== rootPid) {
        found.push(pid);
        break;
      }
      seen.add(cursor);
      cursor = parents.get(cursor);
    }
  }
  return found;
};

/** Exe image of a live pid; null when it exited mid-scan or is a zombie. */
const exeOfPid = (pid: number): string | null => {
  try {
    return readlinkSync(`/proc/${pid}/exe`);
  } catch {
    return null;
  }
};

/** Stored accounting lists are bounded; the counts carry the true totals. */
const ACCOUNTING_LIST_CAP = 4096;

interface DynamicJob {
  readonly program: string;
  readonly argv?: readonly string[];
  readonly env_set?: Readonly<Record<string, string>>;
  readonly cwd: string;
  readonly session_timeout_ms: number;
  readonly result_path: string;
}

/**
 * Load the Frida binding and read the loaded runtime's own version from
 * its package metadata (the module exports no version constant): resolve
 * the module's entry, then walk up to the package.json that owns it. The
 * manager lazy-loads the same module instance on first use.
 */
const loadBindingVersion = async (): Promise<
  { readonly version: string } | { readonly failure: string }
> => {
  try {
    await import("frida");
  } catch (cause) {
    return {
      failure: `Frida binding failed to load: ${cause instanceof Error ? cause.message : String(cause)}`,
    };
  }
  try {
    let dir = dirname(fileURLToPath(import.meta.resolve("frida")));
    for (let depth = 0; depth < 6; depth++) {
      const candidate = join(dir, "package.json");
      if (existsSync(candidate)) {
        const packageJson = JSON.parse(readFileSync(candidate, "utf8")) as {
          name?: unknown;
          version?: unknown;
        };
        if (
          packageJson.name === "frida" &&
          typeof packageJson.version === "string"
        )
          return { version: packageJson.version };
      }
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  } catch {
    // Fall through to the honest failure below.
  }
  return {
    failure:
      "Frida binding loaded but its version could not be determined from its package metadata",
  };
};

const main = async (): Promise<void> => {
  const job = JSON.parse(
    readFileSync(process.argv[2] ?? "", "utf8"),
  ) as DynamicJob;
  const result: {
    -readonly [K in keyof DynamicWorkerResult]: DynamicWorkerResult[K];
  } = {
    status: "running",
    failure_reason: null,
    frida_version: null,
    hook_pack_version: HOOK_PACK_VERSION,
    script_source_sha256: null,
    target_pid: null,
    resume_observed: false,
    stream_settled: false,
    messages: [],
    messages_truncated: false,
    descendant_accounting: null,
  };
  const publish = (): void => {
    const parsed = dynamicWorkerResultSchema.parse(result);
    const temp = `${job.result_path}.tmp-${process.pid}`;
    writeFileSync(temp, `${JSON.stringify(parsed, null, 1)}\n`);
    renameSync(temp, job.result_path);
  };
  // The shim that armed this worker as the run's subreaper left a marker
  // beside the job naming its own pid, which the exec preserved into this
  // process. Only with that proof is this worker's descendant accounting
  // authoritative: without it, escapees reparent past this worker to the
  // host init, the accounting would be blind, and the application must
  // claim no containment verdict from it.
  let subreaperArmed = false;
  try {
    const marker = JSON.parse(
      readFileSync(
        join(dirname(job.result_path), SUBREAPER_MARKER_FILE),
        "utf8",
      ),
    ) as { pid?: unknown; subreaper?: unknown };
    subreaperArmed = marker.subreaper === true && marker.pid === process.pid;
  } catch {
    subreaperArmed = false;
  }
  const observedDescendants = new Map<number, string>();
  /**
   * Refresh the descendant accounting from the worker's own tree and
   * return the descendants remaining now. As the subreaper this worker
   * is where escapees reparent, so its tree is the complete descendant
   * set for the run regardless of the image a descendant exec'd. The
   * target itself is excluded: it is the session's own process, not an
   * escapee. Processes whose exe can no longer be read (exited mid-scan,
   * zombie husks) are not remaining. The observed union is recorded only
   * once the session has ended (recordObserved), when a surviving
   * descendant has by definition outlived the target; the remaining set
   * refreshes during the session too, so a worker ended mid-session by
   * the supervisor still leaves a current set for the verdict.
   */
  const refreshAccounting = (
    recordObserved: boolean,
  ): readonly DynamicAccountedProcess[] => {
    const current: DynamicAccountedProcess[] = [];
    for (const pid of descendantsOf(process.pid)) {
      if (pid === result.target_pid) continue;
      const exe = exeOfPid(pid);
      if (exe === null) continue;
      current.push({ pid, exe });
      if (recordObserved && !observedDescendants.has(pid))
        observedDescendants.set(pid, exe);
    }
    const observed = [...observedDescendants.entries()].map(([pid, exe]) => ({
      pid,
      exe,
    }));
    result.descendant_accounting = {
      subreaper_armed: subreaperArmed,
      observed: observed.slice(0, ACCOUNTING_LIST_CAP),
      observed_count: observed.length,
      remaining: current.slice(0, ACCOUNTING_LIST_CAP),
      remaining_count: current.length,
    };
    return current;
  };
  try {
    process.chdir(job.cwd);
    for (const [key, value] of Object.entries(job.env_set ?? {}))
      process.env[key] = value;

    const binding = await loadBindingVersion();
    if ("failure" in binding) {
      result.status = "unavailable";
      result.failure_reason = binding.failure;
      publish();
      return;
    }
    result.frida_version = binding.version;
    const loadedMajor = Number(binding.version.split(".")[0]);
    if (loadedMajor !== HOOK_PACK_TESTED_FRIDA_MAJOR) {
      result.status = "version_skew";
      result.failure_reason =
        `Hook pack ${HOOK_PACK_VERSION} is tested against the Frida ${HOOK_PACK_TESTED_FRIDA_MAJOR} API line, ` +
        `but the loaded Frida binding is ${binding.version}; refusing before spawn.`;
      publish();
      return;
    }

    const provider = new FridaInstrumentationManager();
    const session = await provider.startSession({
      mode: "spawn",
      program: job.program,
      // The manager prepends the program to argv itself, so the job
      // carries the stimulus arguments only.
      argv: job.argv ?? [],
    });
    if (!session.ok) {
      result.status = "failed";
      result.failure_reason = `startSession failed: ${session.error.message}`;
      publish();
      return;
    }
    const sessionId = session.value.sessionId;
    result.target_pid = session.value.pid;
    const script = await provider.loadScript(sessionId, {
      sourceKind: "inline",
      source: HOOK_PACK_SOURCE,
    });
    if (!script.ok) {
      result.status = "failed";
      result.failure_reason = `loadScript failed: ${script.error.message}`;
      await provider.closeSession(sessionId).catch(() => {});
      publish();
      return;
    }
    result.script_source_sha256 = script.value.sourceSha256;
    publish();
    const resumed = await provider.resumeSession(sessionId);
    if (!resumed.ok) {
      result.status = "failed";
      result.failure_reason = `resumeSession failed: ${resumed.error.message}`;
      await provider.closeSession(sessionId).catch(() => {});
      publish();
      return;
    }
    // Poll the session status; keep the longest message snapshot seen
    // (snapshots are cumulative) until the target detaches or time runs
    // out, re-publishing as the snapshot grows.
    let longest: readonly JsonValue[] = [];
    let detached = false;
    let lastPublishAt = Date.now();
    let lastAccountingAt = 0;
    const deadline = Date.now() + job.session_timeout_ms;
    while (Date.now() < deadline) {
      const status = provider.status(sessionId);
      if (status === undefined) {
        detached = true;
        break;
      }
      if ((status.messages ?? []).length >= longest.length) {
        longest = status.messages ?? [];
        result.messages_truncated = status.messagesTruncated === true;
      }
      result.resume_observed = status.targetResumeObserved === true;
      if (status.state === "detached") {
        detached = true;
        break;
      }
      if (
        longest.length > result.messages.length &&
        Date.now() - lastPublishAt >= 200
      ) {
        result.messages = [...longest];
        publish();
        lastPublishAt = Date.now();
      }
      // Keep the accounting's remaining set current while the session
      // runs, so a worker the supervisor ends mid-session (deadline, RSS
      // cap) still leaves a fresh set for the containment verdict.
      if (Date.now() - lastAccountingAt >= 250) {
        lastAccountingAt = Date.now();
        const before = result.descendant_accounting;
        refreshAccounting(false);
        const after = result.descendant_accounting;
        if (
          before?.remaining_count !== after?.remaining_count ||
          before?.observed_count !== after?.observed_count
        )
          publish();
      }
      await sleep(50);
    }
    if (detached) {
      // The target's final stdout flush is written during exit; its hook
      // message can reach the session FIFO after the detach is first
      // observed. Keep reading until the snapshot stops growing (or the
      // settle budget runs out) so the stream claim is complete.
      let stablePolls = 0;
      const settleDeadline = Date.now() + 1500;
      while (Date.now() < settleDeadline && stablePolls < 3) {
        const status = provider.status(sessionId);
        const messages = status?.messages ?? [];
        if (messages.length > longest.length) {
          longest = messages;
          result.messages_truncated = status?.messagesTruncated === true;
          stablePolls = 0;
        } else {
          stablePolls++;
        }
        await sleep(60);
      }
      result.stream_settled = stablePolls >= 3;
    }
    result.messages = [...longest];
    if (!detached) {
      // Session timeout: end the session and kill the target the worker
      // spawned, then let the survivor check below decide about holding.
      result.status = "session_timeout";
      if (result.target_pid !== null) {
        try {
          process.kill(result.target_pid, "SIGKILL");
        } catch {
          // Already gone.
        }
      }
      await provider.closeSession(sessionId).catch(() => {});
      await provider.closeAll().catch(() => {});
      publish();
    } else {
      await provider.closeSession(sessionId).catch(() => {});
      await provider.closeAll().catch(() => {});
      result.status = "complete";
      publish();
    }
    // Survivor check and descendant accounting: processes still in the
    // worker's own tree (escapees reparent here through the subreaper)
    // are held inside the supervisor's accounting until it ends the run;
    // the worker never releases them into the host. If they drain on
    // their own, the run completes normally. The accounting is refreshed
    // and re-published whenever the held set changes, so a run the
    // supervisor ends mid-hold still leaves its latest accounting in the
    // published result for the application's containment verdict.
    await sleep(150);
    let remaining = refreshAccounting(true);
    publish();
    if (remaining.length > 0) {
      if (result.status === "complete") {
        result.status = "holding";
        publish();
      }
      const holdDeadline = Date.now() + 600_000;
      while (Date.now() < holdDeadline && remaining.length > 0) {
        await sleep(500);
        const before = result.descendant_accounting;
        remaining = refreshAccounting(true);
        const after = result.descendant_accounting;
        if (
          before?.remaining_count !== after?.remaining_count ||
          before?.observed_count !== after?.observed_count
        )
          publish();
      }
      if (remaining.length === 0 && result.status === "holding") {
        result.status = "complete";
        publish();
      }
    }
  } catch (error) {
    result.status = "failed";
    result.failure_reason = `worker exception: ${error instanceof Error ? error.message : String(error)}`;
    try {
      publish();
    } catch {
      process.exit(1);
    }
  }
};

await main();
process.exit(0);
