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
  readdirSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  dynamicWorkerResultSchema,
  type DynamicWorkerResult,
} from "../domain/dynamicExecution/dynamicObservation.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { FridaInstrumentationManager } from "./FridaInstrumentationManager.js";
import {
  HOOK_PACK_SOURCE,
  HOOK_PACK_TESTED_FRIDA_MAJOR,
  HOOK_PACK_VERSION,
} from "./hookPack.js";

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
  };
  const publish = (): void => {
    const parsed = dynamicWorkerResultSchema.parse(result);
    const temp = `${job.result_path}.tmp-${process.pid}`;
    writeFileSync(temp, `${JSON.stringify(parsed, null, 1)}\n`);
    renameSync(temp, job.result_path);
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
    // Survivor check: processes still in the worker's own tree (escapees
    // reparent here through the subreaper) are held inside the
    // supervisor's accounting until it ends the run; the worker never
    // releases them into the host. If they drain on their own, the run
    // completes normally.
    await sleep(150);
    if (descendantsOf(process.pid).length > 0) {
      if (result.status === "complete") {
        result.status = "holding";
        publish();
      }
      const holdDeadline = Date.now() + 600_000;
      while (Date.now() < holdDeadline && descendantsOf(process.pid).length > 0)
        await sleep(500);
      if (
        descendantsOf(process.pid).length === 0 &&
        result.status === "holding"
      ) {
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
