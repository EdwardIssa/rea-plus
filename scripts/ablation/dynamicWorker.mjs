/**
 * Dynamic-arm worker for the ablation harness. Runs INSIDE the namespace +
 * supervisor isolation (see harness.mjs), drives REA+'s own Frida composition
 * (createFridaInstrumentationProvider from the built dist): spawn (paused) ->
 * load hook pack -> resume -> collect messages -> close. Writes its result
 * atomically (temp file + rename) to job.result_path and exits 0; failures
 * are recorded in the result, never thrown past it.
 *
 * Usage: node dynamicWorker.mjs <job.json>
 * Job: { program, argv, env_set, env_unset, cwd, hook_pack_source,
 *        session_timeout_ms, hold_after_exit_ms, result_path }
 */
import { readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";

import { createFridaInstrumentationProvider } from "../../dist/composition/frida.js";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const descendantsOf = (rootPid) => {
  const parents = new Map();
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
  const found = [];
  for (const pid of parents.keys()) {
    let cursor = pid;
    const seen = new Set();
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

const unwrapPayload = (message) =>
  message !== null &&
  typeof message === "object" &&
  message.type === "send" &&
  message.payload !== null &&
  typeof message.payload === "object"
    ? message.payload
    : null;

const main = async () => {
  const job = JSON.parse(readFileSync(process.argv[2], "utf8"));
  const startedAt = Date.now();
  const result = {
    status: "failed",
    failure_reason: "worker did not complete",
    target_pid: null,
    resume_observed: false,
    messages: [],
    stdout_text: "",
    stderr_text: "",
    observations: { texts: [], dlopen: [], dlsym: [], exit_code: null },
    pack_ready: null,
    survivors_killed: 0,
    wall_ms: 0,
  };
  const publish = () => {
    result.wall_ms = Date.now() - startedAt;
    const temp = `${job.result_path}.tmp-${process.pid}`;
    writeFileSync(temp, JSON.stringify(result, null, 1) + "\n");
    renameSync(temp, job.result_path);
  };
  try {
    process.chdir(job.cwd);
    for (const key of job.env_unset ?? []) delete process.env[key];
    for (const [key, value] of Object.entries(job.env_set ?? {}))
      process.env[key] = value;
    const provider = createFridaInstrumentationProvider();
    const session = await provider.startSession({
      mode: "spawn",
      program: job.program,
      // REA's manager prepends the program to input.argv itself
      // (device.spawn(program, { argv: [program, ...input.argv] })), so the
      // job carries the stimulus arguments only.
      argv: job.argv ?? [],
    });
    if (!session.ok) {
      result.failure_reason = `startSession failed: ${session.error?.message ?? "unknown"}`;
      publish();
      return;
    }
    const sessionId = session.value.sessionId;
    result.target_pid = session.value.pid;
    const script = await provider.loadScript(sessionId, {
      sourceKind: "inline",
      source: job.hook_pack_source,
    });
    if (!script.ok) {
      result.failure_reason = `loadScript failed: ${script.error?.message ?? "unknown"}`;
      await provider.closeSession(sessionId).catch(() => {});
      publish();
      return;
    }
    const resumed = await provider.resumeSession(sessionId);
    if (!resumed.ok) {
      result.failure_reason = `resumeSession failed: ${resumed.error?.message ?? "unknown"}`;
      await provider.closeSession(sessionId).catch(() => {});
      publish();
      return;
    }
    // Poll the session status; keep the longest message snapshot seen
    // (snapshots are cumulative) until the target detaches or time runs out.
    let longest = [];
    let detached = false;
    const deadline = Date.now() + job.session_timeout_ms;
    while (Date.now() < deadline) {
      const status = provider.status(sessionId);
      if (status === undefined) {
        detached = true;
        break;
      }
      if ((status.messages ?? []).length >= longest.length)
        longest = status.messages ?? [];
      result.resume_observed = status.targetResumeObserved === true;
      if (status.state === "detached") {
        detached = true;
        break;
      }
      await sleep(50);
    }
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
        stablePolls = 0;
      } else {
        stablePolls++;
      }
      if (!detached && status !== undefined && status.state !== "detached")
        break;
      await sleep(60);
    }
    result.messages = longest;
    if (!detached) {
      result.failure_reason = "session_timeout";
      await provider.closeSession(sessionId).catch(() => {});
      await provider.closeAll().catch(() => {});
      publish();
      return;
    }
    await provider.closeSession(sessionId).catch(() => {});
    await provider.closeAll().catch(() => {});
    // Derive observations from the hook-pack messages.
    const stdoutChunks = [];
    const stderrChunks = [];
    for (const message of longest) {
      const payload = unwrapPayload(message);
      if (payload === null) continue;
      if (payload.t === "pack_ready") result.pack_ready = payload;
      else if (
        payload.t === "puts" ||
        payload.t === "fputs" ||
        payload.t === "printf_fmt"
      )
        result.observations.texts.push(payload.text);
      else if (payload.t === "write" && Array.isArray(payload.data)) {
        const chunk = Buffer.from(payload.data);
        if (payload.fd === 1) stdoutChunks.push(chunk);
        else if (payload.fd === 2) stderrChunks.push(chunk);
      } else if (payload.t === "dlopen")
        result.observations.dlopen.push({ path: payload.path, ok: payload.ok });
      else if (payload.t === "dlsym")
        result.observations.dlsym.push({ name: payload.name, ok: payload.ok });
      else if (payload.t === "exit")
        result.observations.exit_code = payload.code;
    }
    result.stdout_text = Buffer.concat(stdoutChunks).toString("utf8");
    result.stderr_text = Buffer.concat(stderrChunks).toString("utf8");
    if (job.hold_after_exit_ms > 0) {
      // Containment mode (S3): stay alive and hold the escaped tree inside
      // the supervisor's accounting until the supervisor deadline ends the
      // run; the supervisor's termination cascade is the mechanism on trial.
      result.status = "holding";
      publish();
      await sleep(job.hold_after_exit_ms);
      return;
    }
    // Survivor self-check: nothing in our own tree may outlive the session.
    await sleep(150);
    for (const pid of descendantsOf(process.pid)) {
      try {
        process.kill(pid, "SIGKILL");
        result.survivors_killed++;
      } catch {
        // Already gone.
      }
    }
    result.status = "complete";
    result.failure_reason = null;
    publish();
  } catch (error) {
    result.failure_reason = `worker exception: ${error?.message ?? String(error)}`;
    try {
      publish();
    } catch {
      // Result path unreachable; the harness records a missing result.
    }
  }
};

await main();
process.exit(0);
