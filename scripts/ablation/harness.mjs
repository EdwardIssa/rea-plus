/**
 * Isolation harness for the dynamic-execution ablation: runs the dynamic
 * worker (or a plain fixture, for fidelity checks) inside the measured
 * namespace contract (user + net + mount, NO pid namespace — feasibility
 * section 3) under the repo's WorkerSupervisor (process-tree RSS cap +
 * deadline, /proc accounting), with a termination cascade (process-group
 * SIGKILL + /proc parentage descendant sweep + target-exe sweep) and a
 * post-run survivor verification. Only repo-authored fixtures are ever run
 * through this harness (spec section 2, hard rule).
 */
import { spawn } from "node:child_process";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { WorkerSupervisor } from "../../dist/process/WorkerSupervisor.js";

const HERE = dirname(fileURLToPath(import.meta.url));
export const WORKER_PATH = join(HERE, "dynamicWorker.mjs");
const SHIM_PATH = join(HERE, "subreaper.py");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const readParentMap = () => {
  const parents = new Map();
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

export const descendantsOf = (rootPid, parents = readParentMap()) => {
  const found = [];
  for (const pid of parents.keys()) {
    if (pid === rootPid) continue;
    let cursor = pid;
    const seen = new Set();
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

export const processesWithExe = (exePaths) => {
  const found = [];
  for (const entry of readdirSync("/proc")) {
    if (!/^\d+$/u.test(entry)) continue;
    try {
      const exe = readlinkSync(`/proc/${entry}/exe`);
      if (exePaths.includes(exe)) found.push(Number(entry));
    } catch {
      // Zombie, kernel thread, or not ours to inspect.
    }
  }
  return found;
};

const killPid = (pid, signal = "SIGKILL") => {
  try {
    process.kill(pid, signal);
  } catch {
    // Already gone.
  }
};

/**
 * Termination cascade used as the supervisor's terminateGroup (the
 * supervisor awaits it): group kill, then repeated parentage sweeps
 * (orphans reparent to the subreaper worker, so the sweep keeps finding
 * them), then a target-exe sweep.
 */
export const makeTerminateGroup = (rootPid, targetExePaths) => async () => {
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

const namespacePrefix = ({ scratchDir, fixtureBinDir }) => {
  const commands = [
    `mount -t tmpfs tmpfs ${scratchDir}`,
    `mount --bind ${fixtureBinDir} ${fixtureBinDir}`,
    `mount -o remount,ro,bind ${fixtureBinDir}`,
  ];
  return commands.join(" && ");
};

const runSupervised = async ({
  innerCommand,
  runDir,
  deadlineMs,
  rssCapBytes,
  env,
  targetExePaths,
}) => {
  mkdirSync(runDir, { recursive: true });
  const stdoutFd = openSync(join(runDir, "chain-stdout.log"), "w");
  const stderrFd = openSync(join(runDir, "chain-stderr.log"), "w");
  const startedAt = Date.now();
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
      innerCommand,
    ],
    { detached: true, stdio: ["ignore", stdoutFd, stderrFd], env },
  );
  const supervisor = new WorkerSupervisor(child, {
    rssCapBytes,
    deadlineMs,
    pollIntervalMs: 200,
    terminateGroup: makeTerminateGroup(child.pid, targetExePaths),
  });
  supervisor.start();
  const outcome = await supervisor.outcome();
  closeSync(stdoutFd);
  closeSync(stderrFd);
  // Settle, then verify: no process running the target binary may survive.
  await sleep(600);
  let survivors = processesWithExe(targetExePaths);
  const breach = survivors.length > 0;
  if (breach) {
    for (const pid of survivors) killPid(pid);
    await sleep(400);
    survivors = processesWithExe(targetExePaths);
    for (const pid of survivors) killPid(pid);
  }
  return {
    outcome: outcome.reason,
    peak_rss_bytes: outcome.peakRssBytes ?? 0,
    wall_ms: Date.now() - startedAt,
    survivors_after: survivors,
    containment_breach: breach,
    exit: { code: outcome.exitCode, signal: outcome.signal },
  };
};

/**
 * Run one Frida session job under the full isolation contract.
 * spec: { job (worker job fields), fixtureBinDir, runDir, deadlineMs,
 *         rssCapBytes, rlimitNproc? }
 */
export const runDynamicJob = async (spec) => {
  const scratchDir = join(spec.runDir, "scratch");
  mkdirSync(scratchDir, { recursive: true });
  const jobPath = join(spec.runDir, "job.json");
  writeFileSync(
    jobPath,
    JSON.stringify(
      { ...spec.job, result_path: join(spec.runDir, "result.json") },
      null,
      1,
    ),
  );
  const prefix = namespacePrefix({
    scratchDir,
    fixtureBinDir: spec.fixtureBinDir,
  });
  const ulimit = spec.rlimitNproc ? `ulimit -u ${spec.rlimitNproc} && ` : "";
  const inner = `${prefix} && ${ulimit}exec python3 ${SHIM_PATH} ${WORKER_PATH} ${jobPath}`;
  const run = await runSupervised({
    innerCommand: inner,
    runDir: spec.runDir,
    deadlineMs: spec.deadlineMs,
    rssCapBytes: spec.rssCapBytes,
    env: { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: scratchDir },
    targetExePaths: [spec.job.program],
  });
  const resultPath = join(spec.runDir, "result.json");
  const result = existsSync(resultPath)
    ? JSON.parse(readFileSync(resultPath, "utf8"))
    : null;
  return { ...run, result };
};

/**
 * Run a fixture directly (no Frida) inside the same namespace contract, for
 * the harness fidelity gate: standalone output must equal authored truth.
 */
export const runPlainJob = async (spec) => {
  const scratchDir = join(spec.runDir, "scratch");
  mkdirSync(scratchDir, { recursive: true });
  const prefix = namespacePrefix({
    scratchDir,
    fixtureBinDir: spec.fixtureBinDir,
  });
  const argv = [spec.program, ...(spec.argv ?? [])]
    .map((a) => `'${String(a).replaceAll("'", "'\\''")}'`)
    .join(" ");
  const inner = `${prefix} && cd ${spec.fixtureBinDir} && exec ${argv}`;
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    TMPDIR: scratchDir,
    ...spec.envSet,
  };
  const run = await runSupervised({
    innerCommand: inner,
    runDir: spec.runDir,
    deadlineMs: spec.deadlineMs,
    rssCapBytes: spec.rssCapBytes,
    env,
    targetExePaths: [spec.program],
  });
  const stdout = existsSync(join(spec.runDir, "chain-stdout.log"))
    ? readFileSync(join(spec.runDir, "chain-stdout.log"), "utf8")
    : "";
  const stderr = existsSync(join(spec.runDir, "chain-stderr.log"))
    ? readFileSync(join(spec.runDir, "chain-stderr.log"), "utf8")
    : "";
  return { ...run, stdout, stderr };
};
