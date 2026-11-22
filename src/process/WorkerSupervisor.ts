import { readdir, readFile } from "node:fs/promises";

import type { ProviderProcessHandle } from "./ProviderProcess.js";

/**
 * Sum RSS over a process tree on Linux by walking /proc parent links.
 * Returns undefined when the platform or the tree cannot be read, so the
 * watchdog treats memory as unknown rather than absent.
 */
export const readProcessTreeRssBytes = async (
  rootPid: number,
): Promise<number | undefined> => {
  if (process.platform !== "linux") return undefined;
  let entries: string[];
  try {
    entries = await readdir("/proc");
  } catch {
    return undefined;
  }
  const parents = new Map<number, number>();
  const rss = new Map<number, number>();
  const pageSize = 4096;
  await Promise.all(
    entries
      .filter((entry) => /^\d+$/u.test(entry))
      .map(async (entry) => {
        const pid = Number(entry);
        try {
          const stat = await readFile(`/proc/${entry}/stat`, "utf8");
          // comm may contain spaces and parentheses; fields after the final
          // ")" are: state, ppid, ... rss is field 24 overall (index 21 here).
          const tail = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
          const ppid = Number(tail[1]);
          const rssPages = Number(tail[21]);
          if (Number.isFinite(ppid)) parents.set(pid, ppid);
          if (Number.isFinite(rssPages)) rss.set(pid, rssPages * pageSize);
        } catch {
          // The process exited mid-scan; its RSS is simply not observed.
        }
      }),
  );
  if (!rss.has(rootPid) && !parents.has(rootPid)) return undefined;
  let total = 0;
  for (const [pid, bytes] of rss) {
    let cursor: number | undefined = pid;
    const seen = new Set<number>();
    while (cursor !== undefined && !seen.has(cursor)) {
      if (cursor === rootPid) {
        total += bytes;
        break;
      }
      seen.add(cursor);
      cursor = parents.get(cursor);
    }
  }
  return total;
};

/** Why a supervised worker settled. Watchdog reasons name the constraint. */
export type WorkerTerminationReason =
  | "deadline"
  | "memory"
  | "exited"
  | "crashed"
  | "stopped";

/** Terminal observation of one supervised worker. */
export interface WorkerOutcome {
  readonly reason: WorkerTerminationReason;
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly peakRssBytes: number | undefined;
  readonly wallMs: number;
}

export interface WorkerSupervisorOptions {
  /** RSS cap for the whole worker tree; enforced on measured bytes only. */
  readonly rssCapBytes: number;
  /** Wall-clock deadline from supervisor start; undefined disables it. */
  readonly deadlineMs?: number;
  readonly pollIntervalMs?: number;
  /** Injectable tree RSS reader; defaults to the /proc reader. */
  readonly readTreeRssBytes?: (rootPid: number) => Promise<number | undefined>;
  /**
   * Terminate the worker's whole process group. Defaults to SIGKILL on the
   * group; the launcher injects its owned cleanup cascade.
   */
  readonly terminateGroup?: () => Promise<void>;
  /** Runs only after termination fully settles: stop before explain. */
  readonly onOutcome?: (outcome: WorkerOutcome) => void;
}

/**
 * Supervises one spawned worker process. Constraint evaluation always
 * precedes any abort (brain before muscle): each poll first measures the
 * tree RSS and the elapsed wall time, and only then acts. When a constraint
 * trips, the termination cascade runs to completion before the outcome is
 * published to observers (stop before explain).
 */
export class WorkerSupervisor {
  readonly #process: ProviderProcessHandle;
  readonly #options: WorkerSupervisorOptions;
  readonly #startedAt = Date.now();
  #timer: NodeJS.Timeout | undefined;
  #peakRssBytes: number | undefined;
  #breach: "deadline" | "memory" | undefined;
  #stopRequested = false;
  #settled: WorkerOutcome | undefined;
  readonly #outcomePromise: Promise<WorkerOutcome>;
  #resolveOutcome!: (outcome: WorkerOutcome) => void;

  constructor(
    workerProcess: ProviderProcessHandle,
    options: WorkerSupervisorOptions,
  ) {
    this.#process = workerProcess;
    this.#options = options;
    this.#outcomePromise = new Promise<WorkerOutcome>((resolve) => {
      this.#resolveOutcome = resolve;
    });
    this.#process.once(
      "exit",
      (code: number | null, signal: NodeJS.Signals | null) => {
        void this.#onExit(code, signal);
      },
    );
  }

  /** Begin polling. Idempotent; a settled supervisor stays settled. */
  start(): void {
    if (this.#timer !== undefined || this.#settled !== undefined) return;
    const interval = this.#options.pollIntervalMs ?? 250;
    this.#timer = setInterval(() => void this.#poll(), interval);
    this.#timer.unref?.();
  }

  /** The terminal outcome, resolving once the worker has fully settled. */
  outcome(): Promise<WorkerOutcome> {
    return this.#outcomePromise;
  }

  /** Latest settled outcome, or undefined while the worker is live. */
  snapshot(): WorkerOutcome | undefined {
    return this.#settled;
  }

  /** Peak measured tree RSS so far; undefined until a read succeeds. */
  get peakRssBytes(): number | undefined {
    return this.#peakRssBytes;
  }

  /**
   * Mark an owner-initiated stop whose termination cascade runs elsewhere
   * (the launcher's own cleanup), so the worker's exit is reported as
   * `stopped` rather than `crashed`.
   */
  noteOwnerStop(): void {
    this.#stopRequested = true;
  }

  /**
   * Owner-initiated stop: mark the stop first so the worker's exit is
   * reported as `stopped`, then run the termination cascade.
   */
  async stop(): Promise<WorkerOutcome> {
    this.#stopRequested = true;
    if (
      this.#settled === undefined &&
      this.#process.exitCode === null &&
      this.#process.signalCode === null
    ) {
      await this.#terminate();
    }
    return this.#outcomePromise;
  }

  async #poll(): Promise<void> {
    if (this.#settled !== undefined || this.#breach !== undefined) return;
    // Evaluate first: fresh measurements and elapsed time, then act.
    const pid = this.#process.pid;
    let rss: number | undefined;
    if (pid !== undefined) {
      rss = await (this.#options.readTreeRssBytes ?? readProcessTreeRssBytes)(
        pid,
      );
    }
    if (rss !== undefined)
      this.#peakRssBytes = Math.max(this.#peakRssBytes ?? 0, rss);
    const elapsed = Date.now() - this.#startedAt;
    let breach: "deadline" | "memory" | undefined;
    if (
      this.#options.deadlineMs !== undefined &&
      elapsed >= this.#options.deadlineMs
    )
      breach = "deadline";
    else if (rss !== undefined && rss > this.#options.rssCapBytes)
      breach = "memory";
    if (breach === undefined) return;
    if (this.#settled !== undefined) return;
    this.#breach = breach;
    await this.#terminate();
  }

  async #terminate(): Promise<void> {
    try {
      if (this.#options.terminateGroup !== undefined)
        await this.#options.terminateGroup();
      else if (this.#process.pid !== undefined) {
        try {
          process.kill(-this.#process.pid, "SIGKILL");
        } catch {
          this.#process.kill("SIGKILL");
        }
      }
    } catch {
      // Termination is best-effort; the exit observation settles the outcome.
    }
  }

  async #onExit(
    code: number | null,
    signal: NodeJS.Signals | null,
  ): Promise<void> {
    if (this.#settled !== undefined) return;
    // The cascade has completed by the time exit is observed; only now is
    // the outcome published to observers.
    const reason: WorkerTerminationReason =
      this.#breach ??
      (this.#stopRequested ? "stopped" : code === 0 ? "exited" : "crashed");
    const outcome: WorkerOutcome = {
      reason,
      exitCode: code,
      signal,
      peakRssBytes: this.#peakRssBytes,
      wallMs: Date.now() - this.#startedAt,
    };
    this.#settled = outcome;
    if (this.#timer !== undefined) {
      clearInterval(this.#timer);
      this.#timer = undefined;
    }
    this.#resolveOutcome(outcome);
    this.#options.onOutcome?.(outcome);
  }
}
