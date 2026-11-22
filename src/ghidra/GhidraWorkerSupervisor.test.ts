import { spawn, type ChildProcess } from "node:child_process";

import { describe, expect, it } from "vitest";

import type { ProviderProcessHandle } from "../process/ProviderProcess.js";
import {
  GhidraWorkerSupervisor,
  parseJvmHeapBytes,
  resolveGhidraWorkerRssCap,
} from "./GhidraWorkerSupervisor.js";

const asHandle = (child: ChildProcess): ProviderProcessHandle =>
  child as unknown as ProviderProcessHandle;

/** Spawn a detached node child so group termination cannot reach the test runner. */
const spawnChild = (script: string): ChildProcess =>
  spawn(process.execPath, ["-e", script], {
    detached: true,
    stdio: "ignore",
  });

const SLEEPER = "setTimeout(() => {}, 30000);";
const HOG =
  "const chunks = [];" +
  "setInterval(() => { const b = new Uint8Array(32 * 1024 * 1024); b.fill(1); chunks.push(b); }, 20);" +
  "setTimeout(() => {}, 30000);";

const isAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

describe("parseJvmHeapBytes", () => {
  it("parses JVM heap units exactly", () => {
    expect(parseJvmHeapBytes("2G")).toBe(2 * 1024 * 1024 * 1024);
    expect(parseJvmHeapBytes("512M")).toBe(512 * 1024 * 1024);
    expect(parseJvmHeapBytes("1024K")).toBe(1024 * 1024);
    expect(parseJvmHeapBytes("1073741824")).toBe(1073741824);
    expect(parseJvmHeapBytes("2g")).toBe(2 * 1024 * 1024 * 1024);
  });

  it("refuses values it cannot read exactly", () => {
    expect(parseJvmHeapBytes("lots")).toBeUndefined();
    expect(parseJvmHeapBytes("")).toBeUndefined();
    expect(parseJvmHeapBytes("-2G")).toBeUndefined();
    expect(parseJvmHeapBytes("0")).toBeUndefined();
  });
});

describe("resolveGhidraWorkerRssCap", () => {
  it("keeps the 3 GiB default above the default 2G heap", () => {
    expect(resolveGhidraWorkerRssCap({ configuredMaxHeap: "2G" })).toBe(
      3 * 1024 * 1024 * 1024,
    );
  });

  it("raises a cap that would sit at or below the heap", () => {
    expect(
      resolveGhidraWorkerRssCap({
        configuredMaxHeap: "2G",
        requestedCapBytes: 1024 * 1024 * 1024,
      }),
    ).toBe(2 * 1024 * 1024 * 1024 + 512 * 1024 * 1024);
    expect(resolveGhidraWorkerRssCap({ configuredMaxHeap: "4G" })).toBe(
      4 * 1024 * 1024 * 1024 + 512 * 1024 * 1024,
    );
  });

  it("honors the requested cap when no heap is configured", () => {
    expect(resolveGhidraWorkerRssCap({ requestedCapBytes: 1234 })).toBe(1234);
  });
});

describe("GhidraWorkerSupervisor", () => {
  it("kills the whole worker at the wall-clock deadline and reports deadline", async () => {
    const child = spawnChild(SLEEPER);
    const pid = child.pid!;
    let outcomePublishedAfterDeath = false;
    const supervisor = new GhidraWorkerSupervisor(asHandle(child), {
      rssCapBytes: 3 * 1024 * 1024 * 1024,
      deadlineMs: 300,
      pollIntervalMs: 50,
      onOutcome: () => {
        // Stop before explain: observers run only after the cascade settled.
        outcomePublishedAfterDeath = !isAlive(pid);
      },
    });
    supervisor.start();
    const outcome = await supervisor.outcome();
    expect(outcome.reason).toBe("deadline");
    expect(outcome.wallMs).toBeLessThan(10_000);
    expect(isAlive(pid)).toBe(false);
    expect(outcomePublishedAfterDeath).toBe(true);
  }, 20_000);

  it("contains a worker that exceeds its RSS cap and reports memory", async () => {
    const child = spawnChild(HOG);
    const pid = child.pid!;
    const supervisor = new GhidraWorkerSupervisor(asHandle(child), {
      rssCapBytes: 150 * 1024 * 1024,
      pollIntervalMs: 50,
    });
    supervisor.start();
    const outcome = await supervisor.outcome();
    expect(outcome.reason).toBe("memory");
    expect(outcome.peakRssBytes).toBeGreaterThan(150 * 1024 * 1024);
    expect(isAlive(pid)).toBe(false);
  }, 30_000);

  it("reports a kill -9 crash and a later worker still runs to a clean exit", async () => {
    const victim = spawnChild(SLEEPER);
    const crashSupervisor = new GhidraWorkerSupervisor(asHandle(victim), {
      rssCapBytes: 3 * 1024 * 1024 * 1024,
      pollIntervalMs: 50,
    });
    crashSupervisor.start();
    process.kill(victim.pid!, "SIGKILL");
    const crash = await crashSupervisor.outcome();
    expect(crash.reason).toBe("crashed");
    expect(crash.signal).toBe("SIGKILL");

    const next = spawnChild("process.exit(0);");
    const nextSupervisor = new GhidraWorkerSupervisor(asHandle(next), {
      rssCapBytes: 3 * 1024 * 1024 * 1024,
      pollIntervalMs: 50,
    });
    nextSupervisor.start();
    const clean = await nextSupervisor.outcome();
    expect(clean.reason).toBe("exited");
    expect(clean.exitCode).toBe(0);
  }, 20_000);

  it("distinguishes a nonzero exit as crashed and an owner stop as stopped", async () => {
    const failing = spawnChild("process.exit(3);");
    const failSupervisor = new GhidraWorkerSupervisor(asHandle(failing), {
      rssCapBytes: 3 * 1024 * 1024 * 1024,
      pollIntervalMs: 25,
    });
    failSupervisor.start();
    expect((await failSupervisor.outcome()).reason).toBe("crashed");

    const sleeper = spawnChild(SLEEPER);
    const stopSupervisor = new GhidraWorkerSupervisor(asHandle(sleeper), {
      rssCapBytes: 3 * 1024 * 1024 * 1024,
      pollIntervalMs: 25,
    });
    stopSupervisor.start();
    const stopped = await stopSupervisor.stop();
    expect(stopped.reason).toBe("stopped");
    expect(isAlive(sleeper.pid!)).toBe(false);
  }, 20_000);
});
