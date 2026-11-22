import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { beforeAll, describe, expect, it } from "vitest";

import {
  createDynamicExecutionService,
  runDynamicExecutionCommand,
} from "../../../src/application/dynamicExecution/runDynamicExecution.js";
import { parseEvidence, type Evidence } from "../../../src/domain/evidence.js";
import {
  buildFixtures,
  FIXTURES_ROOT,
} from "../../../scripts/ablation/buildFixtures.mjs";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const workerPath = join(
  here,
  "..",
  "..",
  "..",
  "dist",
  "frida",
  "dynamicWorkerMain.js",
);

const binaryOf = (id: string): string => join(FIXTURES_ROOT, "bin", id, id);
const truthOf = (id: string): Record<string, unknown> =>
  JSON.parse(
    readFileSync(join(FIXTURES_ROOT, id, "truth.json"), "utf8"),
  ) as Record<string, unknown>;
const sha256Of = (path: string): string =>
  createHash("sha256").update(readFileSync(path)).digest("hex");

/**
 * Pids of s4 escapees alive on the host: processes whose cmdline is the
 * fixture's distinctive different-image invocation (`sleep 31337`). The
 * s4 test checks the host directly as an independent guard, outside the
 * product's own accounting and verdict entirely.
 */
const s4EscapeePids = (): number[] => {
  const found: number[] = [];
  for (const entry of readdirSync("/proc")) {
    if (!/^\d+$/u.test(entry)) continue;
    try {
      const parts = readFileSync(`/proc/${entry}/cmdline`, "utf8")
        .split("\0")
        .filter((part) => part.length > 0);
      if (
        parts.length === 2 &&
        (parts[0] === "sleep" || parts[0]?.endsWith("/sleep") === true) &&
        parts[1] === "31337"
      )
        found.push(Number(entry));
    } catch {
      // Process exited mid-scan or is not ours to inspect.
    }
  }
  return found;
};

beforeAll(() => {
  buildFixtures();
}, 300_000);

describe("execute_dynamically product path", () => {
  it("a1: runtime-only plaintext lands as a string row (class A parity)", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-eval-a1-");
    const evidencePath = join(temp, "a1.evidence.json");
    const result = await runDynamicExecutionCommand({
      targetPath: binaryOf("a1"),
      evidencePath,
    });
    if (!result.ok) throw result.error;
    expect(result.value.status).toBe("complete");
    expect(result.value.counts).toEqual({ strings: 1, modules: 0, symbols: 0 });
    expect(result.value.supervisor.reason).toBe("exited");

    const evidence = parseEvidence(
      JSON.parse(await readFile(evidencePath, "utf8")),
    ) as Evidence;
    expect(evidence.subject?.digest.sha256).toBe(sha256Of(binaryOf("a1")));
    expect(evidence.provider).toMatchObject({
      id: "frida",
      version: "17.23.2",
    });
    expect(evidence.authority).toBe("controlled-replay");
    const nr = evidence.normalized_result as {
      strings: unknown;
      output: { stdout: string; exit_code: number | null };
      execution: {
        hook_pack_version: string;
        frida_version: string;
        pack_ready: { missing: string[] } | null;
        containment: {
          verified: boolean;
          source: string;
          breach: boolean | null;
          survivors_after: string[];
          reaped_descendants: string[];
        };
      };
    };
    // The class-A truth: the plaintext exists only at runtime.
    expect(nr.strings).toEqual([
      { value: "alpha-secret-one", channel: "puts" },
    ]);
    expect(nr.output.stdout).toBe(
      (truthOf("a1").outputs as Record<string, string>)["s1"],
    );
    expect(nr.output.exit_code).toBe(0);
    expect(nr.execution.hook_pack_version).toBe("1.1.0");
    expect(nr.execution.frida_version).toBe("17.23.2");
    expect(nr.execution.pack_ready?.missing).toEqual([]);
    expect(nr.execution.containment).toEqual({
      verified: true,
      source: "subreaper_accounting",
      breach: false,
      survivors_after: [],
      reaped_descendants: [],
    });
  }, 120_000);

  it("c1: the executed dispatch target is observed, the others are not (class C parity)", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-eval-c1-");
    const evidencePath = join(temp, "c1.evidence.json");
    const result = await runDynamicExecutionCommand({
      targetPath: binaryOf("c1"),
      argv: ["0"],
      evidencePath,
    });
    if (!result.ok) throw result.error;
    expect(result.value.status).toBe("complete");
    const evidence = parseEvidence(
      JSON.parse(await readFile(evidencePath, "utf8")),
    ) as Evidence;
    const nr = evidence.normalized_result as {
      strings: { value: string }[];
      output: { stdout: string };
    };
    expect(nr.output.stdout).toContain("result-add");
    expect(nr.output.stdout).not.toContain("result-sub");
    expect(nr.output.stdout).not.toContain("result-mul");
    expect(nr.strings.map((row) => row.value)).toContain("result-add");
    expect(nr.strings.map((row) => row.value)).not.toContain("result-sub");
  }, 120_000);

  it("b3: dlopen/dlsym observations file under exactly one kind each", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-eval-b3-");
    const evidencePath = join(temp, "b3.evidence.json");
    const result = await runDynamicExecutionCommand({
      targetPath: binaryOf("b3"),
      evidencePath,
    });
    if (!result.ok) throw result.error;
    expect(result.value.status).toBe("complete");
    const evidence = parseEvidence(
      JSON.parse(await readFile(evidencePath, "utf8")),
    ) as Evidence;
    const nr = evidence.normalized_result as {
      strings: { value: string }[];
      modules: { path: string; basename: string | null; ok: boolean }[];
      symbols: { name: string; ok: boolean }[];
      output: { stdout: string };
    };
    expect(nr.modules).toContainEqual({
      path: "./libplug3.so",
      basename: "libplug3.so",
      ok: true,
    });
    expect(nr.symbols).toContainEqual({ name: "plug_greet", ok: true });
    const stringValues = nr.strings.map((row) => row.value);
    expect(stringValues).toContain("plug-three-hello");
    // The vocabulary rule: a load path and a symbol name are never strings.
    expect(stringValues).not.toContain("./libplug3.so");
    expect(stringValues).not.toContain("plug_greet");
    expect(nr.output.stdout).toContain("plug-three-hello");
  }, 120_000);

  it("is deterministic across three identical a1 runs", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-eval-det-");
    const filings: unknown[] = [];
    for (let i = 0; i < 3; i++) {
      const evidencePath = join(temp, `a1-${i}.evidence.json`);
      const result = await runDynamicExecutionCommand({
        targetPath: binaryOf("a1"),
        evidencePath,
      });
      if (!result.ok) throw result.error;
      const evidence = parseEvidence(
        JSON.parse(await readFile(evidencePath, "utf8")),
      ) as Evidence;
      const nr = evidence.normalized_result as {
        strings: unknown;
        modules: unknown;
        symbols: unknown;
        output: unknown;
      };
      filings.push({
        strings: nr.strings,
        modules: nr.modules,
        symbols: nr.symbols,
        output: nr.output,
      });
    }
    expect(filings[1]).toEqual(filings[0]);
    expect(filings[2]).toEqual(filings[0]);
  }, 180_000);
});

describe("execute_dynamically refusals", () => {
  it("refuses a second concurrent run instead of queueing it", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-eval-busy-");
    const service = createDynamicExecutionService();
    const first = service.run({
      targetPath: binaryOf("s3"),
      sessionTimeoutMs: 3_000,
      deadlineMs: 30_000,
      evidencePath: join(temp, "s3.evidence.json"),
    });
    const second = await service.run({
      targetPath: binaryOf("a1"),
      evidencePath: join(temp, "a1.evidence.json"),
    });
    expect(second.ok).toBe(false);
    if (!second.ok)
      expect((second.error as { _tag?: string })._tag).toBe(
        "AnalysisResourceConstraintError",
      );
    const firstResult = await first;
    if (!firstResult.ok) throw firstResult.error;
    expect(firstResult.value.status).toBe("terminated");
  }, 120_000);

  it("refuses a missing target without writing Evidence", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-eval-missing-");
    const evidencePath = join(temp, "none.evidence.json");
    const result = await runDynamicExecutionCommand({
      targetPath: join(temp, "no-such-binary"),
      evidencePath,
    });
    expect(result.ok).toBe(false);
    expect(existsSync(evidencePath)).toBe(false);
  }, 60_000);
});

describe("execute_dynamically containment on the product path", () => {
  it("s1 fork bomb is terminated by the supervisor with no survivors", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-eval-s1-");
    const service = createDynamicExecutionService();
    // Which supervisor limit fires first for s1 is condition-dependent,
    // measured both ways on this host: during the ablation run (busy box,
    // interleaved reps) the bomb grew ~0.31 GB/s and the 10 s deadline won
    // (peak 3,119,976,448); re-running the harness itself under the exact
    // ablation budgets on a quieter box (2026-11-22) fired memory at 4.3 s
    // (peak 3,236,614,144). The containment invariant is what this
    // regression pins: the supervisor terminates the run, no process
    // survives, no breach. s2 (memory) and s3 (deadline) keep exact-reason
    // assertions because their outcomes are structural, not raced.
    const result = await service.run({
      targetPath: binaryOf("s1"),
      sessionTimeoutMs: 8_000,
      deadlineMs: 10_000,
      evidencePath: join(temp, "s1.evidence.json"),
    });
    if (!result.ok) throw result.error;
    expect(result.value.status).toBe("terminated");
    expect(["deadline", "memory"]).toContain(result.value.supervisor.reason);
    const evidence = parseEvidence(
      JSON.parse(await readFile(join(temp, "s1.evidence.json"), "utf8")),
    ) as Evidence;
    const nr = evidence.normalized_result as {
      execution: {
        containment: {
          verified: boolean;
          source: string;
          breach: boolean | null;
          survivors_after: string[];
          reaped_descendants: string[];
        };
      };
    };
    // Whichever supervisor limit fires, the verdict comes from the
    // worker's subreaper accounting: the bomb's paused children are the
    // accounted descendants, all reaped by the verdict, none surviving.
    expect(nr.execution.containment.verified).toBe(true);
    expect(nr.execution.containment.source).toBe("subreaper_accounting");
    expect(nr.execution.containment.breach).toBe(false);
    expect(nr.execution.containment.survivors_after).toEqual([]);
    expect(nr.execution.containment.reaped_descendants).toEqual([
      binaryOf("s1"),
    ]);
    // The service is healthy for a subsequent run.
    const after = await service.run({
      targetPath: binaryOf("a1"),
      evidencePath: join(temp, "a1.evidence.json"),
    });
    if (!after.ok) throw after.error;
    expect(after.value.status).toBe("complete");
  }, 180_000);

  it("s2 memory hog ends at the supervisor memory cap", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-eval-s2-");
    const result = await runDynamicExecutionCommand({
      targetPath: binaryOf("s2"),
      sessionTimeoutMs: 25_000,
      deadlineMs: 30_000,
      evidencePath: join(temp, "s2.evidence.json"),
    });
    if (!result.ok) throw result.error;
    expect(result.value.status).toBe("terminated");
    expect(result.value.supervisor.reason).toBe("memory");
    expect(result.value.supervisor.peak_rss_bytes).not.toBeNull();
  }, 180_000);

  it("s3 setsid escapee is reaped by the cascade: deadline, no survivors, no breach", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-eval-s3-");
    const evidencePath = join(temp, "s3.evidence.json");
    const result = await runDynamicExecutionCommand({
      targetPath: binaryOf("s3"),
      sessionTimeoutMs: 3_000,
      deadlineMs: 9_000,
      evidencePath,
    });
    if (!result.ok) throw result.error;
    expect(result.value.status).toBe("terminated");
    expect(result.value.supervisor.reason).toBe("deadline");
    const evidence = parseEvidence(
      JSON.parse(await readFile(evidencePath, "utf8")),
    ) as Evidence;
    const nr = evidence.normalized_result as {
      execution: {
        containment: {
          verified: boolean;
          source: string;
          breach: boolean | null;
          survivors_after: string[];
          reaped_descendants: string[];
        };
      };
      output: { stdout: string };
    };
    expect(nr.execution.containment).toEqual({
      verified: true,
      source: "subreaper_accounting",
      breach: false,
      survivors_after: [],
      // The escapee pauses in the target's own image; the subreaper
      // accounting names it as a reaped descendant.
      reaped_descendants: [binaryOf("s3")],
    });
    expect(nr.output.stdout).toContain("escapee-spawned");
  }, 180_000);

  it("s4 different-image escapee is reaped only through the subreaper: deadline, no survivors, no breach", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-eval-s4-");
    const evidencePath = join(temp, "s4.evidence.json");
    const result = await runDynamicExecutionCommand({
      targetPath: binaryOf("s4"),
      sessionTimeoutMs: 3_000,
      deadlineMs: 9_000,
      evidencePath,
    });
    if (!result.ok) throw result.error;
    expect(result.value.status).toBe("terminated");
    expect(result.value.supervisor.reason).toBe("deadline");
    const evidence = parseEvidence(
      JSON.parse(await readFile(evidencePath, "utf8")),
    ) as Evidence;
    const nr = evidence.normalized_result as {
      execution: {
        containment: {
          verified: boolean;
          source: string;
          breach: boolean | null;
          survivors_after: string[];
          reaped_descendants: string[];
        };
      };
      output: { stdout: string };
    };
    expect(nr.execution.containment.verified).toBe(true);
    expect(nr.execution.containment.source).toBe("subreaper_accounting");
    expect(nr.execution.containment.breach).toBe(false);
    expect(nr.execution.containment.survivors_after).toEqual([]);
    // The verdict is sourced from the worker's subreaper accounting, and
    // the accounting names the reaped escapee by the image it exec'd —
    // the fact a target-exe scan could never produce for this fixture.
    expect(
      nr.execution.containment.reaped_descendants.some((exe) =>
        exe.endsWith("/sleep"),
      ),
    ).toBe(true);
    expect(nr.output.stdout).toContain("escapee-spawned");
    // Verify independently at the host level: the fixture's escapee runs
    // /bin/sleep with a distinctive duration, so scan /proc cmdlines for
    // exactly that invocation. This is the assertion that makes the
    // subreaper load-bearing: with the shim dropped from the chain, the
    // orphaned escapee reparents to the host init instead of the worker,
    // no cascade layer can see it, and this scan finds it alive.
    const escapees = s4EscapeePids();
    try {
      expect(escapees).toEqual([]);
    } finally {
      // Never leak a live escapee into the host, even on failure.
      for (const pid of escapees) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // Already gone.
        }
      }
    }
    // The service is healthy for a subsequent run.
    const after = await runDynamicExecutionCommand({
      targetPath: binaryOf("a1"),
      evidencePath: join(temp, "a1.evidence.json"),
    });
    if (!after.ok) throw after.error;
    expect(after.value.status).toBe("complete");
  }, 180_000);
});

describe("dynamic worker binding states (stubbed module resolution)", () => {
  const writeStubRig = async (
    dir: string,
    stub: { packageJson: object; index: string },
  ): Promise<{ jobPath: string; resultPath: string }> => {
    await mkdir(join(dir, "stub-pkg"), { recursive: true });
    await writeFile(
      join(dir, "stub-pkg", "package.json"),
      JSON.stringify(stub.packageJson),
    );
    await writeFile(join(dir, "stub-pkg", "index.mjs"), stub.index);
    await writeFile(
      join(dir, "hooks.mjs"),
      `export async function resolve(specifier, context, next) {
  if (specifier === "frida")
    return {
      url: new URL("./stub-pkg/index.mjs", import.meta.url).href,
      shortCircuit: true,
    };
  return next(specifier, context);
}
`,
    );
    await writeFile(
      join(dir, "init.mjs"),
      `import { register } from "node:module";
register("./hooks.mjs", import.meta.url);
`,
    );
    const resultPath = join(dir, "result.json");
    const jobPath = join(dir, "job.json");
    await writeFile(
      jobPath,
      JSON.stringify({
        program: "/bin/true",
        argv: [],
        env_set: {},
        cwd: dir,
        session_timeout_ms: 5_000,
        result_path: resultPath,
      }),
    );
    return { jobPath, resultPath };
  };

  const runWorkerWithRig = async (dir: string, jobPath: string) =>
    run(process.execPath, [
      "--import",
      join(dir, "init.mjs"),
      workerPath,
      jobPath,
    ]);

  it("reports unavailable with the real cause when the binding fails to load", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-worker-absent-");
    const { jobPath, resultPath } = await writeStubRig(temp, {
      packageJson: { name: "frida", version: "17.23.2", type: "module" },
      index: `throw new Error("stub binding exploded");\n`,
    });
    await runWorkerWithRig(temp, jobPath);
    const result = JSON.parse(await readFile(resultPath, "utf8")) as {
      status: string;
      failure_reason: string | null;
    };
    expect(result.status).toBe("unavailable");
    expect(result.failure_reason).toContain("stub binding exploded");
  }, 60_000);

  it("refuses a binding from an untested major line, naming both versions", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-worker-skew-");
    const { jobPath, resultPath } = await writeStubRig(temp, {
      packageJson: {
        name: "frida",
        version: "18.2.0",
        type: "module",
        main: "index.mjs",
        exports: { ".": "./index.mjs" },
      },
      index: `export default {};\n`,
    });
    await runWorkerWithRig(temp, jobPath);
    const result = JSON.parse(await readFile(resultPath, "utf8")) as {
      status: string;
      failure_reason: string | null;
      frida_version: string | null;
    };
    expect(result.status).toBe("version_skew");
    expect(result.frida_version).toBe("18.2.0");
    expect(result.failure_reason).toContain("18.2.0");
    expect(result.failure_reason).toContain("17");
  }, 60_000);
});
