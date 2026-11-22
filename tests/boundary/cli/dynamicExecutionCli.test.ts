import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { beforeAll, expect } from "vitest";

import { parseEvidence } from "../../../src/domain/evidence.js";
import {
  buildFixtures,
  FIXTURES_ROOT,
} from "../../../scripts/ablation/buildFixtures.mjs";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const binaryOf = (id: string): string => join(FIXTURES_ROOT, "bin", id, id);
const sha256Of = (path: string): string =>
  createHash("sha256").update(readFileSync(path)).digest("hex");

beforeAll(() => {
  buildFixtures();
}, 300_000);

cliTest(
  "execute-dynamically runs a1 and writes Evidence whose runtime string row matches truth",
  async ({ cli }) => {
    const temp = await createTestTempDirectory("rea-dynexec-cli-a1-");
    const evidencePath = join(temp, "a1.evidence.json");
    const result = await cli.run({
      arguments: [
        "execute-dynamically",
        binaryOf("a1"),
        evidencePath,
        "--json",
      ],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const outcome = result.json as {
      status: string;
      provider_state: string;
      evidence_id: string;
      counts: { strings: number; modules: number; symbols: number };
      supervisor: { reason: string };
      limitations: string[];
    };
    expect(outcome.status).toBe("complete");
    expect(outcome.provider_state).toBe("ready");
    expect(outcome.evidence_id).toMatch(/^ev_[a-f0-9]{64}$/u);
    expect(outcome.counts).toEqual({ strings: 1, modules: 0, symbols: 0 });
    expect(outcome.supervisor.reason).toBe("exited");
    expect(outcome.limitations).toEqual([]);

    const evidence = parseEvidence(
      JSON.parse(await readFile(evidencePath, "utf8")),
    );
    expect(evidence.evidence_id).toBe(outcome.evidence_id);
    expect(evidence.subject?.digest.sha256).toBe(sha256Of(binaryOf("a1")));
    const nr = evidence.normalized_result as {
      strings: unknown;
      output: { stdout: string };
      execution: { hook_pack_version: string; frida_version: string };
    };
    expect(nr.strings).toEqual([
      { value: "alpha-secret-one", channel: "puts" },
    ]);
    expect(nr.output.stdout).toBe("MARK:main\nMARK:reveal\nalpha-secret-one\n");
    expect(nr.execution.hook_pack_version).toBe("1.1.0");
    expect(nr.execution.frida_version).toBe("17.23.2");
  },
);

cliTest(
  "execute-dynamically passes stimulus argv through to the target (c1 dispatch)",
  async ({ cli }) => {
    const temp = await createTestTempDirectory("rea-dynexec-cli-c1-");
    const evidencePath = join(temp, "c1.evidence.json");
    const result = await cli.run({
      arguments: [
        "execute-dynamically",
        binaryOf("c1"),
        evidencePath,
        "--argument",
        "2",
      ],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = parseEvidence(
      JSON.parse(await readFile(evidencePath, "utf8")),
    );
    const nr = evidence.normalized_result as {
      output: { stdout: string };
    };
    expect(nr.output.stdout).toContain("result-mul");
    expect(nr.output.stdout).not.toContain("result-add");
  },
);

cliTest(
  "execute-dynamically fails closed for a missing target and writes no Evidence",
  async ({ cli }) => {
    const temp = await createTestTempDirectory("rea-dynexec-cli-missing-");
    const evidencePath = join(temp, "none.evidence.json");
    const result = await cli.run({
      arguments: [
        "execute-dynamically",
        join(temp, "no-such-binary"),
        evidencePath,
        "--json",
      ],
    });
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain('"error"');
    await expect(readFile(evidencePath, "utf8")).rejects.toThrow();
  },
);
