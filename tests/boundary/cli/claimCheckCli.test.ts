import { createHash } from "node:crypto";
import { access, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { parseClaimCheckLedger } from "../../../src/domain/claimCheck/claimCheckLedger.js";
import {
  buildClaimCheckReport,
  type ClaimCheckOutcome,
} from "../../../src/domain/claimCheck/claimCheckReport.js";
import { STRING_CLAIM_VALIDATOR } from "../../../src/domain/claimCheck/stringClaimValidator.js";
import { createEvidence } from "../../../src/domain/evidence.js";
import {
  buildClaimCheckFixture,
  fixtureStringRow,
  type ClaimCheckFixture,
} from "../../fixtures/claimCheck/claimCheckFixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

let fixturePromise: Promise<ClaimCheckFixture> | undefined;
const fixture = (): Promise<ClaimCheckFixture> =>
  (fixturePromise ??= buildClaimCheckFixture());

const provider = { id: "ghidra", name: "Ghidra", version: "12.1.4" };

const writeEvidence = async (
  root: string,
  name: string,
  sha256: string,
  rows: readonly unknown[],
  format: "elf" | "mach-o" = "elf",
): Promise<string> => {
  const record = createEvidence(
    { path: "/fixtures/artifact", sha256, format },
    provider,
    { operation: "list_strings", parameters: {}, result: rows },
  );
  const path = join(root, name);
  await writeFile(path, JSON.stringify(record));
  return path;
};

const truthOutcomes = (
  ledgerPath: string,
): Promise<readonly ClaimCheckOutcome[]> =>
  readFile(ledgerPath, "utf8").then((text) => {
    const ledger = parseClaimCheckLedger(JSON.parse(text));
    return ledger.entries
      .filter((entry) => entry.kind === "adjudication")
      .map((entry) => ({
        claim_id: entry.claim_id,
        claim_version: entry.claim_version,
        state: entry.state,
        reason: entry.reason,
      }));
  });

cliTest(
  "claim-check adjudicates the known-supported set on unstripped and stripped fixtures",
  async ({ cli }) => {
    const f = await fixture();
    for (const binary of [
      { path: f.unstrippedPath, sha256: f.unstrippedSha256 },
      { path: f.strippedPath, sha256: f.strippedSha256 },
    ]) {
      const root = await createTestTempDirectory("rea-claim-check-cli-");
      const evidencePath = await writeEvidence(
        root,
        "evidence.json",
        binary.sha256,
        f.strings.map((entry) => fixtureStringRow(entry)),
      );
      const ledgerPath = join(root, "ledger.json");
      const result = await cli.run({
        arguments: [
          "claim-check",
          evidencePath,
          binary.path,
          ledgerPath,
          "--json",
        ],
      });
      expect(result.exitCode, result.stderr).toBe(0);
      const outcome = result.json as {
        counts: { supported: number; refuted: number; unknown: number };
        report_digest: string;
      };
      expect(outcome.counts).toEqual({ supported: 3, refuted: 0, unknown: 0 });
      const outcomes = await truthOutcomes(ledgerPath);
      const report = buildClaimCheckReport({
        validator: STRING_CLAIM_VALIDATOR,
        truthSetId: "claim-fixture-truth",
        outcomes: outcomes.map((entry) => ({
          ...entry,
          truth_state: "supported" as const,
        })),
      });
      expect(report.precision).toBe(1);
      expect(report.coverage).toBe(1);
    }
  },
);

cliTest(
  "claim-check adjudicates the known-refuted set as refuted and none supported",
  async ({ cli }) => {
    const f = await fixture();
    const root = await createTestTempDirectory("rea-claim-check-cli-");
    const [greeting, unterminated, tail] = f.strings;
    const shifted = `0x${(BigInt(greeting!.address) + 1n).toString(16)}`;
    const rows = [
      fixtureStringRow(greeting!, { value: `X${greeting!.value.slice(1)}` }),
      fixtureStringRow(unterminated!, {
        byteLength: unterminated!.byteLength + 1,
      }),
      fixtureStringRow(tail!, { byteLength: tail!.byteLength - 1 }),
      fixtureStringRow(greeting!, { address: shifted }),
    ];
    const evidencePath = await writeEvidence(
      root,
      "evidence.json",
      f.unstrippedSha256,
      rows,
    );
    const ledgerPath = join(root, "ledger.json");
    const result = await cli.run({
      arguments: [
        "claim-check",
        evidencePath,
        f.unstrippedPath,
        ledgerPath,
        "--json",
      ],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const outcome = result.json as {
      counts: { supported: number; refuted: number; unknown: number };
    };
    expect(outcome.counts.supported).toBe(0);
    expect(outcome.counts).toEqual({ supported: 0, refuted: 4, unknown: 0 });
    const outcomes = await truthOutcomes(ledgerPath);
    const report = buildClaimCheckReport({
      validator: STRING_CLAIM_VALIDATOR,
      truthSetId: "claim-fixture-refuted",
      outcomes: outcomes.map((entry) => ({
        ...entry,
        truth_state: "refuted" as const,
      })),
    });
    // No supported verdicts at all: precision is vacuous, and the gate's
    // hard requirement (zero supported on refuted truth) is asserted above.
    expect(report.precision).toBeNull();
  },
);

cliTest(
  "claim-check adjudicates gap, beyond-segment, and Mach-O claims as unknown",
  async ({ cli }) => {
    const f = await fixture();
    const root = await createTestTempDirectory("rea-claim-check-cli-");
    const unknownRow = (address: string) => ({
      address,
      value: "not-present",
      string: {
        encoding: "utf-8",
        encoding_status: "observed",
        termination: "present_or_not_required",
        byte_length: 12,
      },
    });
    const evidencePath = await writeEvidence(
      root,
      "evidence.json",
      f.unstrippedSha256,
      [unknownRow(f.gapAddress), unknownRow(f.beyondAddress)],
    );
    const ledgerPath = join(root, "ledger.json");
    const result = await cli.run({
      arguments: [
        "claim-check",
        evidencePath,
        f.unstrippedPath,
        ledgerPath,
        "--json",
      ],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    expect((result.json as { counts: unknown }).counts).toEqual({
      supported: 0,
      refuted: 0,
      unknown: 2,
    });
    const outcomes = await truthOutcomes(ledgerPath);
    expect(outcomes.map((entry) => entry.reason)).toEqual([
      "address_unmapped",
      "address_unmapped",
    ]);

    const macho = Buffer.alloc(64);
    macho.writeUInt32LE(0xfeedfacf, 0);
    const machoPath = join(root, "fixture.macho");
    await writeFile(machoPath, macho);
    const machoSha = createHash("sha256").update(macho).digest("hex");
    const machoEvidence = await writeEvidence(
      root,
      "macho-evidence.json",
      machoSha,
      [unknownRow("0x1000")],
      "mach-o",
    );
    const machoLedger = join(root, "macho-ledger.json");
    const machoResult = await cli.run({
      arguments: [
        "claim-check",
        machoEvidence,
        machoPath,
        machoLedger,
        "--json",
      ],
    });
    expect(machoResult.exitCode, machoResult.stderr).toBe(0);
    const machoOutcomes = await truthOutcomes(machoLedger);
    expect(machoOutcomes).toHaveLength(1);
    expect(machoOutcomes[0]).toMatchObject({
      state: "unknown",
      reason: "format_not_supported",
    });
  },
);

cliTest(
  "claim-check is deterministic across runs and aborts on digest mismatch",
  async ({ cli }) => {
    const f = await fixture();
    const root = await createTestTempDirectory("rea-claim-check-cli-");
    const evidencePath = await writeEvidence(
      root,
      "evidence.json",
      f.unstrippedSha256,
      f.strings.map((entry) => fixtureStringRow(entry)),
    );
    const runOnce = async (ledgerName: string, artifact: string) =>
      cli.run({
        arguments: [
          "claim-check",
          evidencePath,
          artifact,
          join(root, ledgerName),
          "--json",
        ],
      });
    const first = await runOnce("ledger-a.json", f.unstrippedPath);
    const second = await runOnce("ledger-b.json", f.unstrippedPath);
    expect(first.exitCode, first.stderr).toBe(0);
    expect(second.exitCode, second.stderr).toBe(0);
    expect((second.json as { report_digest: string }).report_digest).toBe(
      (first.json as { report_digest: string }).report_digest,
    );
    // The Evidence names the unstripped digest; the stripped artifact must
    // abort the run before any verdict or ledger write.
    const mismatched = await runOnce("ledger-c.json", f.strippedPath);
    expect(mismatched.exitCode).toBe(1);
    expect(mismatched.stdout).toContain("artifact_digest_mismatch");
    await expect(access(join(root, "ledger-c.json"))).rejects.toThrow();
  },
);
