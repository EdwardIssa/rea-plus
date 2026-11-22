import { createHash } from "node:crypto";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import {
  parseClaimCheckLedger,
  resolveClaimCheckStates,
} from "../../domain/claimCheck/claimCheckLedger.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { runClaimCheck } from "./runClaimCheck.js";
import { buildSyntheticElf, SYNTHETIC_ELF } from "./syntheticElf.fixture.js";

const provider = { id: "ghidra", name: "Ghidra", version: "12.1.4" };

const stringRow = (
  address: string,
  value: string,
  byteLength = value.length + 1,
  termination:
    | "missing"
    | "present_or_not_required" = "present_or_not_required",
) => ({
  address,
  value,
  string: {
    encoding: "utf-8",
    encoding_status: "observed",
    termination,
    byte_length: byteLength,
  },
});

const setup = async (): Promise<{
  root: string;
  artifactPath: string;
  sha256: string;
}> => {
  const root = await mkdtemp(join(tmpdir(), "rea-claim-check-run-"));
  const artifactPath = join(root, "fixture.elf");
  const { bytes, sha256 } = buildSyntheticElf();
  await writeFile(artifactPath, bytes);
  return { root, artifactPath, sha256 };
};

const evidenceFor = (
  sha256: string,
  rows: readonly unknown[],
  options: { format?: string; links?: readonly string[] } = {},
): Evidence =>
  createEvidence(
    {
      path: "/fixtures/artifact",
      sha256,
      format: (options.format ?? "elf") as "elf",
    },
    provider,
    {
      operation: "list_strings",
      parameters: {},
      result: rows,
      evidenceLinks: options.links ?? [],
    },
  );

// oxlint-disable-next-line max-lines-per-function -- the end-to-end run cases share one synthetic ELF fixture.
describe("claim-check run", () => {
  it("adjudicates a mixed claim set and commits a verifiable ledger", async () => {
    const { root, artifactPath, sha256 } = await setup();
    try {
      const evidence = evidenceFor(sha256, [
        stringRow(SYNTHETIC_ELF.alpha.address, SYNTHETIC_ELF.alpha.value),
        stringRow(SYNTHETIC_ELF.alpha.address, "alpha-strinh"),
        stringRow(
          SYNTHETIC_ELF.raw.address,
          SYNTHETIC_ELF.raw.value,
          SYNTHETIC_ELF.raw.byteLength,
          "missing",
        ),
        stringRow(SYNTHETIC_ELF.gapAddress, "gap-string"),
        stringRow(SYNTHETIC_ELF.beyondAddress, "beyond-string"),
      ]);
      const ledgerPath = join(root, "ledger.json");
      const result = await runClaimCheck({
        evidence: [evidence],
        artifactPath,
        ledgerPath,
      });
      if (!result.ok) throw result.error;
      expect(result.value.counts).toEqual({
        supported: 2,
        refuted: 1,
        unknown: 2,
      });
      expect(result.value.claims_considered).toBe(5);
      expect(result.value.report_digest).toMatch(/^[a-f0-9]{64}$/u);
      const written = parseClaimCheckLedger(
        JSON.parse(await readFile(ledgerPath, "utf8")),
      );
      expect(written).toEqual(result.value.ledger);
      const reasons = new Map(
        written.entries
          .filter((entry) => entry.kind === "adjudication")
          .map((entry) => [entry.claim_id, entry.reason]),
      );
      expect([...reasons.values()]).toContain("address_unmapped");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("is deterministic: two runs produce identical report digests", async () => {
    const { root, artifactPath, sha256 } = await setup();
    try {
      const evidence = evidenceFor(sha256, [
        stringRow(SYNTHETIC_ELF.alpha.address, SYNTHETIC_ELF.alpha.value),
        stringRow(SYNTHETIC_ELF.beta.address, SYNTHETIC_ELF.beta.value),
      ]);
      const first = await runClaimCheck({ evidence: [evidence], artifactPath });
      const second = await runClaimCheck({
        evidence: [evidence],
        artifactPath,
      });
      if (!first.ok) throw first.error;
      if (!second.ok) throw second.error;
      expect(second.value.report_digest).toBe(first.value.report_digest);
      expect(second.value.ledger.ledger_id).toBe(first.value.ledger.ledger_id);
      expect(JSON.stringify(second.value.ledger)).toBe(
        JSON.stringify(first.value.ledger),
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("aborts before any verdict when the artifact digest differs", async () => {
    const { root, sha256 } = await setup();
    try {
      const evidence = evidenceFor(sha256, [
        stringRow(SYNTHETIC_ELF.alpha.address, SYNTHETIC_ELF.alpha.value),
      ]);
      const otherPath = join(root, "other.elf");
      const tampered = Buffer.from(buildSyntheticElf().bytes);
      tampered[0x800] = 0x5a;
      await writeFile(otherPath, tampered);
      const ledgerPath = join(root, "ledger.json");
      const result = await runClaimCheck({
        evidence: [evidence],
        artifactPath: otherPath,
        ledgerPath,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBeInstanceOf(AnalysisInputError);
        expect(
          (result.error as AnalysisInputError).issues[0]?.message,
        ).toContain("artifact_digest_mismatch");
      }
      await expect(access(ledgerPath)).rejects.toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("aborts when the artifact is missing", async () => {
    const { root, sha256 } = await setup();
    try {
      const evidence = evidenceFor(sha256, [
        stringRow(SYNTHETIC_ELF.alpha.address, SYNTHETIC_ELF.alpha.value),
      ]);
      const result = await runClaimCheck({
        evidence: [evidence],
        artifactPath: join(root, "absent.elf"),
      });
      expect(result.ok).toBe(false);
      if (!result.ok)
        expect(
          (result.error as AnalysisInputError).issues[0]?.message,
        ).toContain("artifact_missing");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("refuses Evidence whose semantic identifier does not authenticate", async () => {
    const { root, artifactPath, sha256 } = await setup();
    try {
      const evidence = evidenceFor(sha256, [
        stringRow(SYNTHETIC_ELF.alpha.address, SYNTHETIC_ELF.alpha.value),
      ]);
      const tampered = JSON.parse(JSON.stringify(evidence)) as {
        normalized_result: { value: string }[];
      };
      tampered.normalized_result[0]!.value = "alpha-strinh";
      const result = await runClaimCheck({
        evidence: [tampered],
        artifactPath,
      });
      expect(result.ok).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("adjudicates every Mach-O claim unknown with the format reason", async () => {
    const root = await mkdtemp(join(tmpdir(), "rea-claim-check-macho-"));
    try {
      const macho = Buffer.alloc(64);
      macho.writeUInt32LE(0xfeedfacf, 0);
      const sha256 = createHash("sha256").update(macho).digest("hex");
      const artifactPath = join(root, "fixture.macho");
      await writeFile(artifactPath, macho);
      const evidence = evidenceFor(sha256, [stringRow("0x1000", "hello")], {
        format: "mach-o",
      });
      const result = await runClaimCheck({
        evidence: [evidence],
        artifactPath,
      });
      if (!result.ok) throw result.error;
      expect(result.value.counts).toEqual({
        supported: 0,
        refuted: 0,
        unknown: 1,
      });
      const adjudication = result.value.ledger.entries[0];
      expect(adjudication).toMatchObject({
        kind: "adjudication",
        state: "unknown",
        reason: "format_not_supported",
        label: "unverified",
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("cascades stale marks from a refuted claim to its dependents", async () => {
    const { root, artifactPath, sha256 } = await setup();
    try {
      const first = evidenceFor(sha256, [
        stringRow(SYNTHETIC_ELF.alpha.address, "alpha-strinh"),
      ]);
      const second = createEvidence(
        { path: "/fixtures/artifact", sha256, format: "elf" },
        provider,
        {
          operation: "search_strings",
          parameters: {},
          result: [
            stringRow(SYNTHETIC_ELF.beta.address, SYNTHETIC_ELF.beta.value),
          ],
          evidenceLinks: [first.evidence_id],
        },
      );
      const result = await runClaimCheck({
        evidence: [first, second],
        artifactPath,
      });
      if (!result.ok) throw result.error;
      expect(result.value.counts).toEqual({
        supported: 1,
        refuted: 1,
        unknown: 0,
      });
      expect(result.value.stale_marked).toBe(1);
      const resolved = resolveClaimCheckStates(result.value.ledger);
      const states = [...resolved.values()];
      expect(states).toContainEqual(
        expect.objectContaining({ state: "supported", stale: true }),
      );
      expect(states).toContainEqual(
        expect.objectContaining({ state: "refuted", stale: false }),
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("never supports a claim whose location or value was corrupted", async () => {
    const { root, artifactPath, sha256 } = await setup();
    try {
      const evidence = evidenceFor(sha256, [
        stringRow("0x400801", SYNTHETIC_ELF.alpha.value),
        stringRow(SYNTHETIC_ELF.alpha.address, "alpha-string!"),
      ]);
      const result = await runClaimCheck({
        evidence: [evidence],
        artifactPath,
      });
      if (!result.ok) throw result.error;
      expect(result.value.counts.supported).toBe(0);
      expect(result.value.counts.refuted).toBe(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
