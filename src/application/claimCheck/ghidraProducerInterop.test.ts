import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { parseEvidence, type Evidence } from "../../domain/evidence.js";
import { deriveClaimRelocations } from "./deriveClaimRelocations.js";
import { parseClaimAddressCoordinate } from "./elfBytePort.js";
import { extractStringClaims } from "./extractStringClaims.js";
import { runClaimCheck } from "./runClaimCheck.js";

/**
 * Regression fixture from REAL producer output: the Evidence pair a live
 * Ghidra 12.1.4 session emitted for the standing gcc fixture `fixture_basic`
 * (sha256 ac8a55eb…) on 2026-11-22 — a composed `binary_overview` record
 * carrying `image_base: "0x100000"` and the `list_strings` record whose 89
 * rows previously adjudicated 0 supported / 89 unknown. The strings record
 * is byte-identical to the earlier live-proof capture (same evidence_id,
 * ev_895df553…), so this fixture pins the exact producer output that failed.
 */
const fixturePath = join(
  import.meta.dirname,
  "../../../tests/fixtures/claimCheck/ghidraFixtureBasicEvidence.json",
);

const loadRecords = async (): Promise<readonly Evidence[]> => {
  const parsed: unknown = JSON.parse(await readFile(fixturePath, "utf8"));
  if (!Array.isArray(parsed)) throw new Error("fixture is not an array");
  return parsed.map((record) => parseEvidence(record));
};

describe("Ghidra producer interop (real session Evidence)", () => {
  it("extracts all 89 claims across both producer address forms", async () => {
    const records = await loadRecords();
    const strings = records.find((r) => r.operation === "list_strings");
    if (strings === undefined) throw new Error("fixture lacks list_strings");
    const subject = strings.subject;
    if (subject === null) throw new Error("fixture record lacks a subject");
    const claims = extractStringClaims([strings]);
    expect(claims).toHaveLength(89);
    let bare = 0;
    let spaced = 0;
    for (const claim of claims) {
      const coordinate = parseClaimAddressCoordinate(claim.location.address);
      if (coordinate === undefined)
        throw new Error(
          `unparseable producer address: ${claim.location.address}`,
        );
      if (coordinate.space === null) bare += 1;
      else spaced += 1;
      // The producer's vocabulary is accepted as recorded: charset names as
      // the engine spells them, termination present_or_not_required.
      expect(["US-ASCII", "UTF-8"]).toContain(claim.assertion.encoding);
      expect(claim.assertion.termination).toBe("present_or_not_required");
    }
    expect(bare).toBe(16);
    expect(spaced).toBe(73);
  });

  it("derives the recorded image base for the string producer", async () => {
    const records = await loadRecords();
    const strings = records.find((r) => r.operation === "list_strings");
    if (strings?.subject == null) throw new Error("fixture record invalid");
    const relocations = deriveClaimRelocations(
      records,
      strings.subject.digest.sha256,
    );
    expect(relocations.get("ghidra")).toEqual({ imageBase: 0x100000n });
  });
});

// The full adjudication needs the artifact the records describe; the
// standing binary lives outside the repo (binaries are never committed),
// so this case runs where the ghidra-fixtures directory is present and
// skips, rather than fails, where it is not.
const artifactAvailable = ((): boolean => {
  try {
    const parsed: unknown = JSON.parse(readFileSync(fixturePath, "utf8"));
    if (!Array.isArray(parsed)) return false;
    const strings = parsed.find(
      (r: { operation?: string }) => r?.operation === "list_strings",
    ) as { subject?: { local_path?: string; digest?: { sha256?: string } } };
    const path = strings?.subject?.local_path;
    const sha = strings?.subject?.digest?.sha256;
    if (path === undefined || sha === undefined || !existsSync(path))
      return false;
    return (
      createHash("sha256").update(readFileSync(path)).digest("hex") === sha
    );
  } catch {
    return false;
  }
})();

describe("Ghidra producer interop (adjudication against the artifact)", () => {
  it.skipIf(!artifactAvailable)(
    "adjudicates the real record 89 supported / 0 refuted / 0 unknown",
    async () => {
      const records = await loadRecords();
      const strings = records.find((r) => r.operation === "list_strings");
      if (strings?.subject == null) throw new Error("fixture record invalid");
      const result = await runClaimCheck({
        evidence: records,
        artifactPath: strings.subject.local_path,
      });
      if (!result.ok) throw result.error;
      expect(result.value.claims_considered).toBe(89);
      expect(result.value.counts).toEqual({
        supported: 89,
        refuted: 0,
        unknown: 0,
      });
    },
  );
});
