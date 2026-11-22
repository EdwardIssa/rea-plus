import { describe, expect, it } from "vitest";

import {
  buildStringClaim,
  claimRecordSchema,
  type ClaimRecord,
  type StringClaimSource,
} from "./claimRecord.js";
import {
  claimCheckLedgerCompleteness,
  createClaimCheckLedgerWriter,
  parseClaimCheckLedger,
  resolveClaimCheckStates,
  type ClaimCheckLedgerWriter,
} from "./claimCheckLedger.js";
import {
  STRING_CLAIM_VALIDATOR,
  type StringClaimVerdict,
} from "./stringClaimValidator.js";

const SHA = "a".repeat(64);
const EVIDENCE_ID = `ev_${"b".repeat(64)}`;

const source: StringClaimSource = {
  subjectSha256: SHA,
  subjectFormat: "elf",
  evidenceId: EVIDENCE_ID,
  providerId: "ghidra",
  providerVersion: "12.1.4",
  operation: "list_strings",
};

const claimAt = (
  address: string,
  value: string,
  dependencies: readonly string[] = [],
): ClaimRecord => {
  const claim = buildStringClaim(
    {
      address,
      value,
      string: {
        encoding: "utf-8",
        encoding_status: "observed",
        termination: "present_or_not_required",
        byte_length: value.length + 1,
      },
    },
    source,
  );
  return dependencies.length === 0
    ? claim
    : claimRecordSchema.parse({ ...claim, dependencies: [...dependencies] });
};

const supported: StringClaimVerdict = {
  state: "supported",
  reason: "bytes_match",
  observed: { bytes_digest: "c".repeat(64), byte_length: 6 },
};
const refuted: StringClaimVerdict = {
  state: "refuted",
  reason: "bytes_mismatch",
  observed: { bytes_digest: "d".repeat(64), byte_length: 6 },
};

const writerFor = (claims: readonly ClaimRecord[]): ClaimCheckLedgerWriter =>
  createClaimCheckLedgerWriter({
    subject: { sha256: SHA, format: "elf" },
    claims,
    validator: STRING_CLAIM_VALIDATOR,
  });

describe("claim-check ledger writer", () => {
  it("commits a hash-chained ledger whose parse verifies end to end", () => {
    const claim = claimAt("0x1000", "hello");
    const writer = writerFor([claim]);
    expect(writer.appendAdjudication(claim, supported)).toBe(true);
    const ledger = writer.commitRun([EVIDENCE_ID]);

    expect(ledger.summary).toMatchObject({
      entries: 2,
      adjudications: 1,
      stale_marks: 0,
      runs: 1,
      supported: 1,
      complete: true,
    });
    expect(claimCheckLedgerCompleteness(ledger)).toBe("complete");
    const commit = ledger.entries[1];
    if (commit?.kind !== "run-commit") throw new Error("expected run-commit");
    expect(commit.signature).toBe(commit.report_digest);
    expect(commit.signer.producer).toBe("rea-claim-check");
    // Round-trip through JSON: parse verifies chain, digests, and summary.
    expect(parseClaimCheckLedger(JSON.parse(JSON.stringify(ledger)))).toEqual(
      ledger,
    );
  });

  it("reports a ledger without a run commit as an incomplete run", () => {
    const claim = claimAt("0x1000", "hello");
    const writer = writerFor([claim]);
    writer.appendAdjudication(claim, supported);
    const incomplete = writer.incompleteLedger();
    expect(incomplete.summary.complete).toBe(false);
    expect(claimCheckLedgerCompleteness(incomplete)).toBe("incomplete");
    expect(parseClaimCheckLedger(incomplete).summary.runs).toBe(0);
  });

  it("treats a duplicate presentation in one run as a no-op", () => {
    const claim = claimAt("0x1000", "hello");
    const writer = writerFor([claim]);
    expect(writer.appendAdjudication(claim, supported)).toBe(true);
    expect(writer.appendAdjudication(claim, refuted)).toBe(false);
    const ledger = writer.commitRun([EVIDENCE_ID]);
    expect(ledger.summary.adjudications).toBe(1);
    expect(ledger.summary.supported).toBe(1);
    expect(ledger.summary.refuted).toBe(0);
  });

  it("cascades a stale mark to dependents without changing their state", () => {
    const parent = claimAt("0x1000", "hello");
    const dependent = claimAt("0x2000", "world", [parent.claim_id]);
    const writer = writerFor([parent, dependent]);
    writer.appendAdjudication(dependent, supported);
    writer.appendAdjudication(parent, refuted);
    const ledger = writer.commitRun([EVIDENCE_ID]);

    expect(ledger.summary.stale_marks).toBe(1);
    const mark = ledger.entries.find((entry) => entry.kind === "stale-mark");
    if (mark?.kind !== "stale-mark") throw new Error("expected stale mark");
    expect(mark.claim_id).toBe(dependent.claim_id);
    expect(mark.cause_claim_id).toBe(parent.claim_id);

    const resolved = resolveClaimCheckStates(ledger);
    expect(resolved.get(dependent.claim_id)).toMatchObject({
      state: "supported",
      stale: true,
    });
    expect(resolved.get(parent.claim_id)).toMatchObject({
      state: "refuted",
      stale: false,
    });
  });

  it("appends no marks when a refuted claim has no dependents", () => {
    const claim = claimAt("0x1000", "hello");
    const writer = writerFor([claim]);
    writer.appendAdjudication(claim, refuted);
    const ledger = writer.commitRun([EVIDENCE_ID]);
    expect(ledger.summary.stale_marks).toBe(0);
  });

  it("resolves a stale-marked claim as unstaled after a fresh adjudication", () => {
    const parent = claimAt("0x1000", "hello");
    const dependentV1 = claimAt("0x2000", "world", [parent.claim_id]);
    const dependentV2 = claimAt("0x2000", "worle", [parent.claim_id]);
    const writer = writerFor([parent, dependentV1, dependentV2]);
    writer.appendAdjudication(dependentV1, supported);
    writer.appendAdjudication(parent, refuted);
    writer.appendAdjudication(dependentV2, refuted);
    const ledger = writer.commitRun([EVIDENCE_ID]);

    const resolved = resolveClaimCheckStates(ledger);
    expect(resolved.get(dependentV1.claim_id)).toMatchObject({
      claim_version: dependentV2.claim_version,
      state: "refuted",
      stale: false,
    });
  });

  it("rejects a ledger whose middle record was altered by one byte", () => {
    const first = claimAt("0x1000", "hello");
    const second = claimAt("0x2000", "world");
    const writer = writerFor([first, second]);
    writer.appendAdjudication(first, supported);
    writer.appendAdjudication(second, supported);
    const ledger = writer.commitRun([EVIDENCE_ID]);

    const serialized = JSON.stringify(ledger);
    // Flip the middle record (the second adjudication): change its reason
    // text. The record digest no longer matches its content, so chain
    // verification must reject the ledger at parse time.
    const firstAt = serialized.indexOf('"bytes_match"');
    const middleAt = serialized.indexOf('"bytes_match"', firstAt + 1);
    expect(middleAt).toBeGreaterThan(firstAt);
    const tampered =
      serialized.slice(0, middleAt) +
      '"bytes_mismatch"' +
      serialized.slice(middleAt + '"bytes_match"'.length);
    expect(() => parseClaimCheckLedger(JSON.parse(tampered))).toThrow();
  });

  it("refuses claims for a different subject and appends after commit", () => {
    const claim = claimAt("0x1000", "hello");
    expect(() =>
      createClaimCheckLedgerWriter({
        subject: { sha256: "e".repeat(64), format: "elf" },
        claims: [claim],
        validator: STRING_CLAIM_VALIDATOR,
      }),
    ).toThrow(/different subject/u);
    const writer = writerFor([claim]);
    writer.commitRun([EVIDENCE_ID]);
    expect(() => writer.appendAdjudication(claim, supported)).toThrow(
      /committed/u,
    );
    expect(() => writer.commitRun([EVIDENCE_ID])).toThrow(/already committed/u);
  });
});
