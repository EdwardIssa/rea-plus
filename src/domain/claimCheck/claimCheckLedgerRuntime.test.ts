import { describe, expect, it } from "vitest";

import {
  createClaimCheckLedgerWriter,
  parseClaimCheckLedger,
  resolveClaimCheckStates,
} from "./claimCheckLedger.js";
import {
  buildRuntimeClaim,
  deriveStimulusDigest,
} from "./runtimeClaimRecord.js";
import {
  RUNTIME_CLAIM_VALIDATOR,
  type RuntimeClaimVerdict,
} from "./runtimeReplayValidator.js";

const SUBJECT = { sha256: "a".repeat(64), format: "elf" };
const SOURCE_ID = `ev_${"b".repeat(64)}`;
const WITNESS_ID = `ev_${"c".repeat(64)}`;

const claim = buildRuntimeClaim(
  { value: "alpha-secret-one", channel: "puts" },
  {
    subjectSha256: SUBJECT.sha256,
    subjectFormat: SUBJECT.format,
    evidenceRefs: [SOURCE_ID],
    providerId: "frida",
    providerVersion: "17.23.2",
    operation: "execute_dynamically",
    stimulusDigest: deriveStimulusDigest([], {}),
  },
);

const verdict: RuntimeClaimVerdict = {
  state: "supported",
  reason: "replay_recurred",
  observed: {
    source_evidence_ids: [SOURCE_ID],
    witness_evidence_ids: [WITNESS_ID],
    eligible_witnesses: 2,
    recurring_witnesses: 2,
    observation_digest: "d".repeat(64),
  },
};

describe("claim-check ledger with the runtime claim class", () => {
  it("appends a runtime verdict pair, commits, and round-trips through parse", () => {
    const writer = createClaimCheckLedgerWriter({
      subject: SUBJECT,
      claims: [claim],
      validator: RUNTIME_CLAIM_VALIDATOR,
    });
    expect(writer.appendAdjudication(claim, verdict)).toBe(true);
    expect(writer.appendAdjudication(claim, verdict)).toBe(false);
    const ledger = writer.commitRun([SOURCE_ID, WITNESS_ID]);
    expect(ledger.summary).toMatchObject({
      adjudications: 1,
      supported: 1,
      refuted: 0,
      unknown: 0,
      complete: true,
    });
    const entry = ledger.entries[0];
    if (entry?.kind !== "adjudication")
      throw new Error("expected adjudication");
    expect(entry.reason).toBe("replay_recurred");
    expect(entry.evidence_refs).toEqual([SOURCE_ID]);
    expect(entry.observed).toEqual(verdict.observed);
    const reparsed = parseClaimCheckLedger(JSON.parse(JSON.stringify(ledger)));
    expect(reparsed).toEqual(ledger);
    const resolved = resolveClaimCheckStates(reparsed);
    expect(resolved.get(claim.claim_id)).toMatchObject({
      state: "supported",
      reason: "replay_recurred",
      stale: false,
    });
  });

  it("refuses a runtime claim for a different subject", () => {
    const foreign = buildRuntimeClaim(
      { value: "x", channel: "puts" },
      {
        subjectSha256: "e".repeat(64),
        subjectFormat: "elf",
        evidenceRefs: [SOURCE_ID],
        providerId: "frida",
        providerVersion: "17.23.2",
        operation: "execute_dynamically",
        stimulusDigest: deriveStimulusDigest([], {}),
      },
    );
    expect(() =>
      createClaimCheckLedgerWriter({
        subject: SUBJECT,
        claims: [foreign],
        validator: RUNTIME_CLAIM_VALIDATOR,
      }),
    ).toThrow(/different subject/u);
  });
});
