import { z } from "zod";

import { digestCanonicalValue } from "../canonicalDigest.js";
import {
  compareAsciiStrings,
  isSortedUniqueAscii,
  uniqueSorted,
} from "../canonicalOrdering.js";
import { digestSchema, prefixedDigestSchema } from "../digests.js";
import type { ClaimRecord } from "./claimRecord.js";
import type { RuntimeClaimRecord } from "./runtimeClaimRecord.js";
import {
  replayObservedSchema,
  runtimeAdjudicationReasonSchema,
  type RuntimeClaimVerdict,
} from "./runtimeReplayValidator.js";
import {
  adjudicationReasonSchema,
  adjudicationStateSchema,
  type AdjudicationState,
  type StringClaimVerdict,
} from "./stringClaimValidator.js";

/**
 * The ledger's full reason vocabulary: the string class's reasons plus the
 * runtime class's. Additive — ledgers written before the runtime class
 * existed still parse, since every value they carry remains in the union.
 */
export const claimCheckReasonSchema = z.enum([
  ...adjudicationReasonSchema.options,
  ...runtimeAdjudicationReasonSchema.options,
]);
export type ClaimCheckReason = z.infer<typeof claimCheckReasonSchema>;

/** prev_digest of the first entry in every ledger. */
const GENESIS_DIGEST = "0".repeat(64);

/** Version of the ledger writer that signs run commits as rea-claim-check. */
export const CLAIM_CHECK_LEDGER_WRITER = {
  producer: "rea-claim-check",
  version: "1.0.0",
} as const;

const validatorIdentitySchema = z.strictObject({
  id: z.string().min(1),
  version: z.string().min(1),
});

const adjudicationRecordSchema = z.strictObject({
  kind: z.literal("adjudication"),
  seq: z.int().min(0),
  claim_id: prefixedDigestSchema("cc"),
  claim_version: digestSchema,
  state: adjudicationStateSchema,
  reason: claimCheckReasonSchema,
  validator: validatorIdentitySchema,
  label: z.enum(["verified-fact", "unverified"]),
  observed: z
    .union([
      z.strictObject({
        bytes_digest: digestSchema,
        byte_length: z.int().min(0),
      }),
      replayObservedSchema,
    ])
    .exactOptional(),
  evidence_refs: z.array(prefixedDigestSchema("ev")),
  prev_digest: digestSchema,
  record_digest: digestSchema,
});

const staleMarkSchema = z.strictObject({
  kind: z.literal("stale-mark"),
  seq: z.int().min(0),
  claim_id: prefixedDigestSchema("cc"),
  cause_claim_id: prefixedDigestSchema("cc"),
  cause_record_digest: digestSchema,
  prev_digest: digestSchema,
  record_digest: digestSchema,
});

const runCommitSchema = z.strictObject({
  kind: z.literal("run-commit"),
  seq: z.int().min(0),
  run: z.strictObject({
    validator: validatorIdentitySchema,
    source_evidence_ids: z.array(prefixedDigestSchema("ev")),
    subject_sha256: digestSchema,
    claims_considered: z.int().min(0),
    counts: z.strictObject({
      supported: z.int().min(0),
      refuted: z.int().min(0),
      unknown: z.int().min(0),
    }),
    stale_marked: z.int().min(0),
  }),
  report_digest: digestSchema,
  signer: z.strictObject({
    producer: z.literal(CLAIM_CHECK_LEDGER_WRITER.producer),
    version: z.string().min(1),
  }),
  /**
   * The canonical report digest itself. This is a digest commitment, not a
   * cryptographic signature: no key infrastructure exists in the product, and
   * the field must never be mistaken for one.
   */
  signature: digestSchema,
  prev_digest: digestSchema,
  record_digest: digestSchema,
});

/** One append-only ledger entry: an adjudication, a stale mark, or a run commit. */
export const claimCheckLedgerEntrySchema = z.discriminatedUnion("kind", [
  adjudicationRecordSchema,
  staleMarkSchema,
  runCommitSchema,
]);
export type ClaimCheckLedgerEntry = z.infer<typeof claimCheckLedgerEntrySchema>;
export type AdjudicationRecord = z.infer<typeof adjudicationRecordSchema>;
export type StaleMark = z.infer<typeof staleMarkSchema>;
export type RunCommit = z.infer<typeof runCommitSchema>;

type LedgerEntryContent =
  | Omit<AdjudicationRecord, "record_digest">
  | Omit<StaleMark, "record_digest">
  | Omit<RunCommit, "record_digest">;

const entryDigest = (content: LedgerEntryContent): string =>
  digestCanonicalValue(content, "Claim-check ledger entry");

const reportDigest = (run: RunCommit["run"]): string =>
  digestCanonicalValue(
    {
      validator: run.validator,
      source_evidence_ids: run.source_evidence_ids,
      subject_sha256: run.subject_sha256,
      claims_considered: run.claims_considered,
      counts: run.counts,
      stale_marked: run.stale_marked,
    },
    "Claim-check run report",
  );

const summarize = (entries: readonly ClaimCheckLedgerEntry[]) => {
  const counts = { supported: 0, refuted: 0, unknown: 0 };
  let adjudications = 0;
  let staleMarks = 0;
  let runs = 0;
  for (const entry of entries) {
    if (entry.kind === "adjudication") {
      adjudications += 1;
      counts[entry.state] += 1;
    } else if (entry.kind === "stale-mark") staleMarks += 1;
    else runs += 1;
  }
  const last = entries[entries.length - 1];
  return {
    entries: entries.length,
    adjudications,
    stale_marks: staleMarks,
    runs,
    ...counts,
    complete: last !== undefined && last.kind === "run-commit",
  };
};

const computeLedgerId = (
  subject: { sha256: string; format: string },
  entries: readonly ClaimCheckLedgerEntry[],
): string =>
  `ccl_${digestCanonicalValue({ subject, entries }, "Claim-check ledger")}`;

const ledgerObjectSchema = z.strictObject({
  ledger_id: prefixedDigestSchema("ccl"),
  subject: z.strictObject({
    sha256: digestSchema,
    format: z.string().min(1),
  }),
  entries: z.array(claimCheckLedgerEntrySchema),
  summary: z.strictObject({
    entries: z.int().min(0),
    adjudications: z.int().min(0),
    stale_marks: z.int().min(0),
    runs: z.int().min(0),
    supported: z.int().min(0),
    refuted: z.int().min(0),
    unknown: z.int().min(0),
    complete: z.boolean(),
  }),
});

type ClaimCheckLedgerValue = z.infer<typeof ledgerObjectSchema>;

const ledgerIssues = (
  ledger: ClaimCheckLedgerValue,
  context: z.RefinementCtx,
): void => {
  const issue = (path: (string | number)[], message: string): void =>
    context.addIssue({ code: "custom", path, message });
  let previousDigest = GENESIS_DIGEST;
  const refutedDigests = new Map<string, string>();
  for (const [index, entry] of ledger.entries.entries()) {
    if (entry.seq !== index)
      issue(
        ["entries", index, "seq"],
        "Ledger entries must be sequenced from 0",
      );
    if (entry.prev_digest !== previousDigest)
      issue(
        ["entries", index, "prev_digest"],
        "Ledger entry does not chain to the previous entry digest",
      );
    const { record_digest: recorded, ...content } = entry;
    if (entryDigest(content) !== recorded)
      issue(
        ["entries", index, "record_digest"],
        "Ledger entry digest does not match its content",
      );
    if (entry.kind === "adjudication") {
      const expectedLabel =
        entry.state === "unknown" ? "unverified" : "verified-fact";
      if (entry.label !== expectedLabel)
        issue(
          ["entries", index, "label"],
          "Adjudication label does not match its state",
        );
      if (!isSortedUniqueAscii(entry.evidence_refs))
        issue(
          ["entries", index, "evidence_refs"],
          "Adjudication evidence refs must be sorted and unique",
        );
      if (entry.state === "refuted")
        refutedDigests.set(entry.claim_id, entry.record_digest);
    }
    if (entry.kind === "stale-mark") {
      if (
        refutedDigests.get(entry.cause_claim_id) !== entry.cause_record_digest
      )
        issue(
          ["entries", index, "cause_record_digest"],
          "Stale mark does not name the refuted adjudication that caused it",
        );
    }
    if (entry.kind === "run-commit") {
      if (reportDigest(entry.run) !== entry.report_digest)
        issue(
          ["entries", index, "report_digest"],
          "Run commit report digest does not match its run content",
        );
      if (entry.signature !== entry.report_digest)
        issue(
          ["entries", index, "signature"],
          "Run commit signature must be its report digest",
        );
      if (entry.run.subject_sha256 !== ledger.subject.sha256)
        issue(
          ["entries", index, "run", "subject_sha256"],
          "Run commit subject does not match the ledger subject",
        );
      if (!isSortedUniqueAscii(entry.run.source_evidence_ids))
        issue(
          ["entries", index, "run", "source_evidence_ids"],
          "Run commit source Evidence IDs must be sorted and unique",
        );
    }
    previousDigest = entry.record_digest;
  }
  if (
    JSON.stringify(summarize(ledger.entries)) !== JSON.stringify(ledger.summary)
  )
    issue(["summary"], "Ledger summary does not match its entries");
  if (computeLedgerId(ledger.subject, ledger.entries) !== ledger.ledger_id)
    issue(["ledger_id"], "Ledger identifier does not match its content");
};

/** Append-only, hash-chained claim-check ledger for one artifact subject. */
export const claimCheckLedgerSchema =
  ledgerObjectSchema.superRefine(ledgerIssues);

export type ClaimCheckLedger = z.infer<typeof ledgerObjectSchema>;

/** Parse a ledger and verify its hash chain, sequence, and summary. */
export const parseClaimCheckLedger = (input: unknown): ClaimCheckLedger =>
  claimCheckLedgerSchema.parse(input);

/** Whether a parsed ledger ends in a run commit and can be read as results. */
export const claimCheckLedgerCompleteness = (
  ledger: ClaimCheckLedger,
): "complete" | "incomplete" =>
  ledger.summary.complete ? "complete" : "incomplete";

/** Resolved consumer view of one claim after the full ledger is applied. */
export interface ResolvedClaimState {
  readonly claim_version: string | null;
  readonly state: AdjudicationState | null;
  readonly reason: ClaimCheckReason | null;
  readonly stale: boolean;
}

/**
 * Resolve every claim's current standing: the latest adjudication wins, and a
 * stale mark applies only when it post-dates that adjudication. A stale mark
 * never changes the recorded state itself.
 */
export const resolveClaimCheckStates = (
  ledger: ClaimCheckLedger,
): ReadonlyMap<string, ResolvedClaimState> => {
  const resolved = new Map<string, ResolvedClaimState>();
  const adjudicationSeqs = new Map<string, number>();
  for (const entry of ledger.entries) {
    if (entry.kind === "adjudication") {
      resolved.set(entry.claim_id, {
        claim_version: entry.claim_version,
        state: entry.state,
        reason: entry.reason,
        stale: false,
      });
      adjudicationSeqs.set(entry.claim_id, entry.seq);
    }
    if (entry.kind === "stale-mark") {
      const current = resolved.get(entry.claim_id);
      if (current === undefined)
        resolved.set(entry.claim_id, {
          claim_version: null,
          state: null,
          reason: null,
          stale: true,
        });
      else if (entry.seq > (adjudicationSeqs.get(entry.claim_id) ?? -1))
        resolved.set(entry.claim_id, { ...current, stale: true });
    }
  }
  return resolved;
};

/** The ledger's view of one registered claim, whichever class produced it. */
interface LedgerClaim {
  readonly claim_id: string;
  readonly claim_version: string;
  readonly subject: { readonly sha256: string; readonly format: string };
  readonly evidence_refs: readonly string[];
  readonly dependencies: readonly string[];
}

const normalizeClaimShape = (
  claim: ClaimRecord | RuntimeClaimRecord,
): LedgerClaim =>
  "evidence_ref" in claim
    ? {
        claim_id: claim.claim_id,
        claim_version: claim.claim_version,
        subject: claim.subject,
        evidence_refs: [claim.evidence_ref],
        dependencies: claim.dependencies,
      }
    : {
        claim_id: claim.claim_id,
        claim_version: claim.claim_version,
        subject: claim.subject,
        evidence_refs: claim.evidence_refs,
        dependencies: claim.dependencies,
      };

type LedgerVerdict = StringClaimVerdict | RuntimeClaimVerdict;

/**
 * The muscle: the only component that appends to a claim-check ledger.
 * It enforces append-only hash chaining, per-run deduplication, and the stale
 * cascade, and it writes the RunCommit last. A verdict it cannot chain is
 * never recorded. Both claim classes share this append path; the string
 * class's behavior through it is unchanged.
 */
export interface ClaimCheckLedgerWriter {
  /**
   * Append one verdict for a registered claim. Returns false when the same
   * claim version was already adjudicated in this run (a duplicate
   * presentation is a no-op). Refutations cascade stale marks to dependents.
   */
  appendAdjudication(claim: ClaimRecord, verdict: StringClaimVerdict): boolean;
  appendAdjudication(
    claim: RuntimeClaimRecord,
    verdict: RuntimeClaimVerdict,
  ): boolean;
  /** Close the run with its RunCommit and return the verified ledger. */
  commitRun(sourceEvidenceIds: readonly string[]): ClaimCheckLedger;
  /** The ledger as it stands, without a RunCommit: an incomplete run. */
  incompleteLedger(): ClaimCheckLedger;
}

/** Registered claims by identity key, with their dependents, for one writer. */
interface ClaimRegistry {
  readonly byKey: ReadonlyMap<string, LedgerClaim>;
  readonly dependentsByClaimId: ReadonlyMap<string, readonly LedgerClaim[]>;
  readonly normalize: (claim: ClaimRecord | RuntimeClaimRecord) => LedgerClaim;
}

const registerClaims = (
  claims: readonly (ClaimRecord | RuntimeClaimRecord)[],
  subject: { readonly sha256: string; readonly format: string },
): ClaimRegistry => {
  const byKey = new Map<string, LedgerClaim>();
  const dependentsByClaimId = new Map<string, LedgerClaim[]>();
  // Registration identity is by object reference, as the string-only writer
  // enforced: the normalized view of a claim object is computed once, and an
  // append is accepted only for the very object that was registered.
  const normalizedByClaim = new WeakMap<object, LedgerClaim>();
  const normalize = (
    rawClaim: ClaimRecord | RuntimeClaimRecord,
  ): LedgerClaim => {
    let normalized = normalizedByClaim.get(rawClaim);
    if (normalized === undefined) {
      normalized = normalizeClaimShape(rawClaim);
      normalizedByClaim.set(rawClaim, normalized);
    }
    return normalized;
  };
  for (const rawClaim of claims) {
    const claim = normalize(rawClaim);
    if (
      claim.subject.sha256 !== subject.sha256 ||
      claim.subject.format !== subject.format
    )
      throw new TypeError(
        "Claim-check ledger writer refuses claims for a different subject",
      );
    byKey.set(`${claim.claim_id}@${claim.claim_version}`, claim);
    for (const dependency of claim.dependencies) {
      const dependents = dependentsByClaimId.get(dependency) ?? [];
      dependents.push(claim);
      dependentsByClaimId.set(dependency, dependents);
    }
  }
  for (const dependents of dependentsByClaimId.values())
    dependents.sort(
      (left, right) =>
        compareAsciiStrings(left.claim_id, right.claim_id) ||
        compareAsciiStrings(left.claim_version, right.claim_version),
    );
  return { byKey, dependentsByClaimId, normalize };
};

export const createClaimCheckLedgerWriter = (input: {
  readonly subject: { readonly sha256: string; readonly format: string };
  readonly claims: readonly (ClaimRecord | RuntimeClaimRecord)[];
  readonly validator: { readonly id: string; readonly version: string };
}): ClaimCheckLedgerWriter => {
  const { subject, validator } = input;
  const registry = registerClaims(input.claims, subject);
  const claimsByKey = registry.byKey;
  const dependentsByClaimId = registry.dependentsByClaimId;
  const normalizeClaim = registry.normalize;

  const entries: ClaimCheckLedgerEntry[] = [];
  const adjudicatedKeys = new Set<string>();
  const appendedMarks = new Set<string>();
  let committed = false;

  const append = (content: LedgerEntryContent): ClaimCheckLedgerEntry => {
    const entry = claimCheckLedgerEntrySchema.parse({
      ...content,
      record_digest: entryDigest(content),
    });
    entries.push(entry);
    return entry;
  };
  const chainFields = (): { seq: number; prev_digest: string } => ({
    seq: entries.length,
    prev_digest: entries[entries.length - 1]?.record_digest ?? GENESIS_DIGEST,
  });

  const buildLedger = (): ClaimCheckLedger =>
    claimCheckLedgerSchema.parse({
      ledger_id: computeLedgerId(subject, entries),
      subject,
      entries: [...entries],
      summary: summarize(entries),
    });

  return {
    appendAdjudication(
      rawClaim: ClaimRecord | RuntimeClaimRecord,
      verdict: LedgerVerdict,
    ) {
      if (committed)
        throw new TypeError("Cannot append to a committed claim-check ledger");
      const claim = normalizeClaim(rawClaim);
      const key = `${claim.claim_id}@${claim.claim_version}`;
      if (claimsByKey.get(key) !== claim)
        throw new TypeError(
          "Claim-check ledger writer refuses an unregistered claim",
        );
      if (adjudicatedKeys.has(key)) return false;
      adjudicatedKeys.add(key);
      const record = append({
        kind: "adjudication",
        ...chainFields(),
        claim_id: claim.claim_id,
        claim_version: claim.claim_version,
        state: verdict.state,
        reason: verdict.reason,
        validator,
        label: verdict.state === "unknown" ? "unverified" : "verified-fact",
        ...(verdict.observed === undefined
          ? {}
          : { observed: verdict.observed }),
        evidence_refs: [...claim.evidence_refs],
      });
      if (verdict.state === "refuted") {
        for (const dependent of dependentsByClaimId.get(claim.claim_id) ?? []) {
          const markKey = `${dependent.claim_id}@${record.record_digest}`;
          if (appendedMarks.has(markKey)) continue;
          appendedMarks.add(markKey);
          append({
            kind: "stale-mark",
            ...chainFields(),
            claim_id: dependent.claim_id,
            cause_claim_id: claim.claim_id,
            cause_record_digest: record.record_digest,
          });
        }
      }
      return true;
    },
    commitRun(sourceEvidenceIds) {
      if (committed)
        throw new TypeError("Claim-check run was already committed");
      committed = true;
      const counts = { supported: 0, refuted: 0, unknown: 0 };
      let staleMarked = 0;
      for (const entry of entries) {
        if (entry.kind === "adjudication") counts[entry.state] += 1;
        if (entry.kind === "stale-mark") staleMarked += 1;
      }
      const run: RunCommit["run"] = {
        validator,
        source_evidence_ids: uniqueSorted(sourceEvidenceIds),
        subject_sha256: subject.sha256,
        claims_considered: adjudicatedKeys.size,
        counts,
        stale_marked: staleMarked,
      };
      const digest = reportDigest(run);
      append({
        kind: "run-commit",
        ...chainFields(),
        run,
        report_digest: digest,
        signer: { ...CLAIM_CHECK_LEDGER_WRITER },
        signature: digest,
      });
      return buildLedger();
    },
    incompleteLedger() {
      return buildLedger();
    },
  };
};
