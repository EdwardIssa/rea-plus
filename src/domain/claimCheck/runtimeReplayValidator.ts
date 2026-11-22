import { z } from "zod";

import { digestCanonicalValue } from "../canonicalDigest.js";
import { compareAsciiStrings, uniqueSorted } from "../canonicalOrdering.js";
import { digestSchema, prefixedDigestSchema } from "../digests.js";
import {
  runtimeObservationKey,
  type RuntimeObservation,
} from "./runtimeObservationDerivation.js";
import type {
  RuntimeClaimChannel,
  RuntimeClaimRecord,
} from "./runtimeClaimRecord.js";
import type { AdjudicationState } from "./stringClaimValidator.js";

/** The runtime replay validator's identity, recorded on every verdict. */
export const RUNTIME_CLAIM_VALIDATOR = {
  id: "rea-runtime-replay",
  version: "1.0.0",
} as const;

/**
 * Reason vocabulary for runtime-claim verdicts; every verdict names one.
 * Class-owned: the ledger's reason union widens with exactly these values.
 */
export const runtimeAdjudicationReasonSchema = z.enum([
  "replay_recurred",
  "replay_absent",
  "record_inconsistent",
  "record_incomplete",
  "recurrence_unconfirmed",
  "recurrence_partial",
  "value_volatile",
  "assertion_malformed",
]);
export type RuntimeAdjudicationReason = z.infer<
  typeof runtimeAdjudicationReasonSchema
>;

/**
 * What one runtime adjudication observed, in place of the byte shape: the
 * claim's source records, the eligible witnesses that carried the verdict,
 * and a digest of the primary source record's re-derived observation set.
 */
export const replayObservedSchema = z.strictObject({
  source_evidence_ids: z.array(prefixedDigestSchema("ev")),
  witness_evidence_ids: z.array(prefixedDigestSchema("ev")),
  eligible_witnesses: z.int().min(0),
  recurring_witnesses: z.int().min(0),
  observation_digest: digestSchema,
});
export type RuntimeReplayObserved = z.infer<typeof replayObservedSchema>;

/** One runtime validator decision: a state, its reason, and its replay shape. */
export interface RuntimeClaimVerdict {
  readonly state: AdjudicationState;
  readonly reason: RuntimeAdjudicationReason;
  readonly observed: RuntimeReplayObserved;
}

/**
 * The declared volatility transform: each maximal run of ASCII digits
 * becomes `#`, and each `0x`-prefixed maximal hex run of length at least 4
 * becomes `#` (applied first, so a hex run's digits are not re-counted).
 * Two values are family-equal when their skeletons are equal and their
 * channels match. The screen only ever blocks a refutation; support always
 * requires exact-value recurrence.
 */
export const volatileSkeleton = (value: string): string =>
  value.replace(/0x[0-9a-fA-F]{4,}/gu, "#").replace(/[0-9]+/gu, "#");

/** Why a record cannot witness a claim's absence, in attribution precedence. */
export type WitnessIneligibilityCause =
  | "containment"
  | "terminated"
  | "truncated"
  | "pack_version_skew"
  | "hook_missing";

/** One group record as the validator sees it: filed rows, re-derived log, run facts. */
export interface RuntimeGroupRecord {
  readonly evidenceId: string;
  /** Filed string-row keys (channel + value) of this record. */
  readonly filed: ReadonlySet<string>;
  /** Observation keys re-derived from this record's own raw log. */
  readonly derived: ReadonlySet<string>;
  /** This record's re-derived observations, sorted (digest and family scan). */
  readonly derivedObservations: readonly RuntimeObservation[];
  /** Whether `raw_result` was a present array at all. */
  readonly rawPresent: boolean;
  /** Whether re-derivation found a `pack_ready` payload in the log. */
  readonly packReadyFound: boolean;
  readonly limitations: readonly string[];
  readonly execution: {
    readonly supervisorReason: string;
    readonly resumeObserved: boolean;
    readonly containmentBreach: boolean;
    readonly survivorsAfter: readonly string[];
    /** Hooks the run reported missing, or null when it reported no pack. */
    readonly packReadyMissing: readonly string[] | null;
    readonly hookPackVersion: string;
  };
}

/** The hooks that can produce each channel's captures. */
const CHANNEL_HOOKS: Readonly<Record<RuntimeClaimChannel, readonly string[]>> =
  {
    puts: ["puts"],
    fputs: ["fputs"],
    printf_fmt: ["printf", "fprintf"],
  };

const hookListed = (missing: readonly string[], hook: string): boolean =>
  missing.some((entry) => entry === hook || entry.startsWith(`${hook} `));

const limitationMissingHooks = (
  limitations: readonly string[],
): readonly string[] => {
  const names: string[] = [];
  for (const limitation of limitations) {
    if (!limitation.startsWith("hooks_unavailable:")) continue;
    for (const name of limitation.slice("hooks_unavailable:".length).split(","))
      names.push(name.trim());
  }
  return names;
};

/**
 * Whether a record's log is complete: the raw log is present, re-derivation
 * found its pack_ready payload, and no truncation limitation is recorded.
 * Presence in an incomplete log is still real; absence proves nothing.
 */
export const runtimeLogComplete = (record: RuntimeGroupRecord): boolean =>
  record.rawPresent &&
  record.packReadyFound &&
  !record.limitations.includes("messages_truncated") &&
  !record.limitations.includes("stdout_incomplete");

/**
 * The first reason a record cannot witness absences on one claim's channel,
 * or null when it is an eligible witness for that channel. Eligibility is
 * per claim channel: a replay that could not capture the channel cannot
 * witness its absence, though it may witness another channel's claims.
 */
export const witnessIneligibility = (
  record: RuntimeGroupRecord,
  channel: RuntimeClaimChannel,
  modalPackVersion: string,
): WitnessIneligibilityCause | null => {
  const { execution, limitations } = record;
  if (
    execution.containmentBreach ||
    execution.survivorsAfter.length > 0 ||
    limitations.some((entry) => entry.startsWith("containment_breach:"))
  )
    return "containment";
  if (
    execution.supervisorReason !== "exited" ||
    !execution.resumeObserved ||
    limitations.some((entry) => entry.startsWith("run_terminated:"))
  )
    return "terminated";
  if (
    limitations.includes("messages_truncated") ||
    limitations.includes("stdout_incomplete")
  )
    return "truncated";
  if (execution.hookPackVersion !== modalPackVersion)
    return "pack_version_skew";
  const missing = [
    ...(execution.packReadyMissing ?? []),
    ...limitationMissingHooks(limitations),
  ];
  if (
    execution.packReadyMissing === null ||
    CHANNEL_HOOKS[channel].every((hook) => hookListed(missing, hook))
  )
    return "hook_missing";
  return null;
};

/** The group's modal hook-pack version; ties resolve to the smallest version. */
export const modalHookPackVersion = (
  records: readonly RuntimeGroupRecord[],
): string => {
  const counts = new Map<string, number>();
  for (const record of records)
    counts.set(
      record.execution.hookPackVersion,
      (counts.get(record.execution.hookPackVersion) ?? 0) + 1,
    );
  let modal = "";
  let best = -1;
  for (const version of [...counts.keys()].sort(compareAsciiStrings)) {
    const count = counts.get(version) ?? 0;
    if (count > best) {
      best = count;
      modal = version;
    }
  }
  return modal;
};

/** Per-group witness accounting, reported with the run's verdicts. */
export interface RuntimeGroupAccounting {
  readonly records_presented: number;
  /** Distinct records that served as an eligible witness for some claim. */
  readonly eligible_witnesses: number;
  readonly ineligibility_by_cause: Readonly<
    Record<WitnessIneligibilityCause, number>
  >;
  /** Observations re-derived from some log but filed in no record's rows. */
  readonly unfiled_observations: number;
}

/** One claim's adjudication inside its group. */
export interface RuntimeClaimOutcome {
  readonly claim: RuntimeClaimRecord;
  readonly verdict: RuntimeClaimVerdict;
}

const observationSetDigest = (
  observations: readonly RuntimeObservation[],
): string =>
  digestCanonicalValue(
    {
      observations: observations.map((observation) => ({
        channel: observation.channel,
        value: observation.value,
      })),
    },
    "Runtime observation set",
  );

/**
 * The brain: pure adjudication of one (subject, stimulus) group's claims
 * against the group's re-derived logs. It writes nothing and launches
 * nothing; verdicts are a function of the presented records alone.
 *
 * Rows, in order: a claim absent from every re-derived log is refuted as
 * record-inconsistent when a filing record's log is complete, unknown as
 * record-incomplete otherwise. A claim present in some log needs two
 * eligible witnesses (records other than the claim's primary source):
 * unanimous recurrence supports it, partial recurrence is unknown, and
 * absence in both refutes it only when no eligible witness carries a
 * family-equal value (the volatility screen).
 */
/** One claim's witness partition: who may witness it, and who recurred. */
interface ClaimWitnesses {
  readonly eligible: readonly RuntimeGroupRecord[];
  readonly recurring: number;
  readonly excluded: readonly {
    readonly evidenceId: string;
    readonly cause: WitnessIneligibilityCause;
  }[];
}

const witnessesForClaim = (input: {
  readonly claim: RuntimeClaimRecord;
  readonly records: readonly RuntimeGroupRecord[];
  readonly primaryId: string | undefined;
  readonly modal: string;
  readonly key: string;
}): ClaimWitnesses => {
  const { claim, records, primaryId, modal, key } = input;
  const eligible: RuntimeGroupRecord[] = [];
  const excluded: ClaimWitnesses["excluded"][number][] = [];
  for (const witness of records) {
    if (witness.evidenceId === primaryId) continue;
    const cause = witnessIneligibility(witness, claim.assertion.channel, modal);
    if (cause === null) eligible.push(witness);
    else excluded.push({ evidenceId: witness.evidenceId, cause });
  }
  return {
    eligible,
    recurring: eligible.filter((record) => record.derived.has(key)).length,
    excluded,
  };
};

const verdictForClaim = (input: {
  readonly claim: RuntimeClaimRecord;
  readonly filedBy: readonly RuntimeGroupRecord[];
  readonly witnesses: ClaimWitnesses;
  readonly inUnion: boolean;
  readonly observed: RuntimeReplayObserved;
}): RuntimeClaimVerdict => {
  const { claim, filedBy, witnesses, inUnion, observed } = input;
  if (!inUnion)
    return filedBy.some((record) => runtimeLogComplete(record))
      ? { state: "refuted", reason: "record_inconsistent", observed }
      : { state: "unknown", reason: "record_incomplete", observed };
  const { eligible, recurring } = witnesses;
  if (eligible.length < 2)
    return { state: "unknown", reason: "recurrence_unconfirmed", observed };
  if (recurring === eligible.length)
    return { state: "supported", reason: "replay_recurred", observed };
  if (recurring > 0)
    return { state: "unknown", reason: "recurrence_partial", observed };
  const skeleton = volatileSkeleton(claim.assertion.value);
  const familyWitnessed = eligible.some((record) =>
    record.derivedObservations.some(
      (observation) =>
        observation.channel === claim.assertion.channel &&
        observation.value !== claim.assertion.value &&
        volatileSkeleton(observation.value) === skeleton,
    ),
  );
  return familyWitnessed
    ? { state: "unknown", reason: "value_volatile", observed }
    : { state: "refuted", reason: "replay_absent", observed };
};

export const adjudicateRuntimeGroup = (input: {
  readonly claims: readonly RuntimeClaimRecord[];
  readonly records: readonly RuntimeGroupRecord[];
}): {
  readonly outcomes: readonly RuntimeClaimOutcome[];
  readonly accounting: RuntimeGroupAccounting;
} => {
  const { claims, records } = input;
  const modal = modalHookPackVersion(records);
  const unionDerived = new Set<string>();
  const unionFiled = new Set<string>();
  for (const record of records) {
    for (const key of record.derived) unionDerived.add(key);
    for (const key of record.filed) unionFiled.add(key);
  }
  let unfiled = 0;
  for (const key of unionDerived) if (!unionFiled.has(key)) unfiled += 1;

  const eligibleWitnessIds = new Set<string>();
  const causeByRecord = new Map<string, WitnessIneligibilityCause>();
  const outcomes: RuntimeClaimOutcome[] = [];
  for (const claim of claims) {
    const key = runtimeObservationKey(
      claim.assertion.channel,
      claim.assertion.value,
    );
    const filedBy = records.filter((record) => record.filed.has(key));
    const primary = [...filedBy].sort((left, right) =>
      compareAsciiStrings(left.evidenceId, right.evidenceId),
    )[0];
    const witnesses = witnessesForClaim({
      claim,
      records,
      primaryId: primary?.evidenceId,
      modal,
      key,
    });
    for (const record of witnesses.eligible)
      eligibleWitnessIds.add(record.evidenceId);
    for (const exclusion of witnesses.excluded)
      if (!causeByRecord.has(exclusion.evidenceId))
        causeByRecord.set(exclusion.evidenceId, exclusion.cause);
    const observed: RuntimeReplayObserved = {
      source_evidence_ids: uniqueSorted(
        filedBy.map((record) => record.evidenceId),
      ),
      witness_evidence_ids: uniqueSorted(
        witnesses.eligible.map((record) => record.evidenceId),
      ),
      eligible_witnesses: witnesses.eligible.length,
      recurring_witnesses: witnesses.recurring,
      observation_digest: observationSetDigest(
        primary?.derivedObservations ?? [],
      ),
    };
    outcomes.push({
      claim,
      verdict: verdictForClaim({
        claim,
        filedBy,
        witnesses,
        inUnion: unionDerived.has(key),
        observed,
      }),
    });
  }

  const ineligibilityByCause: Record<WitnessIneligibilityCause, number> = {
    containment: 0,
    terminated: 0,
    truncated: 0,
    pack_version_skew: 0,
    hook_missing: 0,
  };
  for (const cause of causeByRecord.values()) ineligibilityByCause[cause] += 1;

  return {
    outcomes,
    accounting: {
      records_presented: records.length,
      eligible_witnesses: eligibleWitnessIds.size,
      ineligibility_by_cause: ineligibilityByCause,
      unfiled_observations: unfiled,
    },
  };
};
