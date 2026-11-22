import { describe, expect, it } from "vitest";

import {
  runtimeObservationKey,
  type RuntimeObservation,
} from "./runtimeObservationDerivation.js";
import {
  buildRuntimeClaim,
  deriveStimulusDigest,
  type RuntimeClaimChannel,
  type RuntimeClaimRecord,
} from "./runtimeClaimRecord.js";
import {
  adjudicateRuntimeGroup,
  volatileSkeleton,
  type RuntimeGroupRecord,
} from "./runtimeReplayValidator.js";

const SUBJECT_SHA = "a".repeat(64);
const STIMULUS = deriveStimulusDigest([], {});
let sequence = 0;

const evId = (): string => {
  sequence += 1;
  return `ev_${sequence.toString(16).padStart(64, "0")}`;
};

const claimFor = (
  value: string,
  channel: RuntimeClaimChannel = "puts",
  refs: readonly string[] = [],
): RuntimeClaimRecord =>
  buildRuntimeClaim(
    { value, channel },
    {
      subjectSha256: SUBJECT_SHA,
      subjectFormat: "elf",
      evidenceRefs: refs,
      providerId: "frida",
      providerVersion: "17.23.2",
      operation: "execute_dynamically",
      stimulusDigest: STIMULUS,
    },
  );

interface RecordOptions {
  readonly filed?: readonly RuntimeObservation[];
  readonly derived?: readonly RuntimeObservation[];
  readonly rawPresent?: boolean;
  readonly packReadyFound?: boolean;
  readonly limitations?: readonly string[];
  readonly supervisorReason?: string;
  readonly resumeObserved?: boolean;
  readonly containmentBreach?: boolean | null;
  readonly survivorsAfter?: readonly string[];
  readonly packReadyMissing?: readonly string[] | null;
  readonly hookPackVersion?: string;
}

const record = (options: RecordOptions = {}): RuntimeGroupRecord => {
  const derived = options.derived ?? [];
  return {
    evidenceId: evId(),
    filed: new Set(
      (options.filed ?? []).map((row) =>
        runtimeObservationKey(row.channel, row.value),
      ),
    ),
    derived: new Set(
      derived.map((row) => runtimeObservationKey(row.channel, row.value)),
    ),
    derivedObservations: derived,
    rawPresent: options.rawPresent ?? true,
    packReadyFound: options.packReadyFound ?? true,
    limitations: options.limitations ?? [],
    execution: {
      supervisorReason: options.supervisorReason ?? "exited",
      resumeObserved: options.resumeObserved ?? true,
      containmentBreach:
        options.containmentBreach === undefined
          ? false
          : options.containmentBreach,
      survivorsAfter: options.survivorsAfter ?? [],
      packReadyMissing: options.packReadyMissing ?? [],
      hookPackVersion: options.hookPackVersion ?? "1.1.0",
    },
  };
};

const obs = (
  value: string,
  channel: RuntimeClaimChannel = "puts",
): RuntimeObservation => ({ channel, value });

const verdictOf = (
  claims: readonly RuntimeClaimRecord[],
  records: readonly RuntimeGroupRecord[],
  value: string,
) => {
  const { outcomes, accounting } = adjudicateRuntimeGroup({ claims, records });
  const outcome = outcomes.find(
    (entry) => entry.claim.assertion.value === value,
  );
  if (outcome === undefined) throw new Error(`no outcome for ${value}`);
  return { verdict: outcome.verdict, accounting };
};

describe("runtime replay validator", () => {
  it("supports a claim that recurs in every eligible witness", () => {
    const claim = claimFor("alpha-secret-one");
    const source = record({
      filed: [obs("alpha-secret-one")],
      derived: [obs("alpha-secret-one")],
    });
    const witnessA = record({ derived: [obs("alpha-secret-one")] });
    const witnessB = record({ derived: [obs("alpha-secret-one")] });
    const { verdict, accounting } = verdictOf(
      [claim],
      [source, witnessA, witnessB],
      "alpha-secret-one",
    );
    expect(verdict.state).toBe("supported");
    expect(verdict.reason).toBe("replay_recurred");
    expect(verdict.observed.eligible_witnesses).toBe(2);
    expect(verdict.observed.recurring_witnesses).toBe(2);
    expect(accounting.eligible_witnesses).toBe(2);
  });

  it("excludes a witness whose containment is unverified (breach null)", () => {
    const claim = claimFor("alpha-secret-one");
    const source = record({
      filed: [obs("alpha-secret-one")],
      derived: [obs("alpha-secret-one")],
    });
    const clean = record({ derived: [obs("alpha-secret-one")] });
    const unverified = record({
      derived: [obs("alpha-secret-one")],
      containmentBreach: null,
    });
    const { verdict, accounting } = verdictOf(
      [claim],
      [source, clean, unverified],
      "alpha-secret-one",
    );
    expect(verdict.state).toBe("unknown");
    expect(verdict.reason).toBe("recurrence_unconfirmed");
    expect(accounting.eligible_witnesses).toBe(1);
    expect(accounting.ineligibility_by_cause.containment).toBe(1);
  });

  it("leaves a claim unconfirmed with fewer than two witnesses", () => {
    const claim = claimFor("alpha-secret-one");
    const source = record({
      filed: [obs("alpha-secret-one")],
      derived: [obs("alpha-secret-one")],
    });
    expect(
      verdictOf([claim], [source], "alpha-secret-one").verdict.reason,
    ).toBe("recurrence_unconfirmed");
    const witness = record({ derived: [obs("alpha-secret-one")] });
    expect(
      verdictOf([claim], [source, witness], "alpha-secret-one").verdict.reason,
    ).toBe("recurrence_unconfirmed");
  });

  it("refutes a claim absent from two clean witnesses (replay_absent)", () => {
    const claim = claimFor("result-sub");
    const source = record({
      filed: [obs("result-sub")],
      derived: [obs("result-sub")],
    });
    const witnessA = record({ derived: [obs("result-add")] });
    const witnessB = record({ derived: [obs("result-add")] });
    const { verdict } = verdictOf(
      [claim],
      [source, witnessA, witnessB],
      "result-sub",
    );
    expect(verdict.state).toBe("refuted");
    expect(verdict.reason).toBe("replay_absent");
  });

  it("refutes a phantom row against its own complete log (record_inconsistent)", () => {
    const claim = claimFor("phantom-value");
    const source = record({
      filed: [obs("phantom-value")],
      derived: [obs("something-else")],
    });
    const { verdict } = verdictOf([claim], [source], "phantom-value");
    expect(verdict.state).toBe("refuted");
    expect(verdict.reason).toBe("record_inconsistent");
  });

  it("leaves a phantom row in a truncated log unknown (record_incomplete)", () => {
    const claim = claimFor("phantom-value");
    const source = record({
      filed: [obs("phantom-value")],
      derived: [],
      limitations: ["messages_truncated"],
    });
    const { verdict } = verdictOf([claim], [source], "phantom-value");
    expect(verdict.state).toBe("unknown");
    expect(verdict.reason).toBe("record_incomplete");
  });

  it("reports partial recurrence as unknown, never a verdict either way", () => {
    const claim = claimFor("flaky-value");
    const source = record({
      filed: [obs("flaky-value")],
      derived: [obs("flaky-value")],
    });
    const witnessA = record({ derived: [obs("flaky-value")] });
    const witnessB = record({ derived: [obs("other")] });
    const { verdict } = verdictOf(
      [claim],
      [source, witnessA, witnessB],
      "flaky-value",
    );
    expect(verdict.state).toBe("unknown");
    expect(verdict.reason).toBe("recurrence_partial");
  });

  it("screens volatile values out of refutation (value_volatile)", () => {
    const claim = claimFor("run-12345");
    const source = record({
      filed: [obs("run-12345")],
      derived: [obs("run-12345")],
    });
    const witnessA = record({ derived: [obs("run-23456")] });
    const witnessB = record({ derived: [obs("run-34567")] });
    const { verdict } = verdictOf(
      [claim],
      [source, witnessA, witnessB],
      "run-12345",
    );
    expect(verdict.state).toBe("unknown");
    expect(verdict.reason).toBe("value_volatile");
  });
});

describe("runtime replay validator witness eligibility", () => {
  it("excludes terminated and truncated witnesses and counts the causes", () => {
    const claim = claimFor("alpha-secret-one");
    const source = record({
      filed: [obs("alpha-secret-one")],
      derived: [obs("alpha-secret-one")],
    });
    const terminated = record({
      supervisorReason: "deadline",
      limitations: ["run_terminated: deadline"],
    });
    const truncated = record({ limitations: ["messages_truncated"] });
    const { verdict, accounting } = verdictOf(
      [claim],
      [source, terminated, truncated],
      "alpha-secret-one",
    );
    expect(verdict.reason).toBe("recurrence_unconfirmed");
    expect(accounting.ineligibility_by_cause.terminated).toBe(1);
    expect(accounting.ineligibility_by_cause.truncated).toBe(1);
    expect(accounting.eligible_witnesses).toBe(0);
  });

  it("judges witness eligibility per channel: a printf-missing witness still witnesses puts", () => {
    const claim = claimFor("alpha-secret-one", "puts");
    const source = record({
      filed: [obs("alpha-secret-one")],
      derived: [obs("alpha-secret-one")],
    });
    const printfMissing = record({
      derived: [obs("alpha-secret-one")],
      packReadyMissing: ["printf", "fprintf"],
    });
    const clean = record({ derived: [obs("alpha-secret-one")] });
    const { verdict } = verdictOf(
      [claim],
      [source, printfMissing, clean],
      "alpha-secret-one",
    );
    expect(verdict.state).toBe("supported");
  });

  it("excludes a witness missing the claim channel's only hook", () => {
    const claim = claimFor("alpha-secret-one", "puts");
    const source = record({
      filed: [obs("alpha-secret-one")],
      derived: [obs("alpha-secret-one")],
    });
    const putsMissing = record({
      derived: [obs("alpha-secret-one")],
      packReadyMissing: ["puts"],
    });
    const clean = record({ derived: [obs("alpha-secret-one")] });
    const { verdict, accounting } = verdictOf(
      [claim],
      [source, putsMissing, clean],
      "alpha-secret-one",
    );
    expect(verdict.reason).toBe("recurrence_unconfirmed");
    expect(accounting.ineligibility_by_cause.hook_missing).toBe(1);
  });

  it("pools only the modal pack version's records as witnesses", () => {
    const claim = claimFor("alpha-secret-one");
    const source = record({
      filed: [obs("alpha-secret-one")],
      derived: [obs("alpha-secret-one")],
      hookPackVersion: "1.1.0",
    });
    const skewed = record({
      derived: [obs("alpha-secret-one")],
      hookPackVersion: "1.0.0",
    });
    const clean = record({ derived: [obs("alpha-secret-one")] });
    const { verdict, accounting } = verdictOf(
      [claim],
      [source, skewed, clean],
      "alpha-secret-one",
    );
    expect(verdict.reason).toBe("recurrence_unconfirmed");
    expect(accounting.ineligibility_by_cause.pack_version_skew).toBe(1);
  });

  it("counts observations filed in no record as unfiled, never as claims", () => {
    const claim = claimFor("alpha-secret-one");
    const source = record({
      filed: [obs("alpha-secret-one")],
      derived: [obs("alpha-secret-one"), obs("unfiled-extra")],
    });
    const { accounting } = verdictOf([claim], [source], "alpha-secret-one");
    expect(accounting.unfiled_observations).toBe(1);
  });
});

describe("volatile skeleton", () => {
  it("collapses digit runs and long 0x hex runs", () => {
    expect(volatileSkeleton("run-12345")).toBe("run-#");
    expect(volatileSkeleton("ts=1732123456 pid=991")).toBe("ts=# pid=#");
    expect(volatileSkeleton("addr 0x7f9c1234 dead")).toBe("addr # dead");
    expect(volatileSkeleton("alpha-secret-one")).toBe("alpha-secret-one");
    expect(volatileSkeleton("v2")).toBe("v#");
  });
});
