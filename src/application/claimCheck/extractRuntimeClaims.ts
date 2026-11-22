import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { compareAsciiStrings } from "../../domain/canonicalOrdering.js";
import {
  buildRuntimeClaim,
  deriveStimulusDigest,
  type RuntimeClaimRecord,
} from "../../domain/claimCheck/runtimeClaimRecord.js";
import { dynamicNormalizedResultSchema } from "../../domain/dynamicExecution/dynamicObservation.js";

const OPERATION = "claim_check_runtime";

/** Whether an Evidence record is a dynamic-execution record of the Frida producer. */
export const isRuntimeEvidence = (record: Evidence): boolean =>
  record.operation === "execute_dynamically" && record.provider.id === "frida";

/** The behavior-selecting stimulus one dynamic record ran under. */
export interface RuntimeStimulus {
  readonly argv: readonly string[];
  readonly envSet: Readonly<Record<string, string>>;
  readonly digest: string;
}

const malformedStimulus = (record: Evidence): AnalysisInputError =>
  new AnalysisInputError(OPERATION, {}, [
    {
      path: ["evidence", record.evidence_id, "parameters"],
      reason: "invalid_value",
      message:
        "stimulus_malformed: dynamic Evidence parameters do not yield a stimulus (argv and env_set must be present and well-formed); a record that cannot name its stimulus cannot be grouped",
      expected:
        "parameters.argv (string array) and parameters.env_set (string record)",
    },
  ]);

/**
 * Derive the stimulus a record ran under, from its own parameters. Budgets,
 * the target locator, and the Evidence path are not stimulus parts. A record
 * whose parameters cannot yield a stimulus aborts the run: guessing one
 * would group it with runs whose behavior it does not share.
 */
export const stimulusOfRecord = (record: Evidence): RuntimeStimulus => {
  const parameters = record.parameters as Record<string, unknown>;
  const argv = parameters.argv;
  const envSet = parameters.env_set;
  if (
    !Array.isArray(argv) ||
    argv.some((entry) => typeof entry !== "string") ||
    typeof envSet !== "object" ||
    envSet === null ||
    Array.isArray(envSet) ||
    Object.values(envSet).some((value) => typeof value !== "string")
  )
    throw malformedStimulus(record);
  const argvList = argv as string[];
  const envRecord = envSet as Record<string, string>;
  return {
    argv: argvList,
    envSet: envRecord,
    digest: deriveStimulusDigest(argvList, envRecord),
  };
};

/** One (subject, stimulus) group of runtime records and its claims. */
export interface RuntimeEvidenceGroup {
  readonly stimulusDigest: string;
  readonly stimulus: RuntimeStimulus;
  /** Distinct records of the group, ordered by Evidence id. */
  readonly records: readonly Evidence[];
  /** The union of the group's filed string rows, as claims, by claim id. */
  readonly claims: readonly RuntimeClaimRecord[];
}

const groupClaims = (
  stimulus: RuntimeStimulus,
  records: readonly Evidence[],
): RuntimeClaimRecord[] => {
  const refsByKey = new Map<string, string[]>();
  const rowByKey = new Map<
    string,
    { value: string; channel: "puts" | "fputs" | "printf_fmt" }
  >();
  for (const record of records) {
    const parsed = dynamicNormalizedResultSchema.safeParse(
      record.normalized_result,
    );
    if (!parsed.success)
      throw analysisInputErrorFromIssues(
        OPERATION,
        parsed.error.issues,
        record.normalized_result,
        { cause: parsed.error },
      );
    for (const row of parsed.data.strings) {
      const key = `${row.channel}\0${row.value}`;
      rowByKey.set(key, row);
      const refs = refsByKey.get(key) ?? [];
      refs.push(record.evidence_id);
      refsByKey.set(key, refs);
    }
  }
  const first = records[0];
  const subject = first?.subject;
  if (first === undefined || subject === null || subject === undefined)
    throw new AnalysisInputError(OPERATION, {}, [
      {
        path: ["evidence"],
        reason: "invalid_value",
        message:
          "subject_unavailable: dynamic Evidence does not identify its artifact subject",
        expected: "Evidence with an identified artifact subject",
      },
    ]);
  const claims = [...rowByKey.entries()].map(([key, row]) =>
    buildRuntimeClaim(row, {
      subjectSha256: subject.digest.sha256,
      subjectFormat: subject.format,
      evidenceRefs: refsByKey.get(key) ?? [],
      providerId: first.provider.id,
      providerVersion: first.provider.version,
      operation: first.operation,
      stimulusDigest: stimulus.digest,
    }),
  );
  return claims.sort((left, right) =>
    compareAsciiStrings(left.claim_id, right.claim_id),
  );
};

/**
 * Partition authenticated dynamic-execution records into (subject, stimulus)
 * groups and derive each group's claims. Records of other operations (and
 * other producers) are not runtime sources and are ignored. Duplicate
 * presentations of one record are deduped by Evidence id: a record is not
 * its own second witness. Claims are the union of the group's filed string
 * rows, deduped by claim identity, each carrying every filing record as its
 * sources. Subject agreement across the set is the run layer's check.
 */
export const groupRuntimeEvidence = (
  records: readonly Evidence[],
): RuntimeEvidenceGroup[] => {
  const seen = new Set<string>();
  const byDigest = new Map<
    string,
    { stimulus: RuntimeStimulus; records: Evidence[] }
  >();
  for (const record of records) {
    if (!isRuntimeEvidence(record)) continue;
    if (seen.has(record.evidence_id)) continue;
    seen.add(record.evidence_id);
    const stimulus = stimulusOfRecord(record);
    const group = byDigest.get(stimulus.digest) ?? {
      stimulus,
      records: [],
    };
    group.records.push(record);
    byDigest.set(stimulus.digest, group);
  }
  return [...byDigest.values()]
    .map((group) => {
      const ordered = [...group.records].sort((left, right) =>
        compareAsciiStrings(left.evidence_id, right.evidence_id),
      );
      return {
        stimulusDigest: group.stimulus.digest,
        stimulus: group.stimulus,
        records: ordered,
        claims: groupClaims(group.stimulus, ordered),
      };
    })
    .sort((left, right) =>
      compareAsciiStrings(left.stimulusDigest, right.stimulusDigest),
    );
};
