import { readFile, writeFile } from "node:fs/promises";

import { z } from "zod";

import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import { parseEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";
import { safeParseJson } from "../../domain/safeJson.js";
import { compareAsciiStrings } from "../../domain/canonicalOrdering.js";
import {
  createClaimCheckLedgerWriter,
  type ClaimCheckLedger,
} from "../../domain/claimCheck/claimCheckLedger.js";
import {
  runtimeClaimCheckRunOutcomeSchema,
  type RuntimeClaimCheckRunOutcome,
} from "../../domain/claimCheck/claimCheckRuntimeReport.js";
import type { RuntimeClaimRecord } from "../../domain/claimCheck/runtimeClaimRecord.js";
import { deriveRuntimeObservations } from "../../domain/claimCheck/runtimeObservationDerivation.js";
import {
  adjudicateRuntimeGroup,
  RUNTIME_CLAIM_VALIDATOR,
  type RuntimeClaimVerdict,
  type RuntimeGroupRecord,
} from "../../domain/claimCheck/runtimeReplayValidator.js";
import { dynamicNormalizedResultSchema } from "../../domain/dynamicExecution/dynamicObservation.js";
import {
  groupRuntimeEvidence,
  isRuntimeEvidence,
  type RuntimeEvidenceGroup,
} from "./extractRuntimeClaims.js";

export { runtimeClaimCheckRunOutcomeSchema, type RuntimeClaimCheckRunOutcome };

export interface RuntimeClaimCheckRunRequest {
  /** Raw Evidence JSON values; each is authenticated before any claim is derived. */
  readonly evidence: readonly unknown[];
  /** When set, the committed ledger JSON is written to this path. */
  readonly ledgerPath?: string;
}

const OPERATION = "claim_check_runtime";

const inputError = (
  code: string,
  userMessage: string,
  path: readonly (string | number)[],
  options?: { cause?: unknown },
): AnalysisInputError =>
  new AnalysisInputError(
    OPERATION,
    {
      userMessage,
      ...(options?.cause === undefined ? {} : { cause: options.cause }),
    },
    [
      {
        path: [...path],
        reason: "invalid_value",
        message: `${code}: ${userMessage}`,
      },
    ],
  );

const authenticate = (
  values: readonly unknown[],
): Result<Evidence[], AnalysisError> => {
  const records: Evidence[] = [];
  for (const value of values) {
    try {
      records.push(parseEvidence(value));
    } catch (error) {
      if (error instanceof z.ZodError)
        return err(
          analysisInputErrorFromIssues(OPERATION, error.issues, value, {
            cause: error,
          }),
        );
      throw error;
    }
  }
  return ok(records);
};

/** The one artifact subject every runtime record of the run must agree on. */
const agreeSubject = (
  runtimeRecords: readonly Evidence[],
): Result<{ sha256: string; format: string }, AnalysisError> => {
  const firstSubject = runtimeRecords[0]?.subject;
  if (firstSubject === null || firstSubject === undefined)
    return err(
      inputError(
        "subject_unavailable",
        "Dynamic Evidence does not identify its artifact subject.",
        ["evidence"],
      ),
    );
  for (const record of runtimeRecords) {
    const subject = record.subject;
    if (
      subject === null ||
      subject.digest.sha256 !== firstSubject.digest.sha256 ||
      subject.format !== firstSubject.format
    )
      return err(
        inputError(
          "subject_mismatch",
          "All dynamic Evidence in one run must describe the same artifact subject.",
          ["evidence", record.evidence_id],
        ),
      );
  }
  return ok({
    sha256: firstSubject.digest.sha256,
    format: firstSubject.format,
  });
};

/** Build the validator's view of one group record from its authenticated parts. */
const recordView = (record: Evidence): RuntimeGroupRecord => {
  const parsed = dynamicNormalizedResultSchema.parse(record.normalized_result);
  const derived = deriveRuntimeObservations(record.raw_result);
  return {
    evidenceId: record.evidence_id,
    filed: new Set(parsed.strings.map((row) => `${row.channel}\0${row.value}`)),
    derived: derived.keys,
    derivedObservations: derived.observations,
    rawPresent: Array.isArray(record.raw_result),
    packReadyFound: derived.packReadyFound,
    limitations: record.limitations,
    execution: {
      supervisorReason: parsed.execution.supervisor.reason,
      resumeObserved: parsed.execution.resume_observed,
      containmentBreach: parsed.execution.containment.breach,
      survivorsAfter: parsed.execution.containment.survivors_after,
      packReadyMissing: parsed.execution.pack_ready?.missing ?? null,
      hookPackVersion: parsed.execution.hook_pack_version,
    },
  };
};

/**
 * Run one runtime claim check: authenticate the Evidence, partition the
 * dynamic-execution records into (subject, stimulus) groups, re-derive
 * each record's observations from its preserved raw log, adjudicate each
 * group against its own replay witnesses, and commit the hash-chained
 * ledger. Nothing is executed: adjudication consumes pre-recorded replay
 * Evidence, and the artifact's bytes are never consulted — they are not
 * this class's truth source.
 *
 * Fail-closed throughout: unauthenticated Evidence, a subject mismatch,
 * or a record that cannot name its stimulus aborts before any verdict
 * exists, so no partial adjudication can ever be committed.
 */
export const runRuntimeClaimCheck = async (
  request: RuntimeClaimCheckRunRequest,
  signal?: AbortSignal,
): Promise<Result<RuntimeClaimCheckRunOutcome, AnalysisError>> => {
  const authenticated = authenticate(request.evidence);
  if (!authenticated.ok) return authenticated;
  const runtimeRecords = authenticated.value.filter(isRuntimeEvidence);
  if (runtimeRecords.length === 0)
    return err(
      inputError(
        "no_runtime_evidence",
        "No execute_dynamically Evidence was supplied; there are no runtime claims to adjudicate.",
        ["evidence"],
      ),
    );
  const agreed = agreeSubject(runtimeRecords);
  if (!agreed.ok) return agreed;
  const subject = agreed.value;

  signal?.throwIfAborted();
  let groups: RuntimeEvidenceGroup[];
  try {
    groups = groupRuntimeEvidence(authenticated.value);
  } catch (error) {
    if (error instanceof AnalysisInputError) return err(error);
    throw error;
  }

  const outcomesByClaimId = new Map<
    string,
    { claim: RuntimeClaimRecord; verdict: RuntimeClaimVerdict }
  >();
  const claims: RuntimeClaimRecord[] = [];
  for (const group of groups) {
    signal?.throwIfAborted();
    const { outcomes } = adjudicateRuntimeGroup({
      claims: group.claims,
      records: group.records.map(recordView),
    });
    for (const outcome of outcomes) {
      claims.push(outcome.claim);
      outcomesByClaimId.set(outcome.claim.claim_id, outcome);
    }
  }

  const ordered = [...claims].sort((left, right) =>
    compareAsciiStrings(left.claim_id, right.claim_id),
  );
  const writer = createClaimCheckLedgerWriter({
    subject,
    claims: ordered,
    validator: RUNTIME_CLAIM_VALIDATOR,
  });
  for (const claim of ordered) {
    const outcome = outcomesByClaimId.get(claim.claim_id);
    if (outcome !== undefined)
      writer.appendAdjudication(outcome.claim, outcome.verdict);
  }
  const ledger: ClaimCheckLedger = writer.commitRun(
    runtimeRecords.map((record) => record.evidence_id),
  );

  if (request.ledgerPath !== undefined) {
    try {
      await writeFile(
        request.ledgerPath,
        `${JSON.stringify(ledger, null, 2)}\n`,
      );
    } catch (cause) {
      return err(
        inputError(
          "ledger_write_failed",
          `Claim-check ledger could not be written: ${request.ledgerPath}`,
          ["ledger"],
          { cause },
        ),
      );
    }
  }
  const commit = ledger.entries[ledger.entries.length - 1];
  return ok({
    ledger,
    ledger_path: request.ledgerPath ?? null,
    claims_considered: ledger.summary.adjudications,
    counts: {
      supported: ledger.summary.supported,
      refuted: ledger.summary.refuted,
      unknown: ledger.summary.unknown,
    },
    stale_marked: ledger.summary.stale_marks,
    report_digest: commit?.kind === "run-commit" ? commit.report_digest : "",
  });
};

/** File-shaped entry point shared by the CLI command and the MCP tool. */
export const runRuntimeClaimCheckCommand = async (
  request: {
    readonly evidencePath: string;
    readonly ledgerPath: string;
  },
  signal?: AbortSignal,
): Promise<Result<RuntimeClaimCheckRunOutcome, AnalysisError>> => {
  let text: string;
  try {
    text = await readFile(request.evidencePath, "utf8");
  } catch (cause) {
    return err(
      inputError(
        "evidence_missing",
        `Evidence JSON is missing or unreadable: ${request.evidencePath}`,
        ["evidence"],
        { cause },
      ),
    );
  }
  const decoded = safeParseJson(text);
  if (!decoded.ok)
    return err(
      inputError(
        "evidence_malformed",
        `Evidence JSON could not be parsed: ${request.evidencePath}`,
        ["evidence"],
        { cause: decoded.cause },
      ),
    );
  const evidence = Array.isArray(decoded.value)
    ? decoded.value
    : [decoded.value];
  return runRuntimeClaimCheck(
    { evidence, ledgerPath: request.ledgerPath },
    signal,
  );
};
