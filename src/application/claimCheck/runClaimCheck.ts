import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";

import { z } from "zod";

import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import { parseEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";
import { safeParseJson } from "../../domain/safeJson.js";
import {
  createClaimCheckLedgerWriter,
  type ClaimCheckLedger,
} from "../../domain/claimCheck/claimCheckLedger.js";
import type { ClaimRecord } from "../../domain/claimCheck/claimRecord.js";
import {
  STRING_CLAIM_VALIDATOR,
  validateStringClaim,
  type StringClaimBytePort,
} from "../../domain/claimCheck/stringClaimValidator.js";
import { compareAsciiStrings } from "../../domain/canonicalOrdering.js";
import {
  extractStringClaims,
  isStringEvidence,
} from "./extractStringClaims.js";
import {
  createElfBytePort,
  openArtifactRangeReader,
  type ArtifactRangeReader,
} from "./elfBytePort.js";

import {
  claimCheckRunOutcomeSchema,
  type ClaimCheckRunOutcome,
} from "../../domain/claimCheck/claimCheckReport.js";
export { claimCheckRunOutcomeSchema, type ClaimCheckRunOutcome };

export interface ClaimCheckRunRequest {
  /** Raw Evidence JSON values; each is authenticated before any claim is derived. */
  readonly evidence: readonly unknown[];
  readonly artifactPath: string;
  /** When set, the committed ledger JSON is written to this path. */
  readonly ledgerPath?: string;
}

const OPERATION = "claim_check";

const inputError = (
  code: string,
  userMessage: string,
  path: readonly (string | number)[],
  options?: {
    reason?: "invalid_value" | "invalid_format";
    conformsToInputContract?: boolean;
    cause?: unknown;
  },
): AnalysisInputError =>
  new AnalysisInputError(
    OPERATION,
    {
      userMessage,
      ...(options?.conformsToInputContract === undefined
        ? {}
        : { conformsToInputContract: options.conformsToInputContract }),
      ...(options?.cause === undefined ? {} : { cause: options.cause }),
    },
    [
      {
        path: [...path],
        reason: options?.reason ?? "invalid_value",
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

const digestArtifact = async (path: string): Promise<string> => {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
};

const unsupportedFormatPort = (): StringClaimBytePort => ({
  mapAddress: () => ({ kind: "unmapped" }),
  readRange: () => Promise.resolve(undefined),
});

/**
 * Run one claim check: authenticate the Evidence, verify the artifact is the
 * subject the Evidence names, derive string claims, adjudicate each against
 * the artifact's own bytes, and commit the hash-chained ledger.
 *
 * Fail-closed throughout: unauthenticated Evidence, a missing artifact, or a
 * digest mismatch aborts before any verdict exists, so no partial
 * adjudication can ever be committed.
 */
export const runClaimCheck = async (
  request: ClaimCheckRunRequest,
  signal?: AbortSignal,
): Promise<Result<ClaimCheckRunOutcome, AnalysisError>> => {
  const authenticated = authenticate(request.evidence);
  if (!authenticated.ok) return authenticated;
  const stringRecords = authenticated.value.filter(isStringEvidence);
  if (stringRecords.length === 0)
    return err(
      inputError(
        "no_string_evidence",
        "No list_strings or search_strings Evidence was supplied; there are no string claims to adjudicate.",
        ["evidence"],
      ),
    );
  const firstSubject = stringRecords[0]?.subject;
  if (firstSubject === null || firstSubject === undefined)
    return err(
      inputError(
        "subject_unavailable",
        "String Evidence does not identify its artifact subject.",
        ["evidence"],
      ),
    );
  for (const record of stringRecords) {
    const subject = record.subject;
    if (
      subject === null ||
      subject.digest.sha256 !== firstSubject.digest.sha256 ||
      subject.format !== firstSubject.format
    )
      return err(
        inputError(
          "subject_mismatch",
          "All string Evidence in one run must describe the same artifact subject.",
          ["evidence", record.evidence_id],
        ),
      );
  }
  const subject = {
    sha256: firstSubject.digest.sha256,
    format: firstSubject.format,
  };

  let reader: ArtifactRangeReader;
  try {
    reader = await openArtifactRangeReader(request.artifactPath);
  } catch (cause) {
    return err(
      inputError(
        "artifact_missing",
        `Artifact is missing or unreadable: ${request.artifactPath}`,
        ["artifact"],
        { cause },
      ),
    );
  }
  try {
    signal?.throwIfAborted();
    const artifactDigest = await digestArtifact(request.artifactPath);
    if (artifactDigest !== subject.sha256)
      return err(
        inputError(
          "artifact_digest_mismatch",
          `Artifact SHA-256 ${artifactDigest} does not match the Evidence subject ${subject.sha256}; refusing to adjudicate claims against the wrong artifact.`,
          ["artifact"],
          { conformsToInputContract: true },
        ),
      );

    let claims: ClaimRecord[];
    try {
      claims = extractStringClaims(stringRecords);
    } catch (error) {
      if (error instanceof AnalysisInputError) return err(error);
      throw error;
    }
    const ordered = [...claims].sort(
      (left, right) =>
        compareAsciiStrings(left.claim_id, right.claim_id) ||
        compareAsciiStrings(left.claim_version, right.claim_version),
    );

    const port =
      subject.format === "elf"
        ? await createElfBytePort(reader)
        : unsupportedFormatPort();
    const writer = createClaimCheckLedgerWriter({
      subject,
      claims: ordered,
      validator: STRING_CLAIM_VALIDATOR,
    });
    for (const claim of ordered) {
      signal?.throwIfAborted();
      const verdict = await validateStringClaim(claim, port);
      writer.appendAdjudication(claim, verdict);
    }
    const ledger: ClaimCheckLedger = writer.commitRun(
      stringRecords.map((record) => record.evidence_id),
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
  } finally {
    await reader.close();
  }
};

/** File-shaped entry point shared by the CLI command and the MCP tool. */
export const runClaimCheckCommand = async (
  request: {
    readonly evidencePath: string;
    readonly artifactPath: string;
    readonly ledgerPath: string;
  },
  signal?: AbortSignal,
): Promise<Result<ClaimCheckRunOutcome, AnalysisError>> => {
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
        { reason: "invalid_format", cause: decoded.cause },
      ),
    );
  const evidence = Array.isArray(decoded.value)
    ? decoded.value
    : [decoded.value];
  return runClaimCheck(
    {
      evidence,
      artifactPath: request.artifactPath,
      ledgerPath: request.ledgerPath,
    },
    signal,
  );
};
