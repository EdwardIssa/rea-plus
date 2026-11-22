import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { uniqueSorted } from "../../domain/canonicalOrdering.js";
import {
  buildStringClaim,
  claimRecordSchema,
  type ClaimRecord,
} from "../../domain/claimCheck/claimRecord.js";
import { nativeInventoryRowsSchemas } from "../../domain/native/nativeInventory.js";

const STRING_OPERATIONS: ReadonlySet<string> = new Set([
  "list_strings",
  "search_strings",
]);

/** Whether an Evidence record carries native string rows claim-check can use. */
export const isStringEvidence = (record: Evidence): boolean =>
  STRING_OPERATIONS.has(record.operation);

/**
 * Derive native-string claims from authenticated string Evidence.
 *
 * Two passes: first every record's rows become claims (versions of one claim
 * chain by row order at a shared address), then each claim's dependencies are
 * lifted from its source record's evidence_links through the claims those
 * linked records produced. Links to records outside this set contribute
 * nothing; an empty dependency list is valid and means no cascade applies.
 * Records with other operations are not string sources and are ignored.
 */
export const extractStringClaims = (
  records: readonly Evidence[],
): ClaimRecord[] => {
  const derived: ClaimRecord[] = [];
  const claimIdsByEvidence = new Map<string, string[]>();
  const recordByClaim = new Map<ClaimRecord, Evidence>();

  for (const record of records) {
    if (!isStringEvidence(record)) continue;
    const subject = record.subject;
    if (subject === null)
      throw new AnalysisInputError("claim_check", {}, [
        {
          path: ["evidence", record.evidence_id],
          reason: "invalid_value",
          message:
            "subject_unavailable: string Evidence does not identify its artifact subject",
          expected: "Evidence with an identified artifact subject",
        },
      ]);
    const rows = nativeInventoryRowsSchemas.strings.safeParse(
      record.normalized_result,
    );
    if (!rows.success)
      throw analysisInputErrorFromIssues(
        "claim_check",
        rows.error.issues,
        record.normalized_result,
        { cause: rows.error },
      );
    const lastVersionByClaimId = new Map<string, string>();
    for (const row of rows.data) {
      const claim = buildStringClaim(row, {
        subjectSha256: subject.digest.sha256,
        subjectFormat: subject.format,
        evidenceId: record.evidence_id,
        providerId: record.provider.id,
        providerVersion: record.provider.version,
        operation: record.operation,
      });
      const previousVersion = lastVersionByClaimId.get(claim.claim_id);
      const chained =
        previousVersion === undefined || previousVersion === claim.claim_version
          ? claim
          : claimRecordSchema.parse({
              ...claim,
              supersedes: previousVersion,
            });
      lastVersionByClaimId.set(claim.claim_id, claim.claim_version);
      derived.push(chained);
      recordByClaim.set(chained, record);
      const ids = claimIdsByEvidence.get(record.evidence_id) ?? [];
      ids.push(claim.claim_id);
      claimIdsByEvidence.set(record.evidence_id, ids);
    }
  }

  const unique = new Map<string, ClaimRecord>();
  for (const claim of derived) {
    const record = recordByClaim.get(claim)!;
    const dependencies = uniqueSorted(
      record.evidence_links.flatMap(
        (link) => claimIdsByEvidence.get(link) ?? [],
      ),
    ).filter((dependency) => dependency !== claim.claim_id);
    const withDependencies =
      dependencies.length === claim.dependencies.length
        ? claim
        : claimRecordSchema.parse({ ...claim, dependencies });
    const key = `${claim.claim_id}@${claim.claim_version}`;
    if (!unique.has(key)) unique.set(key, withDependencies);
  }
  return [...unique.values()];
};
