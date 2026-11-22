import { z } from "zod";

import { digestCanonicalValue } from "../canonicalDigest.js";
import { isSortedUniqueAscii } from "../canonicalOrdering.js";
import { digestSchema, prefixedDigestSchema } from "../digests.js";
import type { analysisStringSchema } from "../native/nativeString.js";

/** The only claim class adjudicated by the claim-check MVP. */
export const CLAIM_CHECK_CLASS = "native-string";

/**
 * Truth-block label a claim enters with (Edward's labeling policy): a pipeline
 * string row is pipeline consensus at best until a byte verdict promotes the
 * verdict, never the claim itself.
 */
export const claimLabelSchema = z.enum([
  "verified-fact",
  "pipeline-consensus",
  "interpretation",
]);
export type ClaimLabel = z.infer<typeof claimLabelSchema>;

/**
 * One adjudicable assertion, normalized from one provider string row.
 * Fields the row never declared are null, never invented: a null encoding or
 * byte_length is exactly what lets the validator answer `encoding_undeclared`
 * instead of guessing.
 */
export const claimAssertionSchema = z.strictObject({
  value: z.string(),
  encoding: z.string().min(1).nullable(),
  encoding_status: z.enum(["observed", "inferred"]).nullable(),
  byte_length: z.int().min(0).nullable(),
  termination: z.enum(["missing", "present_or_not_required"]).nullable(),
  /** `display` when the row's value is provider display text, not typed bytes. */
  value_form: z.enum(["typed", "display"]),
});
export type ClaimAssertion = z.infer<typeof claimAssertionSchema>;

/** Stable identity of one claim: the artifact, the class, and the address. */
export const deriveStringClaimId = (
  subjectSha256: string,
  address: string,
): string =>
  `cc_${digestCanonicalValue(
    { subject_sha256: subjectSha256, class: CLAIM_CHECK_CLASS, address },
    "Claim ID",
  )}`;

/** Version of one claim: a digest over its complete assertion payload. */
export const deriveClaimVersion = (assertion: ClaimAssertion): string =>
  digestCanonicalValue(
    {
      value: assertion.value,
      encoding: assertion.encoding,
      encoding_status: assertion.encoding_status,
      byte_length: assertion.byte_length,
      termination: assertion.termination,
      value_form: assertion.value_form,
    },
    "Claim version",
  );

const claimRecordObjectSchema = z.strictObject({
  claim_id: prefixedDigestSchema("cc"),
  class: z.literal(CLAIM_CHECK_CLASS),
  claim_version: digestSchema,
  supersedes: digestSchema.exactOptional(),
  subject: z.strictObject({
    sha256: digestSchema,
    format: z.string().min(1),
  }),
  evidence_ref: prefixedDigestSchema("ev"),
  producer: z.strictObject({
    provider_id: z.string().min(1),
    provider_version: z.string().nullable(),
    operation: z.string().min(1),
  }),
  location: z.strictObject({ address: z.string().min(1) }),
  assertion: claimAssertionSchema,
  dependencies: z.array(prefixedDigestSchema("cc")),
  label: claimLabelSchema,
});

/** One adjudicable native-string assertion derived from one Evidence row. */
export const claimRecordSchema = claimRecordObjectSchema.superRefine(
  (claim, context) => {
    if (!isSortedUniqueAscii(claim.dependencies))
      context.addIssue({
        code: "custom",
        path: ["dependencies"],
        message: "Claim dependencies must be sorted and unique",
      });
    if (
      claim.claim_id !==
      deriveStringClaimId(claim.subject.sha256, claim.location.address)
    )
      context.addIssue({
        code: "custom",
        path: ["claim_id"],
        message: "Claim ID does not match its subject and address",
      });
    if (claim.claim_version !== deriveClaimVersion(claim.assertion))
      context.addIssue({
        code: "custom",
        path: ["claim_version"],
        message: "Claim version does not match its assertion",
      });
  },
);

export type ClaimRecord = z.infer<typeof claimRecordObjectSchema>;

/** Envelope facts a string row inherits from its source Evidence record. */
export interface StringClaimSource {
  readonly subjectSha256: string;
  readonly subjectFormat: string;
  readonly evidenceId: string;
  readonly providerId: string;
  readonly providerVersion: string | null;
  readonly operation: string;
}

type AnalysisStringRow = z.infer<typeof analysisStringSchema>;

/** Normalize one provider string row into its claim assertion. */
export const assertionFromStringRow = (
  row: AnalysisStringRow,
): ClaimAssertion => ({
  value: row.value,
  encoding: row.string?.encoding ?? null,
  encoding_status: row.string?.encoding_status ?? null,
  byte_length: row.string?.byte_length ?? null,
  termination: row.string?.termination ?? null,
  value_form: row.decoding === undefined ? "typed" : "display",
});

/**
 * Build one claim from one string row. `supersedes` links a changed assertion
 * at the same address to the version it replaces; dependencies are attached by
 * the extractor once every record's claims are known.
 */
export const buildStringClaim = (
  row: AnalysisStringRow,
  source: StringClaimSource,
  supersedes?: string,
): ClaimRecord => {
  const assertion = assertionFromStringRow(row);
  return claimRecordSchema.parse({
    claim_id: deriveStringClaimId(source.subjectSha256, row.address),
    class: CLAIM_CHECK_CLASS,
    claim_version: deriveClaimVersion(assertion),
    ...(supersedes === undefined ? {} : { supersedes }),
    subject: { sha256: source.subjectSha256, format: source.subjectFormat },
    evidence_ref: source.evidenceId,
    producer: {
      provider_id: source.providerId,
      provider_version: source.providerVersion,
      operation: source.operation,
    },
    location: { address: row.address },
    assertion,
    dependencies: [],
    label: "pipeline-consensus",
  });
};
