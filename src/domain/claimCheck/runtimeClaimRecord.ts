import { z } from "zod";

import { digestCanonicalValue } from "../canonicalDigest.js";
import { isSortedUniqueAscii, uniqueSorted } from "../canonicalOrdering.js";
import { digestSchema, prefixedDigestSchema } from "../digests.js";
import { claimLabelSchema } from "./claimRecord.js";

/** The runtime claim class: string observations filed by controlled replay. */
export const RUNTIME_CLAIM_CLASS = "runtime-string";

/** Output-function channels a runtime string row can be filed under. */
export const runtimeClaimChannelSchema = z.enum([
  "puts",
  "fputs",
  "printf_fmt",
]);
export type RuntimeClaimChannel = z.infer<typeof runtimeClaimChannelSchema>;

/**
 * Digest of one stimulus: the behavior-selecting inputs of a dynamic run.
 * Budgets are excluded (they bound observation completeness, an eligibility
 * question), as are the target locator and the caller's Evidence path
 * (bookkeeping; the subject digest already identifies the artifact).
 */
export const deriveStimulusDigest = (
  argv: readonly string[],
  envSet: Readonly<Record<string, string>>,
): string =>
  digestCanonicalValue(
    { argv: [...argv], env_set: { ...envSet } },
    "Runtime stimulus",
  );

/**
 * The assertion one runtime-string claim makes: under this stimulus, the
 * target emitted this exact value through this output-function channel.
 * Existence only — the producer's filing dedupes occurrences away, so no
 * count or ordering is claimable.
 */
export const runtimeClaimAssertionSchema = z.strictObject({
  value: z.string(),
  channel: runtimeClaimChannelSchema,
  stimulus_digest: digestSchema,
});
export type RuntimeClaimAssertion = z.infer<typeof runtimeClaimAssertionSchema>;

/** Stable identity of one runtime claim: subject, class, stimulus, channel, value. */
export const deriveRuntimeClaimId = (
  subjectSha256: string,
  assertion: RuntimeClaimAssertion,
): string =>
  `cc_${digestCanonicalValue(
    {
      subject_sha256: subjectSha256,
      class: RUNTIME_CLAIM_CLASS,
      stimulus_digest: assertion.stimulus_digest,
      channel: assertion.channel,
      value: assertion.value,
    },
    "Runtime claim ID",
  )}`;

/**
 * Version of one runtime claim: a digest over its assertion payload. The
 * identity already carries value, channel, and stimulus, so a changed value
 * is a different claim, not a new version; the version exists for ledger
 * parity and changes only if the assertion schema grows.
 */
export const deriveRuntimeClaimVersion = (
  assertion: RuntimeClaimAssertion,
): string =>
  digestCanonicalValue(
    {
      value: assertion.value,
      channel: assertion.channel,
      stimulus_digest: assertion.stimulus_digest,
    },
    "Runtime claim version",
  );

const runtimeClaimRecordObjectSchema = z.strictObject({
  claim_id: prefixedDigestSchema("cc"),
  class: z.literal(RUNTIME_CLAIM_CLASS),
  claim_version: digestSchema,
  supersedes: digestSchema.exactOptional(),
  subject: z.strictObject({
    sha256: digestSchema,
    format: z.string().min(1),
  }),
  /** Every record in the claim's group whose filed rows contain the claim. */
  evidence_refs: z.array(prefixedDigestSchema("ev")),
  producer: z.strictObject({
    provider_id: z.string().min(1),
    provider_version: z.string().nullable(),
    operation: z.string().min(1),
  }),
  assertion: runtimeClaimAssertionSchema,
  dependencies: z.array(prefixedDigestSchema("cc")),
  label: claimLabelSchema,
});

/** One adjudicable runtime-string assertion derived from Evidence rows. */
export const runtimeClaimRecordSchema =
  runtimeClaimRecordObjectSchema.superRefine((claim, context) => {
    if (!isSortedUniqueAscii(claim.evidence_refs))
      context.addIssue({
        code: "custom",
        path: ["evidence_refs"],
        message: "Claim evidence refs must be sorted and unique",
      });
    if (!isSortedUniqueAscii(claim.dependencies))
      context.addIssue({
        code: "custom",
        path: ["dependencies"],
        message: "Claim dependencies must be sorted and unique",
      });
    if (
      claim.claim_id !==
      deriveRuntimeClaimId(claim.subject.sha256, claim.assertion)
    )
      context.addIssue({
        code: "custom",
        path: ["claim_id"],
        message: "Claim ID does not match its subject and assertion",
      });
    if (claim.claim_version !== deriveRuntimeClaimVersion(claim.assertion))
      context.addIssue({
        code: "custom",
        path: ["claim_version"],
        message: "Claim version does not match its assertion",
      });
  });

export type RuntimeClaimRecord = z.infer<typeof runtimeClaimRecordObjectSchema>;

/** Envelope facts a runtime string row inherits from its Evidence group. */
export interface RuntimeClaimSource {
  readonly subjectSha256: string;
  readonly subjectFormat: string;
  /** Every group record whose filed rows contain the claim, by Evidence id. */
  readonly evidenceRefs: readonly string[];
  readonly providerId: string;
  readonly providerVersion: string | null;
  readonly operation: string;
  readonly stimulusDigest: string;
}

/** Build one runtime claim from one filed string row and its group source. */
export const buildRuntimeClaim = (
  row: { readonly value: string; readonly channel: RuntimeClaimChannel },
  source: RuntimeClaimSource,
): RuntimeClaimRecord => {
  const assertion: RuntimeClaimAssertion = {
    value: row.value,
    channel: row.channel,
    stimulus_digest: source.stimulusDigest,
  };
  return runtimeClaimRecordSchema.parse({
    claim_id: deriveRuntimeClaimId(source.subjectSha256, assertion),
    class: RUNTIME_CLAIM_CLASS,
    claim_version: deriveRuntimeClaimVersion(assertion),
    subject: { sha256: source.subjectSha256, format: source.subjectFormat },
    evidence_refs: uniqueSorted(source.evidenceRefs),
    producer: {
      provider_id: source.providerId,
      provider_version: source.providerVersion,
      operation: source.operation,
    },
    assertion,
    dependencies: [],
    label: "pipeline-consensus",
  });
};
