import { createHash } from "node:crypto";

import { z } from "zod";

import type { ClaimAssertion, ClaimRecord } from "./claimRecord.js";

/** The deterministic byte validator's identity, recorded on every verdict. */
export const STRING_CLAIM_VALIDATOR = {
  id: "rea-string-bytes",
  version: "1.0.0",
} as const;

/** Adjudication states a claim-check verdict can carry. */
export const adjudicationStateSchema = z.enum([
  "supported",
  "refuted",
  "unknown",
]);
export type AdjudicationState = z.infer<typeof adjudicationStateSchema>;

/** Reason vocabulary for string-claim verdicts; every verdict names one. */
export const adjudicationReasonSchema = z.enum([
  "bytes_match",
  "bytes_mismatch",
  "address_unmapped",
  "encoding_undeclared",
  "artifact_missing",
  "format_not_supported",
  "assertion_malformed",
]);
export type AdjudicationReason = z.infer<typeof adjudicationReasonSchema>;

/** Where a claimed address lands in the artifact, as the byte port sees it. */
export type ClaimAddressMapping =
  | { readonly kind: "mapped"; readonly offset: number }
  | { readonly kind: "unmapped" }
  | { readonly kind: "malformed" };

/**
 * The validator's only view of the artifact. Implementations preload whatever
 * headers they need so `mapAddress` is synchronous; `readRange` returns
 * undefined when the requested bytes are not fully present, so a truncated
 * read can never be mistaken for a mismatch.
 */
export interface StringClaimBytePort {
  mapAddress(address: string): ClaimAddressMapping;
  readRange(offset: number, length: number): Promise<Uint8Array | undefined>;
}

/** One validator decision: a state, its reason, and what was actually read. */
export interface StringClaimVerdict {
  readonly state: AdjudicationState;
  readonly reason: AdjudicationReason;
  readonly observed?: {
    readonly bytes_digest: string;
    readonly byte_length: number;
  };
}

type Codec = "utf-8" | "ascii" | "latin1" | "utf-16le" | "utf-16be";

const codecFor = (encoding: string): Codec | undefined => {
  switch (encoding.toLowerCase().replace(/[-_]/gu, "")) {
    case "utf8":
      return "utf-8";
    case "ascii":
    case "usascii":
    case "ansix341968":
      return "ascii";
    case "latin1":
    case "iso88591":
    case "iso8859":
    case "windows1252":
      return "latin1";
    case "utf16le":
    case "ucs2":
      return "utf-16le";
    case "utf16be":
      return "utf-16be";
    default:
      return undefined;
  }
};

const encodeValue = (value: string, codec: Codec): Uint8Array => {
  switch (codec) {
    case "utf-8":
      return Buffer.from(value, "utf8");
    case "ascii":
    case "latin1":
      // For ASCII text these encodings coincide byte for byte; latin1 keeps
      // the high half deterministic instead of masking it away.
      return Buffer.from(value, "latin1");
    case "utf-16le":
      return Buffer.from(value, "utf16le");
    case "utf-16be": {
      const little = Buffer.from(value, "utf16le");
      const big = new Uint8Array(little.length);
      for (let index = 0; index + 1 < little.length; index += 2) {
        big[index] = little[index + 1]!;
        big[index + 1] = little[index]!;
      }
      return big;
    }
  }
};

/**
 * The exact stored byte form a claim asserts: the encoded value plus its
 * terminator when termination is not `missing` (a value already ending in
 * the terminator is not terminated twice). `byte_length` is the full stored
 * extent, terminator included, so the canonical form exists only when the
 * stored form occupies exactly the declared byte_length; any other extent
 * is a mismatch once bytes are read.
 */
const canonicalBytes = (
  assertion: ClaimAssertion,
  valueBytes: Uint8Array,
  codec: Codec,
): {
  readonly bytes: Uint8Array | undefined;
  readonly storedLength: number;
} => {
  let stored = valueBytes;
  if (assertion.termination !== "missing") {
    const terminator =
      codec === "utf-16le" || codec === "utf-16be"
        ? new Uint8Array([0, 0])
        : new Uint8Array([0]);
    const alreadyTerminated =
      valueBytes.length >= terminator.length &&
      terminator.every(
        (byte, index) =>
          valueBytes[valueBytes.length - terminator.length + index] === byte,
      );
    if (!alreadyTerminated) {
      stored = new Uint8Array(valueBytes.length + terminator.length);
      stored.set(valueBytes);
      stored.set(terminator, valueBytes.length);
    }
  }
  return {
    bytes:
      assertion.byte_length === null || assertion.byte_length === stored.length
        ? stored
        : undefined,
    storedLength: stored.length,
  };
};

const unknown = (reason: AdjudicationReason): StringClaimVerdict => ({
  state: "unknown",
  reason,
});

const withObserved = (
  state: "supported" | "refuted",
  reason: AdjudicationReason,
  observed: Uint8Array,
): StringClaimVerdict => ({
  state,
  reason,
  observed: {
    bytes_digest: createHash("sha256").update(observed).digest("hex"),
    byte_length: observed.length,
  },
});

/**
 * The brain: pure evaluation of one string claim against artifact bytes.
 * It writes nothing and launches nothing; every input it cannot adjudicate
 * honestly becomes `unknown` with the reason, never a guessed verdict.
 */
export const validateStringClaim = async (
  claim: ClaimRecord,
  port: StringClaimBytePort,
): Promise<StringClaimVerdict> => {
  const { assertion } = claim;
  if (claim.subject.format !== "elf") return unknown("format_not_supported");
  if (assertion.value_form === "display") return unknown("assertion_malformed");

  // Criterion: an undeclared encoding with no byte_length to bound a raw-byte
  // comparison cannot be adjudicated; with byte_length present the comparison
  // is attempted on the row's stated encoding first.
  const declared =
    assertion.encoding !== null && assertion.encoding_status !== "inferred";
  if (assertion.byte_length === null && !declared)
    return unknown("encoding_undeclared");
  const codec =
    assertion.encoding === null ? undefined : codecFor(assertion.encoding);
  if (codec === undefined) return unknown("encoding_undeclared");
  const valueBytes = encodeValue(assertion.value, codec);
  const canonical = canonicalBytes(assertion, valueBytes, codec);
  const readLength = assertion.byte_length ?? canonical.storedLength;

  const mapping = port.mapAddress(claim.location.address);
  if (mapping.kind === "malformed") return unknown("assertion_malformed");
  if (mapping.kind === "unmapped") return unknown("address_unmapped");
  const observed = await port.readRange(mapping.offset, readLength);
  if (observed === undefined || observed.length < readLength)
    return unknown("address_unmapped");

  const expected = canonical.bytes;
  if (expected === undefined)
    return withObserved("refuted", "bytes_mismatch", observed);
  const matches =
    observed.length === expected.length &&
    observed.every((byte, index) => byte === expected[index]);
  return matches
    ? withObserved("supported", "bytes_match", observed)
    : withObserved("refuted", "bytes_mismatch", observed);
};
