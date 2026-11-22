import type { Evidence } from "../../domain/evidence.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import {
  parseSegmentImageBase,
  parseSegments,
} from "../../domain/native/nativeSegments.js";
import { parseClaimAddress, type ElfAddressRelocation } from "./elfBytePort.js";
import { isStringEvidence } from "./extractStringClaims.js";

/**
 * The recorded image base in one non-string Evidence result, when the
 * producer reported one: a segment inventory carries it per segment (the
 * overview base exists only when every segment agrees, the domain's own
 * rule), and an overview or load-image observation carries it directly.
 * Anything else — no base, an unparseable base, segments that disagree —
 * reports nothing, because a relocation must be a recorded fact.
 */
const recordedImageBase = (result: JsonValue): bigint | undefined => {
  if (Array.isArray(result)) {
    const segments = parseSegments(result);
    if (!segments.ok) return undefined;
    const base = parseSegmentImageBase(segments.value);
    return base === undefined ? undefined : parseClaimAddress(base);
  }
  if (typeof result === "object" && result !== null) {
    const base = (result as Readonly<Record<string, JsonValue>>).image_base;
    return typeof base === "string" ? parseClaimAddress(base) : undefined;
  }
  return undefined;
};

/**
 * Derive per-producer address relocation from the Evidence set itself: a
 * binary overview, segment inventory, or load-image record for the same
 * subject states the image base the target was loaded at, and claim
 * adjudication for the claims it describes applies it. Attribution follows
 * recorded facts only:
 *
 * - a context record from a producer that also produced string claims in
 *   the set describes that producer's own loading;
 * - a context record from a composing layer that produced no string claims
 *   (the `binary_overview` workflow record) describes the one session
 *   behind the set, so it is attributed to the set's string producer when
 *   there is exactly one — with several, attribution would be a guess and
 *   the context is dropped;
 * - string records never supply context for themselves, records about
 *   another subject are ignored, and disagreeing bases for one producer
 *   cancel it: an ambiguous base is no base, never a guessed one.
 */
export const deriveClaimRelocations = (
  records: readonly Evidence[],
  subjectSha256: string,
): ReadonlyMap<string, ElfAddressRelocation> => {
  const aboutSubject = records.filter((record) => {
    const subject = record.subject;
    return subject !== null && subject.digest.sha256 === subjectSha256;
  });
  const stringProviders = new Set(
    aboutSubject
      .filter((record) => isStringEvidence(record))
      .map((record) => record.provider.id),
  );
  const ownBases = new Map<string, Set<bigint>>();
  const composedBases = new Set<bigint>();
  for (const record of aboutSubject) {
    if (isStringEvidence(record)) continue;
    const candidate = recordedImageBase(record.normalized_result);
    if (candidate === undefined) continue;
    if (stringProviders.has(record.provider.id)) {
      const bases = ownBases.get(record.provider.id) ?? new Set<bigint>();
      bases.add(candidate);
      ownBases.set(record.provider.id, bases);
    } else {
      composedBases.add(candidate);
    }
  }
  const soleStringProvider =
    stringProviders.size === 1 ? [...stringProviders][0] : undefined;
  const relocations = new Map<string, ElfAddressRelocation>();
  for (const providerId of stringProviders) {
    const candidates = new Set(ownBases.get(providerId) ?? []);
    if (providerId === soleStringProvider)
      for (const base of composedBases) candidates.add(base);
    if (candidates.size === 1)
      relocations.set(providerId, { imageBase: [...candidates][0]! });
  }
  return relocations;
};
