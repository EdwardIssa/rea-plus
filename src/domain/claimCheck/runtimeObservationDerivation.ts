import type { JsonValue } from "../jsonValue.js";
import type { RuntimeClaimChannel } from "./runtimeClaimRecord.js";

/**
 * The claim-check validator's own re-derivation of runtime observations
 * from an Evidence record's preserved `raw_result` message log.
 *
 * This is an independent implementation of the hook pack's message
 * semantics (the pack sends `{ t, text }` payloads for its output-function
 * captures and one `pack_ready` payload at load), written from the pack's
 * documented behavior. It deliberately shares no code with the producer's
 * filing implementation: a check that re-runs the producer's own function
 * compares the producer against itself — pipeline agreement, not
 * adjudication — and filing defects in that function would be invisible
 * to it. The two implementations agreeing is the fidelity signal.
 *
 * Semantics, mirroring the filing rules a filed row asserts:
 * - only session `send` messages with a record payload are hook messages;
 * - payloads with `t` in {puts, fputs, printf_fmt} and a string `text`
 *   contribute one (channel, text) observation;
 * - `MARK:`-prefixed texts are fixture attribution, never content;
 * - the set is deduplicated per (channel, value), as the filed rows are.
 */

/** One re-derived observation: a value seen on one output channel. */
export interface RuntimeObservation {
  readonly channel: RuntimeClaimChannel;
  readonly value: string;
}

/** Set key for one observation; channel and value are both identity parts. */
export const runtimeObservationKey = (
  channel: RuntimeClaimChannel,
  value: string,
): string => `${channel}\0${value}`;

/** What re-derivation recovered from one record's preserved log. */
export interface DerivedRuntimeObservations {
  /** The deduplicated observation set, sorted by (channel, value). */
  readonly observations: readonly RuntimeObservation[];
  /** The same set as lookup keys. */
  readonly keys: ReadonlySet<string>;
  /** Whether the log contained a `pack_ready` payload at all. */
  readonly packReadyFound: boolean;
  /** The pack version the log's `pack_ready` payload declared, if any. */
  readonly packVersion: string | null;
}

const CHANNELS: ReadonlySet<string> = new Set(["puts", "fputs", "printf_fmt"]);

const isRecord = (value: unknown): value is Record<string, JsonValue> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Re-derive the observation set from one record's raw message log. */
export const deriveRuntimeObservations = (
  rawResult: unknown,
): DerivedRuntimeObservations => {
  const observations = new Map<string, RuntimeObservation>();
  let packReadyFound = false;
  let packVersion: string | null = null;
  if (Array.isArray(rawResult)) {
    for (const message of rawResult as readonly JsonValue[]) {
      if (!isRecord(message) || message.type !== "send") continue;
      const payload = message.payload;
      if (!isRecord(payload)) continue;
      if (payload.t === "pack_ready") {
        packReadyFound = true;
        packVersion =
          typeof payload.version === "string" ? payload.version : null;
        continue;
      }
      if (typeof payload.t !== "string" || !CHANNELS.has(payload.t)) continue;
      const text = payload.text;
      if (typeof text !== "string" || text.startsWith("MARK:")) continue;
      const channel = payload.t as RuntimeClaimChannel;
      const key = runtimeObservationKey(channel, text);
      if (!observations.has(key))
        observations.set(key, { channel, value: text });
    }
  }
  const sorted = [...observations.values()].sort((left, right) =>
    left.channel === right.channel
      ? left.value < right.value
        ? -1
        : left.value > right.value
          ? 1
          : 0
      : left.channel < right.channel
        ? -1
        : 1,
  );
  return {
    observations: sorted,
    keys: new Set(observations.keys()),
    packReadyFound,
    packVersion,
  };
};
