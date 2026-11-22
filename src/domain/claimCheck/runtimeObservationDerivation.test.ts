import { describe, expect, it } from "vitest";

import type { JsonValue } from "../jsonValue.js";
import {
  deriveRuntimeObservations,
  runtimeObservationKey,
} from "./runtimeObservationDerivation.js";

const send = (payload: Record<string, JsonValue>): JsonValue =>
  ({ type: "send", payload }) as JsonValue;

describe("runtime observation derivation", () => {
  it("derives deduplicated (channel, value) observations from send payloads", () => {
    const derived = deriveRuntimeObservations([
      send({ t: "pack_ready", version: "1.1.0", hooked: [], missing: [] }),
      send({ t: "puts", text: "alpha-secret-one" }),
      send({ t: "puts", text: "alpha-secret-one" }),
      send({ t: "fputs", text: "alpha-secret-one" }),
      send({ t: "printf_fmt", text: "value=%d" }),
    ]);
    expect(derived.packReadyFound).toBe(true);
    expect(derived.packVersion).toBe("1.1.0");
    expect(derived.observations).toEqual([
      { channel: "fputs", value: "alpha-secret-one" },
      { channel: "printf_fmt", value: "value=%d" },
      { channel: "puts", value: "alpha-secret-one" },
    ]);
    expect(
      derived.keys.has(runtimeObservationKey("puts", "alpha-secret-one")),
    ).toBe(true);
  });

  it("excludes MARK: attribution lines and non-string texts", () => {
    const derived = deriveRuntimeObservations([
      send({ t: "puts", text: "MARK:main" }),
      send({ t: "puts", text: 42 as unknown as JsonValue }),
      send({ t: "write", fd: 1, data: [104, 105] }),
      send({ t: "dlopen", path: "./libplug.so", ok: true }),
    ]);
    expect(derived.observations).toEqual([]);
    expect(derived.packReadyFound).toBe(false);
  });

  it("ignores messages outside the send envelope and non-array logs", () => {
    const bare = deriveRuntimeObservations([
      { t: "puts", text: "bare-payload" } as JsonValue,
      { type: "error", payload: { t: "puts", text: "errored" } } as JsonValue,
    ]);
    expect(bare.observations).toEqual([]);
    for (const absent of [null, undefined, "log", 7, { messages: [] }]) {
      const derived = deriveRuntimeObservations(absent);
      expect(derived.observations).toEqual([]);
      expect(derived.packReadyFound).toBe(false);
      expect(derived.packVersion).toBeNull();
    }
  });
});
