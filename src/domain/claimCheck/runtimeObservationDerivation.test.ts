import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

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

describe("runtime derivation independence", () => {
  // The phantom-row guarantee is structural: the validator's re-derivation
  // must be its own implementation, so a defect in the producer's filing
  // cannot reproduce itself inside the check. Behavioral equivalence on
  // well-formed logs is expected and proves nothing; this source audit is
  // the load-bearing guard, and it fails the moment the derivation (or the
  // validator) imports the producer's filing code.
  it("derives observations without importing the producer's filing code", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    for (const module of [
      "runtimeObservationDerivation.ts",
      "runtimeReplayValidator.ts",
    ]) {
      const source = readFileSync(join(here, module), "utf8");
      expect(source, module).not.toMatch(/dynamicExecution/u);
      expect(source, module).not.toMatch(/fileDynamicObservations/u);
    }
  });
});
