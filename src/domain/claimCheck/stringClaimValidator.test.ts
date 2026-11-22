import { describe, expect, it } from "vitest";

import {
  buildStringClaim,
  type ClaimRecord,
  type StringClaimSource,
} from "./claimRecord.js";
import {
  validateStringClaim,
  type ClaimAddressMapping,
  type StringClaimBytePort,
} from "./stringClaimValidator.js";

const SHA = "a".repeat(64);
const BASE = 0x1000n;

const source = (format = "elf"): StringClaimSource => ({
  subjectSha256: SHA,
  subjectFormat: format,
  evidenceId: `ev_${"b".repeat(64)}`,
  providerId: "ghidra",
  providerVersion: "12.1.4",
  operation: "list_strings",
});

/** In-memory port: one mapped region starting at BASE, nothing beyond it. */
const portOver = (bytes: Uint8Array): StringClaimBytePort => ({
  mapAddress: (address): ClaimAddressMapping => {
    if (!/^0x[0-9a-fA-F]+$/u.test(address)) return { kind: "malformed" };
    const offset = Number(BigInt(address) - BASE);
    return offset >= 0 && offset < bytes.length
      ? { kind: "mapped", offset }
      : { kind: "unmapped" };
  },
  readRange: (offset, length) =>
    Promise.resolve(
      offset + length <= bytes.length
        ? bytes.subarray(offset, offset + length)
        : undefined,
    ),
});

const claim = (
  row: Parameters<typeof buildStringClaim>[0],
  format = "elf",
): ClaimRecord => buildStringClaim(row, source(format));

const utf8Row = (overrides: Record<string, unknown> = {}) => ({
  address: "0x1000",
  value: "hello",
  string: {
    encoding: "utf-8",
    encoding_status: "observed" as const,
    termination: "present_or_not_required" as const,
    byte_length: 6,
  },
  ...overrides,
});

// "hello\0" followed by a distinctive non-zero byte.
const helloBytes = new Uint8Array([
  0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x4e, 0x4f,
]);

// oxlint-disable-next-line max-lines-per-function -- the decision-matrix cases share one in-memory byte port fixture.
describe("string claim validator", () => {
  it("supports a claim whose bytes match, terminator included", async () => {
    const verdict = await validateStringClaim(
      claim(utf8Row()),
      portOver(helloBytes),
    );
    expect(verdict.state).toBe("supported");
    expect(verdict.reason).toBe("bytes_match");
    expect(verdict.observed?.byte_length).toBe(6);
  });

  it("supports a non-terminated string compared at exactly byte_length", async () => {
    const verdict = await validateStringClaim(
      claim(
        utf8Row({
          value: "hell",
          string: {
            encoding: "utf-8",
            encoding_status: "observed",
            termination: "missing",
            byte_length: 4,
          },
        }),
      ),
      portOver(helloBytes),
    );
    expect(verdict.state).toBe("supported");
  });

  it("refutes a claim with one character changed", async () => {
    const verdict = await validateStringClaim(
      claim(utf8Row({ value: "hellp" })),
      portOver(helloBytes),
    );
    expect(verdict.state).toBe("refuted");
    expect(verdict.reason).toBe("bytes_mismatch");
    expect(verdict.observed?.byte_length).toBe(6);
  });

  it("refutes byte_length one too long and one too short", async () => {
    const longer = await validateStringClaim(
      claim(
        utf8Row({
          string: {
            encoding: "utf-8",
            encoding_status: "observed",
            termination: "present_or_not_required",
            byte_length: 7,
          },
        }),
      ),
      portOver(helloBytes),
    );
    expect(longer.state).toBe("refuted");
    const shorter = await validateStringClaim(
      claim(
        utf8Row({
          string: {
            encoding: "utf-8",
            encoding_status: "observed",
            termination: "present_or_not_required",
            byte_length: 5,
          },
        }),
      ),
      portOver(helloBytes),
    );
    expect(shorter.state).toBe("refuted");
  });

  it("never supports a claim whose location shifted by one byte", async () => {
    const verdict = await validateStringClaim(
      claim(utf8Row({ address: "0x1001" })),
      portOver(helloBytes),
    );
    expect(verdict.state).not.toBe("supported");
    expect(verdict.state).toBe("refuted");
  });

  it("answers unknown for an address beyond the mapped region", async () => {
    const verdict = await validateStringClaim(
      claim(utf8Row({ address: "0x9000" })),
      portOver(helloBytes),
    );
    expect(verdict).toEqual({ state: "unknown", reason: "address_unmapped" });
  });

  it("answers unknown when the read runs past the end of the artifact", async () => {
    const verdict = await validateStringClaim(
      claim(
        utf8Row({
          address: "0x1006",
          string: {
            encoding: "utf-8",
            encoding_status: "observed",
            termination: "present_or_not_required",
            byte_length: 6,
          },
        }),
      ),
      portOver(helloBytes),
    );
    expect(verdict).toEqual({ state: "unknown", reason: "address_unmapped" });
  });

  it("answers unknown for non-ELF subjects without touching bytes", async () => {
    const verdict = await validateStringClaim(
      claim(utf8Row(), "mach-o"),
      portOver(helloBytes),
    );
    expect(verdict).toEqual({
      state: "unknown",
      reason: "format_not_supported",
    });
  });

  it("answers unknown when the encoding is inferred and no byte_length bounds the read", async () => {
    const verdict = await validateStringClaim(
      claim({ address: "0x1000", value: "hello" }),
      portOver(helloBytes),
    );
    expect(verdict).toEqual({
      state: "unknown",
      reason: "encoding_undeclared",
    });
  });

  it("attempts the raw-byte comparison for inferred encodings when byte_length is present", async () => {
    const verdict = await validateStringClaim(
      claim(
        utf8Row({
          string: {
            encoding: "utf-8",
            encoding_status: "inferred",
            termination: "present_or_not_required",
            byte_length: 6,
          },
        }),
      ),
      portOver(helloBytes),
    );
    expect(verdict.state).toBe("supported");
  });

  it("answers unknown for an encoding the validator cannot encode", async () => {
    const verdict = await validateStringClaim(
      claim(
        utf8Row({
          string: {
            encoding: "shift-jis",
            encoding_status: "observed",
            termination: "present_or_not_required",
            byte_length: 6,
          },
        }),
      ),
      portOver(helloBytes),
    );
    expect(verdict).toEqual({
      state: "unknown",
      reason: "encoding_undeclared",
    });
  });

  it("answers unknown for display-text values and malformed addresses", async () => {
    const display = await validateStringClaim(
      claim(utf8Row({ decoding: { available: false, reason: "undecodable" } })),
      portOver(helloBytes),
    );
    expect(display).toEqual({
      state: "unknown",
      reason: "assertion_malformed",
    });
    const malformed = await validateStringClaim(
      claim(utf8Row({ address: "not-an-address" })),
      portOver(helloBytes),
    );
    expect(malformed).toEqual({
      state: "unknown",
      reason: "assertion_malformed",
    });
  });

  it("supports UTF-16LE claims", async () => {
    const utf16 = new Uint8Array([
      0x68,
      0x00,
      0x69,
      0x00,
      0x00,
      0x00, // "hi" + NUL, UTF-16LE
    ]);
    const verdict = await validateStringClaim(
      claim(
        utf8Row({
          value: "hi",
          string: {
            encoding: "utf-16le",
            encoding_status: "observed",
            termination: "present_or_not_required",
            byte_length: 6,
          },
        }),
      ),
      portOver(utf16),
    );
    expect(verdict.state).toBe("supported");
  });
});
