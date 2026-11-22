import { describe, expect, it } from "vitest";

import {
  buildStringClaim,
  claimRecordSchema,
  deriveClaimVersion,
  deriveStringClaimId,
  type StringClaimSource,
} from "./claimRecord.js";

const SHA = "a".repeat(64);

const source: StringClaimSource = {
  subjectSha256: SHA,
  subjectFormat: "elf",
  evidenceId: `ev_${"b".repeat(64)}`,
  providerId: "ghidra",
  providerVersion: "12.1.4",
  operation: "list_strings",
};

const row = (overrides: Record<string, unknown> = {}) => ({
  address: "0x1011ad",
  value: "hello",
  string: {
    encoding: "utf-8",
    encoding_status: "observed" as const,
    termination: "present_or_not_required" as const,
    byte_length: 6,
  },
  ...overrides,
});

describe("string claim derivation", () => {
  it("derives a stable claim id from subject, class, and address", () => {
    const first = buildStringClaim(row(), source);
    const second = buildStringClaim(row(), source);
    expect(first.claim_id).toBe(second.claim_id);
    expect(first.claim_id).toBe(deriveStringClaimId(SHA, "0x1011ad"));
    expect(first.claim_id).toMatch(/^cc_[a-f0-9]{64}$/u);
    expect(first.label).toBe("pipeline-consensus");
    expect(first.dependencies).toEqual([]);
  });

  it("changes the version, not the id, when the assertion changes", () => {
    const original = buildStringClaim(row(), source);
    const changed = buildStringClaim(row({ value: "hellp" }), source);
    expect(changed.claim_id).toBe(original.claim_id);
    expect(changed.claim_version).not.toBe(original.claim_version);
    expect(changed.claim_version).toBe(deriveClaimVersion(changed.assertion));
  });

  it("links a changed assertion to the version it supersedes", () => {
    const original = buildStringClaim(row(), source);
    const changed = buildStringClaim(
      row({ value: "hellp" }),
      source,
      original.claim_version,
    );
    expect(changed.supersedes).toBe(original.claim_version);
  });

  it("keeps undeclared row facts null instead of inventing them", () => {
    const bare = buildStringClaim(
      { address: "0x2000", value: "mystery" },
      source,
    );
    expect(bare.assertion).toEqual({
      value: "mystery",
      encoding: null,
      encoding_status: null,
      byte_length: null,
      termination: null,
      value_form: "typed",
    });
  });

  it("marks display-text rows as display value form", () => {
    const display = buildStringClaim(
      row({ decoding: { available: false, reason: "undecodable" } }),
      source,
    );
    expect(display.assertion.value_form).toBe("display");
  });

  it("rejects a claim whose id or version does not match its content", () => {
    const claim = buildStringClaim(row(), source);
    expect(() =>
      claimRecordSchema.parse({ ...claim, claim_id: `cc_${"c".repeat(64)}` }),
    ).toThrow();
    expect(() =>
      claimRecordSchema.parse({
        ...claim,
        assertion: { ...claim.assertion, value: "tampered" },
      }),
    ).toThrow();
  });

  it("rejects unsorted dependencies", () => {
    const claim = buildStringClaim(row(), source);
    const other = buildStringClaim(row({ address: "0x3000" }), source);
    expect(() =>
      claimRecordSchema.parse({
        ...claim,
        dependencies: [other.claim_id, claim.claim_id].sort().reverse(),
      }),
    ).toThrow();
  });
});
