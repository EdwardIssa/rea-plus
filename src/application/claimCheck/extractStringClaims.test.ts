import { describe, expect, it } from "vitest";

import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { extractStringClaims } from "./extractStringClaims.js";
import { buildSyntheticElf } from "./syntheticElf.fixture.js";

const { sha256 } = buildSyntheticElf();
const provider = { id: "ghidra", name: "Ghidra", version: "12.1.4" };
const target = {
  path: "/fixtures/synthetic.elf",
  sha256,
  format: "elf" as const,
};

const stringRow = (address: string, value: string) => ({
  address,
  value,
  string: {
    encoding: "utf-8",
    encoding_status: "observed",
    termination: "present_or_not_required",
    byte_length: value.length + 1,
  },
});

const stringEvidence = (
  operation: string,
  rows: readonly unknown[],
  evidenceLinks: readonly string[] = [],
): Evidence =>
  createEvidence(target, provider, {
    operation,
    parameters: {},
    result: rows,
    evidenceLinks,
  });

describe("string claim extraction", () => {
  it("derives one claim per string row with envelope facts attached", () => {
    const record = stringEvidence("list_strings", [
      stringRow("0x400800", "alpha-string"),
      stringRow("0x402100", "beta-string"),
    ]);
    const claims = extractStringClaims([record]);
    expect(claims).toHaveLength(2);
    expect(claims[0]).toMatchObject({
      class: "native-string",
      subject: { sha256, format: "elf" },
      evidence_ref: record.evidence_id,
      producer: {
        provider_id: "ghidra",
        provider_version: "12.1.4",
        operation: "list_strings",
      },
      location: { address: "0x400800" },
      label: "pipeline-consensus",
    });
  });

  it("ignores records from other operations", () => {
    const record = stringEvidence("list_procedures", [
      { address: "0x400800", value: "main" },
    ]);
    expect(extractStringClaims([record])).toEqual([]);
  });

  it("chains changed assertions at one address through supersedes", () => {
    const record = stringEvidence("list_strings", [
      stringRow("0x400800", "alpha-string"),
      stringRow("0x400800", "alpha-strinh"),
    ]);
    const claims = extractStringClaims([record]);
    expect(claims).toHaveLength(2);
    expect(claims[0]?.claim_id).toBe(claims[1]?.claim_id);
    expect(claims[0]?.supersedes).toBeUndefined();
    expect(claims[1]?.supersedes).toBe(claims[0]?.claim_version);
  });

  it("lifts evidence_links into claim dependencies across records", () => {
    const first = stringEvidence("list_strings", [
      stringRow("0x400800", "alpha-string"),
    ]);
    const second = stringEvidence(
      "search_strings",
      [stringRow("0x402100", "beta-string")],
      [first.evidence_id],
    );
    const claims = extractStringClaims([first, second]);
    const [firstClaim, secondClaim] = claims;
    expect(firstClaim?.dependencies).toEqual([]);
    expect(secondClaim?.dependencies).toEqual([firstClaim?.claim_id]);
  });

  it("refuses string Evidence without an identified subject", () => {
    const anonymous = createEvidence(undefined, provider, {
      operation: "list_strings",
      parameters: {},
      result: [stringRow("0x400800", "alpha-string")],
    });
    try {
      extractStringClaims([anonymous]);
      expect.unreachable("extraction must refuse a subjectless record");
    } catch (error) {
      expect(error).toBeInstanceOf(AnalysisInputError);
      expect((error as AnalysisInputError).issues[0]?.message).toContain(
        "subject_unavailable",
      );
    }
  });

  it("refuses string Evidence whose rows do not match the row contract", () => {
    const broken = stringEvidence("list_strings", [
      { address: "0x400800", value: 42 },
    ]);
    expect(() => extractStringClaims([broken])).toThrow();
  });
});
