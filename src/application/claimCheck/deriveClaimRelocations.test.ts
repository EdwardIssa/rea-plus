import { describe, expect, it } from "vitest";

import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { deriveClaimRelocations } from "./deriveClaimRelocations.js";

const provider = { id: "ghidra", name: "Ghidra", version: "12.1.4" };
const otherProvider = { id: "hopper", name: "Hopper", version: "6.0" };
const workflowProvider = {
  id: "rea-workflow",
  name: "REA composed investigation workflow",
  version: "1",
};
const sha256 = "a".repeat(64);
const otherSha256 = "b".repeat(64);

const record = (
  operation: string,
  result: unknown,
  options: {
    provider?: typeof provider;
    sha256?: string;
  } = {},
): Evidence =>
  createEvidence(
    {
      path: "/fixtures/artifact",
      sha256: options.sha256 ?? sha256,
      format: "elf",
    },
    options.provider ?? provider,
    { operation, parameters: {}, result, evidenceLinks: [] },
  );

const strings = (options: { provider?: typeof provider } = {}): Evidence =>
  record(
    "list_strings",
    [
      {
        address: "0x101100",
        value: "dyn-alpha",
        string: {
          encoding: "UTF-8",
          termination: "present_or_not_required",
          byte_length: 10,
        },
      },
    ],
    options,
  );

const overview = (
  imageBase: string,
  options: { provider?: typeof provider } = {},
): Evidence =>
  record(
    "read_binary_inventory_summary",
    {
      document: "fixture.elf",
      image_base: imageBase,
      segments: [],
      procedure_count: 0,
      string_count: 0,
    },
    options,
  );

const segment = (imageBase: string) => ({
  name: "ram",
  start: "0x100000",
  end: "0x103000",
  readable: true,
  writable: false,
  executable: true,
  image_base: imageBase,
  address_space: "ram",
});

describe("claim relocation derivation", () => {
  it("reads the image base from the producer's overview record", () => {
    const relocations = deriveClaimRelocations(
      [strings(), overview("0x100000")],
      sha256,
    );
    expect(relocations.get("ghidra")).toEqual({ imageBase: 0x100000n });
  });

  it("reads the image base from a segment inventory when segments agree", () => {
    const relocations = deriveClaimRelocations(
      [
        strings(),
        record("list_segments", [segment("0x100000"), segment("0x100000")]),
      ],
      sha256,
    );
    expect(relocations.get("ghidra")).toEqual({ imageBase: 0x100000n });
  });

  it("reports nothing when the segments disagree about the base", () => {
    const relocations = deriveClaimRelocations(
      [
        strings(),
        record("list_segments", [segment("0x100000"), segment("0x200000")]),
      ],
      sha256,
    );
    expect(relocations.size).toBe(0);
  });

  it("cancels a producer's base when two context records disagree", () => {
    const relocations = deriveClaimRelocations(
      [strings(), overview("0x100000"), overview("0x200000")],
      sha256,
    );
    expect(relocations.size).toBe(0);
  });

  it("attributes a composed overview to the set's only string producer", () => {
    const relocations = deriveClaimRelocations(
      [
        strings(),
        record(
          "binary_overview",
          { image_base: "0x100000" },
          { provider: workflowProvider },
        ),
      ],
      sha256,
    );
    expect(relocations.get("ghidra")).toEqual({ imageBase: 0x100000n });
  });

  it("drops composed context when several producers contributed strings", () => {
    const relocations = deriveClaimRelocations(
      [
        strings(),
        strings({ provider: otherProvider }),
        record(
          "binary_overview",
          { image_base: "0x100000" },
          { provider: workflowProvider },
        ),
      ],
      sha256,
    );
    expect(relocations.size).toBe(0);
  });

  it("ignores records about another subject", () => {
    const relocations = deriveClaimRelocations(
      [
        strings(),
        record(
          "read_binary_inventory_summary",
          { image_base: "0x100000" },
          { sha256: otherSha256 },
        ),
      ],
      sha256,
    );
    expect(relocations.size).toBe(0);
  });

  it("never lets a string record supply its own relocation context", () => {
    const relocations = deriveClaimRelocations([strings()], sha256);
    expect(relocations.size).toBe(0);
  });

  it("keys relocation by the producer that recorded it", () => {
    const relocations = deriveClaimRelocations(
      [
        strings(),
        strings({ provider: otherProvider }),
        overview("0x400000", { provider: otherProvider }),
      ],
      sha256,
    );
    expect(relocations.get("ghidra")).toBeUndefined();
    expect(relocations.get("hopper")).toEqual({ imageBase: 0x400000n });
  });

  it("ignores a base that is not a parseable address", () => {
    const relocations = deriveClaimRelocations(
      [strings(), overview("soon")],
      sha256,
    );
    expect(relocations.size).toBe(0);
  });
});
