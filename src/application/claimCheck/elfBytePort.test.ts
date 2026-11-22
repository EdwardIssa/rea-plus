import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  createElfBytePort,
  openArtifactRangeReader,
  parseClaimAddress,
  parseClaimAddressCoordinate,
  type ArtifactRangeReader,
} from "./elfBytePort.js";
import {
  buildSyntheticDynElf,
  buildSyntheticElf,
  SYNTHETIC_DYN_ELF,
} from "./syntheticElf.fixture.js";

describe("ELF byte port", () => {
  let reader: ArtifactRangeReader;
  let root: string;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), "rea-claim-check-elf-"));
    const path = join(root, "fixture.elf");
    await writeFile(path, buildSyntheticElf().bytes);
    reader = await openArtifactRangeReader(path);
  });
  afterAll(async () => {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  });

  it("maps addresses inside both load segments to file offsets", async () => {
    const port = await createElfBytePort(reader);
    expect(port.mapAddress("0x400800")).toEqual({
      kind: "mapped",
      offset: 0x800,
    });
    expect(port.mapAddress("0x402100")).toEqual({
      kind: "mapped",
      offset: 0x2100,
    });
    const bytes = await port.readRange(0x800, 13);
    expect(Buffer.from(bytes!).toString("utf8")).toBe("alpha-string\0");
  });

  it("leaves segment gaps and beyond-segment addresses unmapped", async () => {
    const port = await createElfBytePort(reader);
    expect(port.mapAddress("0x401234")).toEqual({ kind: "unmapped" });
    expect(port.mapAddress("0x403500")).toEqual({ kind: "unmapped" });
  });

  it("reports garbage addresses as malformed and short reads as missing", async () => {
    const port = await createElfBytePort(reader);
    expect(port.mapAddress("hello")).toEqual({ kind: "malformed" });
    expect(port.mapAddress("0xZZ")).toEqual({ kind: "malformed" });
    expect(await port.readRange(0x2ff0, 0x40)).toBeUndefined();
    expect(await port.readRange(0x800, 0)).toEqual(new Uint8Array(0));
  });

  it("maps nothing for bytes that are not an ELF image", async () => {
    const path = join(root, "not-elf.bin");
    await writeFile(path, Buffer.alloc(256, 0x41));
    const other = await openArtifactRangeReader(path);
    try {
      const port = await createElfBytePort(other);
      expect(port.mapAddress("0x400800")).toEqual({ kind: "unmapped" });
    } finally {
      await other.close();
    }
  });

  it("parses hex and decimal provider addresses", () => {
    expect(parseClaimAddress("0x1011ad")).toBe(0x1011adn);
    expect(parseClaimAddress("1053101")).toBe(1053101n);
    expect(parseClaimAddress("0x")).toBeUndefined();
    expect(parseClaimAddress("-5")).toBeUndefined();
    expect(parseClaimAddress("")).toBeUndefined();
  });

  it("parses bare and address-space coordinates", () => {
    expect(parseClaimAddressCoordinate("0x1011ad")).toEqual({
      space: null,
      offset: 0x1011adn,
    });
    expect(parseClaimAddressCoordinate(".strtab:0x1da")).toEqual({
      space: ".strtab",
      offset: 0x1dan,
    });
    expect(parseClaimAddressCoordinate("mem%3Aory:0x10")).toEqual({
      space: "mem%3Aory",
      offset: 0x10n,
    });
    expect(parseClaimAddressCoordinate(".strtab:1234")).toBeUndefined();
    expect(parseClaimAddressCoordinate("::0x10")).toBeUndefined();
    expect(parseClaimAddressCoordinate("hello")).toBeUndefined();
  });
});

describe("ELF byte port (ET_DYN sections and relocation)", () => {
  let reader: ArtifactRangeReader;
  let root: string;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), "rea-claim-check-elf-dyn-"));
    const path = join(root, "fixture-dyn.elf");
    await writeFile(path, buildSyntheticDynElf().bytes);
    reader = await openArtifactRangeReader(path);
  });
  afterAll(async () => {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  });

  it("maps section-space addresses through the artifact's section headers", async () => {
    const port = await createElfBytePort(reader);
    expect(port.mapAddress(SYNTHETIC_DYN_ELF.table.address)).toEqual({
      kind: "mapped",
      offset: 0x2810,
    });
    const bytes = await port.readRange(
      0x2810,
      SYNTHETIC_DYN_ELF.table.byteLength,
    );
    expect(Buffer.from(bytes!).toString("utf8")).toBe("table-string\0");
  });

  it("leaves NOBITS, unknown, and out-of-range section spaces unmapped", async () => {
    const port = await createElfBytePort(reader);
    expect(port.mapAddress(SYNTHETIC_DYN_ELF.nobitsAddress)).toEqual({
      kind: "unmapped",
    });
    expect(port.mapAddress(SYNTHETIC_DYN_ELF.unknownSectionAddress)).toEqual({
      kind: "unmapped",
    });
    expect(port.mapAddress(SYNTHETIC_DYN_ELF.beyondSectionAddress)).toEqual({
      kind: "unmapped",
    });
  });

  it("keeps raw virtual-address semantics without recorded relocation", async () => {
    const port = await createElfBytePort(reader);
    expect(port.mapAddress("0x1100")).toEqual({
      kind: "mapped",
      offset: 0x1100,
    });
    // The producer's loaded address means nothing without its recorded base.
    expect(port.mapAddress(SYNTHETIC_DYN_ELF.alpha.address)).toEqual({
      kind: "unmapped",
    });
  });

  it("applies recorded relocation to bare addresses for ET_DYN", async () => {
    const port = await createElfBytePort(reader, {
      relocation: { imageBase: BigInt(SYNTHETIC_DYN_ELF.imageBase) },
    });
    expect(port.mapAddress(SYNTHETIC_DYN_ELF.alpha.address)).toEqual({
      kind: "mapped",
      offset: 0x1100,
    });
    expect(port.mapAddress(SYNTHETIC_DYN_ELF.beta.address)).toEqual({
      kind: "mapped",
      offset: 0x2100,
    });
    // With recorded context the loaded space is authoritative: the raw VA
    // no longer maps, so a raw coincidence can never support a claim.
    expect(port.mapAddress("0x1100")).toEqual({ kind: "unmapped" });
    // Section spaces are unaffected by relocation.
    expect(port.mapAddress(SYNTHETIC_DYN_ELF.table.address)).toEqual({
      kind: "mapped",
      offset: 0x2810,
    });
  });

  it("ignores relocation for ET_EXEC, whose addresses are already absolute", async () => {
    const path = join(root, "fixture-exec.elf");
    await writeFile(path, buildSyntheticElf().bytes);
    const execReader = await openArtifactRangeReader(path);
    try {
      const port = await createElfBytePort(execReader, {
        relocation: { imageBase: 0x100000n },
      });
      expect(port.mapAddress("0x400800")).toEqual({
        kind: "mapped",
        offset: 0x800,
      });
    } finally {
      await execReader.close();
    }
  });
});
