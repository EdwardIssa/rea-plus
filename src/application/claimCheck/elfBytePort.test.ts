import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  createElfBytePort,
  openArtifactRangeReader,
  parseClaimAddress,
  type ArtifactRangeReader,
} from "./elfBytePort.js";
import { buildSyntheticElf } from "./syntheticElf.fixture.js";

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
});
