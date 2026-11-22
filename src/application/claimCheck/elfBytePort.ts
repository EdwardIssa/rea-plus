import { open, stat, type FileHandle } from "node:fs/promises";

import { readElfHeaderFacts } from "../../domain/elfFixedHeader.js";
import { readElfProgramHeader } from "../../domain/elfProgramHeader.js";
import type {
  ClaimAddressMapping,
  StringClaimBytePort,
} from "../../domain/claimCheck/stringClaimValidator.js";

/**
 * Bounded range reads over one artifact file. The whole file is never loaded:
 * reads go through the file handle at explicit offsets, so very large
 * artifacts cost only the ranges a claim actually needs.
 */
export interface ArtifactRangeReader {
  readonly size: number;
  readRange(offset: number, length: number): Promise<Uint8Array | undefined>;
  close(): Promise<void>;
}

/** Open an artifact for range reads; the caller owns closing the reader. */
export const openArtifactRangeReader = async (
  path: string,
): Promise<ArtifactRangeReader> => {
  const info = await stat(path);
  const handle: FileHandle = await open(path, "r");
  return {
    size: info.size,
    readRange: async (offset, length) => {
      if (length === 0) return new Uint8Array(0);
      if (offset < 0 || offset + length > info.size) return undefined;
      const buffer = Buffer.alloc(length);
      const { bytesRead } = await handle.read(buffer, 0, length, offset);
      return bytesRead === length ? buffer : undefined;
    },
    close: () => handle.close(),
  };
};

const PT_LOAD = 1;
// Extended program-header numbering (PN_XNUM) is not resolved: such files
// adjudicate every address as unmapped rather than guessing the real count.
const PN_XNUM = 0xffff;
const MAX_PROGRAM_HEADER_TABLE_BYTES = 4 * 1024 * 1024;

/** Parse a provider address string; anything else is malformed, never guessed. */
export const parseClaimAddress = (address: string): bigint | undefined => {
  const hex = /^0[xX]([0-9a-fA-F]+)$/u.exec(address);
  if (hex !== null) return BigInt(`0x${hex[1]}`);
  if (/^[0-9]+$/u.test(address)) return BigInt(address);
  return undefined;
};

interface LoadSegment {
  readonly offset: bigint;
  readonly virtualAddress: bigint;
  readonly fileSize: bigint;
}

const unmappedPort = (reader: ArtifactRangeReader): StringClaimBytePort => ({
  mapAddress: (address) =>
    parseClaimAddress(address) === undefined
      ? { kind: "malformed" }
      : { kind: "unmapped" },
  readRange: (offset, length) => reader.readRange(offset, length),
});

/**
 * Build the byte port for one ELF artifact over REA's own format parsers.
 * Program headers are read once, up front; after that, address mapping is a
 * table lookup and reads are bounded ranges. An artifact whose bytes are not
 * a parseable ELF maps nothing, so its claims adjudicate `address_unmapped`
 * instead of failing the run.
 */
export const createElfBytePort = async (
  reader: ArtifactRangeReader,
): Promise<StringClaimBytePort> => {
  const headerBytes = await reader.readRange(0, 64);
  if (headerBytes === undefined) return unmappedPort(reader);
  const facts = readElfHeaderFacts(Buffer.from(headerBytes), reader.size);
  if (!facts.ok) return unmappedPort(reader);
  const { elfClass, byteOrder } = facts.value;
  const littleEndian = byteOrder === "little";
  const view = new DataView(
    headerBytes.buffer,
    headerBytes.byteOffset,
    headerBytes.byteLength,
  );
  const programHeaderOffset =
    elfClass === 64
      ? Number(view.getBigUint64(32, littleEndian))
      : view.getUint32(28, littleEndian);
  const entrySize = view.getUint16(elfClass === 64 ? 54 : 42, littleEndian);
  const entryCount = view.getUint16(elfClass === 64 ? 56 : 44, littleEndian);
  if (
    programHeaderOffset === 0 ||
    entrySize === 0 ||
    entryCount === 0 ||
    entryCount === PN_XNUM ||
    entrySize * entryCount > MAX_PROGRAM_HEADER_TABLE_BYTES
  )
    return unmappedPort(reader);
  const table = await reader.readRange(
    programHeaderOffset,
    entrySize * entryCount,
  );
  if (table === undefined) return unmappedPort(reader);

  const segments: LoadSegment[] = [];
  for (let index = 0; index < entryCount; index += 1) {
    const entry = table.subarray(
      index * entrySize,
      index * entrySize + entrySize,
    );
    const parsed = readElfProgramHeader(entry, elfClass, littleEndian);
    if (!parsed.ok) return unmappedPort(reader);
    if (parsed.value.type === PT_LOAD && parsed.value.fileSize > 0n)
      segments.push({
        offset: parsed.value.offset,
        virtualAddress: parsed.value.virtualAddress,
        fileSize: parsed.value.fileSize,
      });
  }

  return {
    mapAddress: (address): ClaimAddressMapping => {
      const value = parseClaimAddress(address);
      if (value === undefined) return { kind: "malformed" };
      for (const segment of segments) {
        if (
          value >= segment.virtualAddress &&
          value < segment.virtualAddress + segment.fileSize
        )
          return {
            kind: "mapped",
            offset: Number(segment.offset + (value - segment.virtualAddress)),
          };
      }
      return { kind: "unmapped" };
    },
    readRange: (offset, length) => reader.readRange(offset, length),
  };
};
