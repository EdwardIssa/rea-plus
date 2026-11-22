import { open, stat, type FileHandle } from "node:fs/promises";

import { readElfHeaderFacts } from "../../domain/elfFixedHeader.js";
import { readElfProgramHeader } from "../../domain/elfProgramHeader.js";
import { readElfSectionHeader } from "../../domain/elfSectionHeader.js";
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
const ET_DYN = 3;
const SHT_NOBITS = 8;
const SHN_UNDEF = 0;
const SHN_XINDEX = 0xffff;
// Extended program-header numbering (PN_XNUM) is not resolved: such files
// adjudicate every address as unmapped rather than guessing the real count.
const PN_XNUM = 0xffff;
const MAX_PROGRAM_HEADER_TABLE_BYTES = 4 * 1024 * 1024;
// Extended section numbering is likewise left unresolved; a section table
// that cannot be read whole within the same bound yields no section mapping.
const MAX_SECTION_HEADER_TABLE_BYTES = 4 * 1024 * 1024;
const MAX_SECTION_NAME_TABLE_BYTES = 4 * 1024 * 1024;

/** Parse a provider address string; anything else is malformed, never guessed. */
export const parseClaimAddress = (address: string): bigint | undefined => {
  const hex = /^0[xX]([0-9a-fA-F]+)$/u.exec(address);
  if (hex !== null) return BigInt(`0x${hex[1]}`);
  if (/^[0-9]+$/u.test(address)) return BigInt(address);
  return undefined;
};

/** One parsed provider address: a bare coordinate or an address-space coordinate. */
export interface ClaimAddressCoordinate {
  /** Encoded address-space name for `space:0x…` forms; null for bare addresses. */
  readonly space: string | null;
  readonly offset: bigint;
}

const ADDRESS_SPACE_PATTERN =
  /^((?:[A-Za-z0-9._~-]|%[0-9a-fA-F]{2})+):0[xX]([0-9a-fA-F]+)$/u;

/**
 * Parse the canonical REA address forms: a bare hex or decimal coordinate,
 * or an encoded address-space name followed by `:0x` and a hex offset (the
 * form producers emit for addresses outside the default space, such as an
 * ELF section space). Anything else is not an address this port can read.
 */
export const parseClaimAddressCoordinate = (
  address: string,
): ClaimAddressCoordinate | undefined => {
  const spaced = ADDRESS_SPACE_PATTERN.exec(address);
  if (spaced !== null)
    return { space: spaced[1]!, offset: BigInt(`0x${spaced[2]}`) };
  const bare = parseClaimAddress(address);
  return bare === undefined ? undefined : { space: null, offset: bare };
};

/** Decode a percent-encoded address-space name to the name it denotes. */
const decodeAddressSpace = (space: string): string =>
  space.replace(/%([0-9a-fA-F]{2})/gu, (_escape, hex: string) =>
    String.fromCharCode(Number.parseInt(hex, 16)),
  );

/**
 * Recorded relocation context for one producer's addresses: the image base
 * the producer loaded the artifact at, taken from that producer's own
 * Evidence (its binary overview or segment inventory), never inferred.
 * Claims from a producer without recorded context keep raw address
 * semantics, so their addresses adjudicate exactly as before.
 */
export interface ElfAddressRelocation {
  readonly imageBase: bigint;
}

interface LoadSegment {
  readonly offset: bigint;
  readonly virtualAddress: bigint;
  readonly fileSize: bigint;
}

interface SectionRange {
  readonly offset: bigint;
  readonly size: bigint;
  readonly type: number;
}

const unmappedPort = (reader: ArtifactRangeReader): StringClaimBytePort => ({
  mapAddress: (address) =>
    parseClaimAddressCoordinate(address) === undefined
      ? { kind: "malformed" }
      : { kind: "unmapped" },
  readRange: (offset, length) => reader.readRange(offset, length),
});

/**
 * Read the section header table and resolve section names through the
 * section-name string table. Any gap in the chain (no table, extended
 * numbering, an unreadable name table, a section header that does not
 * parse) yields no section mapping at all: section-space addresses then
 * adjudicate unmapped rather than landing somewhere guessed. A name held
 * by two sections is dropped, because the space it names is ambiguous.
 */
const loadSections = async (
  reader: ArtifactRangeReader,
  headerBytes: Uint8Array,
  elfClass: 32 | 64,
  littleEndian: boolean,
): Promise<ReadonlyMap<string, SectionRange>> => {
  const none = new Map<string, SectionRange>();
  const view = new DataView(
    headerBytes.buffer,
    headerBytes.byteOffset,
    headerBytes.byteLength,
  );
  const wide = elfClass === 64;
  const sectionHeaderOffset = wide
    ? Number(view.getBigUint64(40, littleEndian))
    : view.getUint32(32, littleEndian);
  const entrySize = view.getUint16(wide ? 58 : 46, littleEndian);
  const entryCount = view.getUint16(wide ? 60 : 48, littleEndian);
  const nameTableIndex = view.getUint16(wide ? 62 : 50, littleEndian);
  if (
    sectionHeaderOffset === 0 ||
    entrySize === 0 ||
    entryCount === 0 ||
    nameTableIndex === SHN_UNDEF ||
    nameTableIndex === SHN_XINDEX ||
    nameTableIndex >= entryCount ||
    entrySize * entryCount > MAX_SECTION_HEADER_TABLE_BYTES
  )
    return none;
  const table = await reader.readRange(
    sectionHeaderOffset,
    entrySize * entryCount,
  );
  if (table === undefined) return none;
  const headers: SectionRange[] = [];
  const nameOffsets: number[] = [];
  for (let index = 0; index < entryCount; index += 1) {
    const entry = table.subarray(
      index * entrySize,
      index * entrySize + entrySize,
    );
    const parsed = readElfSectionHeader(entry, elfClass, littleEndian);
    if (!parsed.ok) return none;
    headers.push({
      offset: parsed.value.offset,
      size: parsed.value.size,
      type: parsed.value.type,
    });
    nameOffsets.push(parsed.value.nameOffset);
  }
  const nameTable = headers[nameTableIndex]!;
  if (
    nameTable.type === SHT_NOBITS ||
    nameTable.size > BigInt(MAX_SECTION_NAME_TABLE_BYTES)
  )
    return none;
  const nameBytes = await reader.readRange(
    Number(nameTable.offset),
    Number(nameTable.size),
  );
  if (nameBytes === undefined) return none;
  const nameAt = (offset: number): string | undefined => {
    if (offset >= nameBytes.length) return undefined;
    const end = nameBytes.indexOf(0, offset);
    if (end < 0) return undefined;
    return Buffer.from(nameBytes.subarray(offset, end)).toString("utf8");
  };
  const sections = new Map<string, SectionRange>();
  const ambiguous = new Set<string>();
  headers.forEach((section, index) => {
    const name = nameAt(nameOffsets[index]!);
    if (name === undefined || name === "") return;
    if (sections.has(name)) {
      sections.delete(name);
      ambiguous.add(name);
      return;
    }
    if (!ambiguous.has(name)) sections.set(name, section);
  });
  return sections;
};

/**
 * Build the byte port for one ELF artifact over REA's own format parsers.
 * Program headers are read once, up front; after that, address mapping is a
 * table lookup and reads are bounded ranges. An artifact whose bytes are not
 * a parseable ELF maps nothing, so its claims adjudicate `address_unmapped`
 * instead of failing the run.
 *
 * Address forms, all resolved from recorded facts only:
 * - a bare address is an ELF virtual address, mapped through PT_LOAD;
 * - with a recorded relocation for the claim's producer and an ET_DYN
 *   artifact, a bare address is the producer's loaded address and the
 *   recorded image base is subtracted first — the recorded space is then
 *   authoritative, so an address that only maps raw is unmapped, never
 *   rescued by coincidence;
 * - a `section:0x…` address names an ELF section space and lands at that
 *   section's file offset plus the in-space offset, from the artifact's own
 *   section headers.
 */
export const createElfBytePort = async (
  reader: ArtifactRangeReader,
  options: { readonly relocation?: ElfAddressRelocation } = {},
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
  const sections = await loadSections(
    reader,
    headerBytes,
    elfClass,
    littleEndian,
  );
  // Relocation is additive only for ET_DYN: an ET_EXEC image already loads
  // at its recorded virtual addresses, so its image base is descriptive and
  // subtracting it would corrupt every address.
  const relocation =
    options.relocation !== undefined && facts.value.type === ET_DYN
      ? options.relocation
      : undefined;

  return {
    mapAddress: (address): ClaimAddressMapping => {
      const coordinate = parseClaimAddressCoordinate(address);
      if (coordinate === undefined) return { kind: "malformed" };
      if (coordinate.space !== null) {
        const section = sections.get(decodeAddressSpace(coordinate.space));
        if (
          section === undefined ||
          section.type === SHT_NOBITS ||
          coordinate.offset >= section.size
        )
          return { kind: "unmapped" };
        return {
          kind: "mapped",
          offset: Number(section.offset + coordinate.offset),
        };
      }
      const virtualAddress =
        relocation === undefined
          ? coordinate.offset
          : coordinate.offset - relocation.imageBase;
      if (virtualAddress < 0n) return { kind: "unmapped" };
      for (const segment of segments) {
        if (
          virtualAddress >= segment.virtualAddress &&
          virtualAddress < segment.virtualAddress + segment.fileSize
        )
          return {
            kind: "mapped",
            offset: Number(
              segment.offset + (virtualAddress - segment.virtualAddress),
            ),
          };
      }
      return { kind: "unmapped" };
    },
    readRange: (offset, length) => reader.readRange(offset, length),
  };
};
