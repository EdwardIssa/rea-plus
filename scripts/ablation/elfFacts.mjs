/**
 * Minimal ELF64 facts the ablation harness derives from a target binary's own
 * bytes (never from ground truth): the DT_NEEDED soname list, the symbol-table
 * names, the section names, and the PT_INTERP interpreter path — the metadata
 * the static claim rules in tests/fixtures/dynamic/SCORING.md exclude by.
 */
import { readFileSync } from "node:fs";

const parseElf = (binaryPath) => {
  const bytes = readFileSync(binaryPath);
  if (bytes.length < 64 || bytes[0] !== 0x7f || bytes[1] !== 0x45)
    throw new Error(`not an ELF file: ${binaryPath}`);
  if (bytes[4] !== 2) throw new Error(`not an ELF64 file: ${binaryPath}`);
  const u16 = (o) => bytes.readUInt16LE(o);
  const u32 = (o) => bytes.readUInt32LE(o);
  const u64 = (o) => Number(bytes.readBigUInt64LE(o));
  const sectionHeaderOffset = u64(0x28);
  const sectionHeaderSize = u16(0x3a);
  const sectionCount = u16(0x3c);
  const sectionNameIndex = u16(0x3e);
  const sections = [];
  for (let i = 0; i < sectionCount; i++) {
    const o = sectionHeaderOffset + i * sectionHeaderSize;
    sections.push({
      nameOffset: u32(o),
      type: u32(o + 4),
      offset: u64(o + 0x18),
      size: u64(o + 0x20),
      link: u32(o + 0x28),
      entsize: u64(o + 0x38),
    });
  }
  const readStringAt = (tableOffset, offset) => {
    const start = tableOffset + offset;
    let end = start;
    while (end < bytes.length && bytes[end] !== 0) end++;
    return bytes.toString("utf8", start, end);
  };
  const nameSection = sections[sectionNameIndex];
  for (const section of sections)
    section.name = nameSection
      ? readStringAt(nameSection.offset, section.nameOffset)
      : "";
  const programHeaderOffset = u64(0x20);
  const programHeaderSize = u16(0x36);
  const programHeaderCount = u16(0x38);
  let interp = null;
  for (let i = 0; i < programHeaderCount; i++) {
    const o = programHeaderOffset + i * programHeaderSize;
    if (u32(o) === 3) {
      // PT_INTERP
      const offset = u64(o + 8);
      const size = u64(o + 0x20);
      interp = bytes
        .toString("utf8", offset, offset + size)
        .replace(/\0.*$/u, "");
    }
  }
  return { bytes, sections, readStringAt, u64, interp };
};

/**
 * { dtNeeded, symbolNames, sectionNames, interp } from the binary's own
 * ELF structures.
 */
export const readElfMetadata = (binaryPath) => {
  const { bytes, sections, readStringAt, u64, interp } = parseElf(binaryPath);
  const sectionNames = sections.map((s) => s.name).filter((n) => n.length > 0);
  let dtNeeded = [];
  const dynamic = sections.find((s) => s.name === ".dynamic");
  if (dynamic !== undefined) {
    const stringSection = sections[dynamic.link];
    const entrySize = dynamic.entsize || 16;
    for (
      let o = dynamic.offset;
      o + entrySize <= dynamic.offset + dynamic.size;
      o += entrySize
    ) {
      const tag = Number(bytes.readBigInt64LE(o));
      if (tag === 0) break;
      if (tag === 1)
        dtNeeded.push(readStringAt(stringSection.offset, u64(o + 8)));
    }
  }
  const commentSection = sections.find((s) => s.name === ".comment");
  const commentStrings = new Set(
    commentSection === undefined
      ? []
      : bytes
          .toString(
            "utf8",
            commentSection.offset,
            commentSection.offset + commentSection.size,
          )
          .split("\0")
          .filter((s) => s.length > 0),
  );
  const symbolNames = new Set();
  for (const section of sections) {
    if (section.type !== 2 && section.type !== 11) continue; // SYMTAB, DYNSYM
    const stringSection = sections[section.link];
    if (stringSection === undefined) continue;
    const entrySize = section.entsize || 24;
    for (
      let o = section.offset;
      o + entrySize <= section.offset + section.size;
      o += entrySize
    ) {
      const nameOffset = bytes.readUInt32LE(o);
      if (nameOffset === 0) continue;
      const name = readStringAt(stringSection.offset, nameOffset);
      if (name.length > 0) symbolNames.add(name);
    }
  }
  return { dtNeeded, symbolNames, sectionNames, interp, commentStrings };
};

export const readDtNeeded = (binaryPath) =>
  readElfMetadata(binaryPath).dtNeeded;
