import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { copyFile, mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));

/**
 * Ground truth for the claim-check fixtures. The values below are the
 * constants written in claimStrings.c; addresses and stored extents are
 * derived here by a small independent ELF section reader over the compiled
 * fixture's own bytes, never from an analyzer or from REA's ELF code.
 */
export const CLAIM_FIXTURE_STRINGS = [
  { name: "greeting", value: "claim-check-greeting" },
  { name: "unterminated", value: "NOTERM01" },
  { name: "tail", value: "tail-at-section-end" },
] as const;

export interface ClaimFixtureString {
  readonly name: string;
  readonly value: string;
  /** Provider-style hex address of the first stored byte. */
  readonly address: string;
  /** Full stored extent in bytes, terminator included when present. */
  readonly byteLength: number;
  readonly termination: "missing" | "present_or_not_required";
  readonly endsAtSectionEnd: boolean;
}

export interface ClaimCheckFixture {
  readonly root: string;
  readonly unstrippedPath: string;
  readonly strippedPath: string;
  readonly unstrippedSha256: string;
  readonly strippedSha256: string;
  readonly strings: readonly ClaimFixtureString[];
  /** A virtual address inside the gap between two PT_LOAD segments. */
  readonly gapAddress: string;
  /** A virtual address past the end of every PT_LOAD segment. */
  readonly beyondAddress: string;
}

interface SectionFacts {
  readonly addr: bigint;
  readonly offset: number;
  readonly size: number;
}

interface LoadFacts {
  readonly start: bigint;
  readonly end: bigint;
}

const readSections = (
  bytes: Buffer,
): { sections: Map<string, SectionFacts>; loads: LoadFacts[] } => {
  if (bytes.toString("latin1", 0, 4) !== "\x7fELF")
    throw new Error("fixture is not an ELF image");
  const phoff = Number(bytes.readBigUInt64LE(32));
  const phentsize = bytes.readUInt16LE(54);
  const phnum = bytes.readUInt16LE(56);
  const loads: LoadFacts[] = [];
  for (let i = 0; i < phnum; i += 1) {
    const at = phoff + i * phentsize;
    if (bytes.readUInt32LE(at) !== 1) continue; // PT_LOAD
    const vaddr = bytes.readBigUInt64LE(at + 16);
    const filesz = bytes.readBigUInt64LE(at + 32);
    if (filesz > 0n) loads.push({ start: vaddr, end: vaddr + filesz });
  }
  const shoff = Number(bytes.readBigUInt64LE(40));
  const shentsize = bytes.readUInt16LE(58);
  const shnum = bytes.readUInt16LE(60);
  const shstrndx = bytes.readUInt16LE(62);
  const headerAt = (index: number) => shoff + index * shentsize;
  const strHeader = headerAt(shstrndx);
  const strOffset = Number(bytes.readBigUInt64LE(strHeader + 24));
  const nameAt = (offset: number): string => {
    const end = bytes.indexOf(0, strOffset + offset);
    return bytes.toString("utf8", strOffset + offset, end);
  };
  const sections = new Map<string, SectionFacts>();
  for (let i = 0; i < shnum; i += 1) {
    const at = headerAt(i);
    sections.set(nameAt(bytes.readUInt32LE(at)), {
      addr: bytes.readBigUInt64LE(at + 16),
      offset: Number(bytes.readBigUInt64LE(at + 24)),
      size: Number(bytes.readBigUInt64LE(at + 32)),
    });
  }
  return { sections, loads };
};

const deriveTruth = (
  bytes: Buffer,
): {
  strings: ClaimFixtureString[];
  gapAddress: string;
  beyondAddress: string;
} => {
  const { sections, loads } = readSections(bytes);
  const section = sections.get(".claimstrings");
  if (section === undefined)
    throw new Error("fixture is missing its .claimstrings section");
  const sectionBytes = bytes.subarray(
    section.offset,
    section.offset + section.size,
  );
  const strings = CLAIM_FIXTURE_STRINGS.map(({ name, value }) => {
    const valueBytes = Buffer.from(value, "utf8");
    const index = sectionBytes.indexOf(valueBytes);
    if (index < 0) throw new Error(`fixture string ${name} not in section`);
    const after = sectionBytes[index + valueBytes.length];
    const terminated = after === 0;
    const byteLength = valueBytes.length + (terminated ? 1 : 0);
    return {
      name,
      value,
      address: `0x${(section.addr + BigInt(index)).toString(16)}`,
      byteLength,
      termination: terminated
        ? ("present_or_not_required" as const)
        : ("missing" as const),
      endsAtSectionEnd: index + byteLength === sectionBytes.length,
    };
  });
  const byName = new Map(strings.map((entry) => [entry.name, entry]));
  if (byName.get("unterminated")?.termination !== "missing")
    throw new Error("fixture unterminated string gained a terminator");
  if (byName.get("tail")?.endsAtSectionEnd !== true)
    throw new Error("fixture tail string does not end at the section end");
  const sorted = [...loads].sort((a, b) => (a.start < b.start ? -1 : 1));
  let gap: bigint | undefined;
  for (let i = 0; i + 1 < sorted.length; i += 1) {
    const current = sorted[i]!;
    const next = sorted[i + 1]!;
    if (next.start > current.end) {
      gap = current.end + (next.start - current.end) / 2n;
      break;
    }
  }
  if (gap === undefined) throw new Error("fixture has no segment gap");
  const lastEnd = sorted[sorted.length - 1]!.end;
  return {
    strings,
    gapAddress: `0x${gap.toString(16)}`,
    beyondAddress: `0x${(lastEnd + 0x1000n).toString(16)}`,
  };
};

const sha256Of = async (path: string): Promise<string> =>
  createHash("sha256")
    .update(await readFile(path))
    .digest("hex");

export const buildClaimCheckFixture = async (): Promise<ClaimCheckFixture> => {
  const root = await mkdtemp(join(tmpdir(), "rea-claim-check-fixture-"));
  const unstrippedPath = join(root, "claim-fixture");
  const strippedPath = join(root, "claim-fixture.stripped");
  await run("cc", ["-O0", "-o", unstrippedPath, join(here, "claimStrings.c")]);
  await copyFile(unstrippedPath, strippedPath);
  await run("strip", [strippedPath]);
  const bytes = await readFile(unstrippedPath);
  const truth = deriveTruth(bytes);
  // The stripped copy holds the same section bytes at the same virtual
  // addresses; only symbol/debug data is gone.
  const strippedTruth = deriveTruth(await readFile(strippedPath));
  if (JSON.stringify(strippedTruth.strings) !== JSON.stringify(truth.strings))
    throw new Error("stripped fixture truth diverged from unstripped");
  return {
    root,
    unstrippedPath,
    strippedPath,
    unstrippedSha256: await sha256Of(unstrippedPath),
    strippedSha256: await sha256Of(strippedPath),
    strings: truth.strings,
    gapAddress: truth.gapAddress,
    beyondAddress: truth.beyondAddress,
  };
};

/** A list_strings/search_strings row asserting one fixture string. */
export const fixtureStringRow = (
  entry: ClaimFixtureString,
  overrides: { value?: string; byteLength?: number; address?: string } = {},
) => ({
  address: overrides.address ?? entry.address,
  value: overrides.value ?? entry.value,
  string: {
    encoding: "utf-8",
    encoding_status: "observed",
    termination: entry.termination,
    byte_length: overrides.byteLength ?? entry.byteLength,
  },
});
