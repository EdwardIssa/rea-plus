import { createHash } from "node:crypto";

/**
 * A tiny hand-built ELF64 image with two PT_LOAD segments and a real gap
 * between them. Every string address below is a builder constant, so test
 * truth is authored here, never derived from an analyzer.
 *
 * Layout: LOAD1 covers file [0, 0x1000) at vaddr 0x400000; LOAD2 covers
 * file [0x2000, 0x3000) at vaddr 0x402000; vaddr [0x401000, 0x402000) is a
 * segment gap mapped by nothing.
 */
export const SYNTHETIC_ELF = {
  alpha: { address: "0x400800", value: "alpha-string", byteLength: 13 },
  raw: { address: "0x400900", value: "RAWBYTES", byteLength: 8 },
  beta: { address: "0x402100", value: "beta-string", byteLength: 12 },
  gapAddress: "0x401234",
  beyondAddress: "0x403500",
} as const;

export const buildSyntheticElf = (): {
  readonly bytes: Buffer;
  readonly sha256: string;
} => {
  const bytes = Buffer.alloc(0x3000);
  // ELF header.
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  bytes.writeUInt16LE(2, 16); // ET_EXEC
  bytes.writeUInt16LE(62, 18); // EM_X86_64
  bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(64n, 32); // e_phoff
  bytes.writeUInt16LE(64, 52); // e_ehsize
  bytes.writeUInt16LE(56, 54); // e_phentsize
  bytes.writeUInt16LE(2, 56); // e_phnum
  // Program headers.
  const phdr = (at: number, offset: bigint, vaddr: bigint, size: bigint) => {
    bytes.writeUInt32LE(1, at); // PT_LOAD
    bytes.writeUInt32LE(5, at + 4); // R+X
    bytes.writeBigUInt64LE(offset, at + 8);
    bytes.writeBigUInt64LE(vaddr, at + 16);
    bytes.writeBigUInt64LE(vaddr, at + 24);
    bytes.writeBigUInt64LE(size, at + 32);
    bytes.writeBigUInt64LE(size, at + 40);
    bytes.writeBigUInt64LE(0x1000n, at + 48);
  };
  phdr(64, 0n, 0x400000n, 0x1000n);
  phdr(120, 0x2000n, 0x402000n, 0x1000n);
  // String bytes (file offsets mirror the vaddr deltas above).
  bytes.write("alpha-string\0", 0x800, "utf8");
  bytes.write("RAWBYTES", 0x900, "utf8");
  bytes.write("gamma\0", 0x908, "utf8"); // follows the raw string immediately
  bytes.write("beta-string\0", 0x2100, "utf8");
  return {
    bytes,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
};

/**
 * A hand-built ET_DYN ELF64 image in the shape a relocating producer (the
 * Ghidra bridge) reports: PT_LOAD virtual addresses start at 0, the
 * producer's loaded addresses are those addresses plus its image base, and
 * non-loaded sections live in their own named address spaces. Every address
 * below is a builder constant, so test truth is authored here.
 *
 * Layout: LOAD1 covers file [0, 0x2000) at vaddr 0; LOAD2 covers file
 * [0x2000, 0x3000) at vaddr 0x2000. `.rodata` is the loaded half of LOAD1;
 * `.strtab` (file 0x2800) and `.bss` (NOBITS, no file bytes) are named
 * section spaces; section headers sit at file 0x2c00.
 */
export const SYNTHETIC_DYN_ELF = {
  /** The image base the fixture's producer is recorded as loading at. */
  imageBase: "0x100000",
  alpha: { address: "0x101100", value: "dyn-alpha", byteLength: 10 },
  beta: { address: "0x102100", value: "dyn-beta", byteLength: 9 },
  table: { address: ".strtab:0x10", value: "table-string", byteLength: 13 },
  nobitsAddress: ".bss:0x10",
  unknownSectionAddress: ".nope:0x10",
  beyondSectionAddress: ".strtab:0x100",
} as const;

export const buildSyntheticDynElf = (): {
  readonly bytes: Buffer;
  readonly sha256: string;
} => {
  const bytes = Buffer.alloc(0x3000);
  // ELF header.
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  bytes.writeUInt16LE(3, 16); // ET_DYN
  bytes.writeUInt16LE(62, 18); // EM_X86_64
  bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(64n, 32); // e_phoff
  bytes.writeBigUInt64LE(0x2c00n, 40); // e_shoff
  bytes.writeUInt16LE(64, 52); // e_ehsize
  bytes.writeUInt16LE(56, 54); // e_phentsize
  bytes.writeUInt16LE(2, 56); // e_phnum
  bytes.writeUInt16LE(64, 58); // e_shentsize
  bytes.writeUInt16LE(5, 60); // e_shnum
  bytes.writeUInt16LE(4, 62); // e_shstrndx
  // Program headers.
  const phdr = (at: number, offset: bigint, vaddr: bigint, size: bigint) => {
    bytes.writeUInt32LE(1, at); // PT_LOAD
    bytes.writeUInt32LE(5, at + 4); // R+X
    bytes.writeBigUInt64LE(offset, at + 8);
    bytes.writeBigUInt64LE(vaddr, at + 16);
    bytes.writeBigUInt64LE(vaddr, at + 24);
    bytes.writeBigUInt64LE(size, at + 32);
    bytes.writeBigUInt64LE(size, at + 40);
    bytes.writeBigUInt64LE(0x1000n, at + 48);
  };
  phdr(64, 0n, 0n, 0x2000n);
  phdr(120, 0x2000n, 0x2000n, 0x1000n);
  // String bytes in the loaded segments (file offset == virtual address).
  bytes.write("dyn-alpha\0", 0x1100, "utf8");
  bytes.write("dyn-beta\0", 0x2100, "utf8");
  // The .strtab section space: offset 0x10 inside file offset 0x2800.
  bytes.write("table-string\0", 0x2810, "utf8");
  // Section-name string table at file 0x2a00:
  // "" @0, ".rodata" @1, ".strtab" @9, ".bss" @17, ".shstrtab" @22.
  bytes.write("\0.rodata\0.strtab\0.bss\0.shstrtab\0", 0x2a00, "utf8");
  // Section headers at file 0x2c00.
  const shdr = (
    at: number,
    name: number,
    type: number,
    flags: bigint,
    addr: bigint,
    offset: bigint,
    size: bigint,
  ) => {
    bytes.writeUInt32LE(name, at);
    bytes.writeUInt32LE(type, at + 4);
    bytes.writeBigUInt64LE(flags, at + 8);
    bytes.writeBigUInt64LE(addr, at + 16);
    bytes.writeBigUInt64LE(offset, at + 24);
    bytes.writeBigUInt64LE(size, at + 32);
  };
  // [0] SHT_NULL stays zeroed.
  shdr(0x2c00 + 64, 1, 1, 0x2n, 0x1000n, 0x1000n, 0x1000n); // .rodata PROGBITS ALLOC
  shdr(0x2c00 + 128, 9, 3, 0n, 0n, 0x2800n, 0x100n); // .strtab STRTAB
  shdr(0x2c00 + 192, 17, 8, 0x3n, 0x3000n, 0x2800n, 0x100n); // .bss NOBITS
  shdr(0x2c00 + 256, 22, 3, 0n, 0n, 0x2a00n, 0x20n); // .shstrtab STRTAB
  return {
    bytes,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
};
