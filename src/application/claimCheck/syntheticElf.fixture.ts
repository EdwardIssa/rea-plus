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
