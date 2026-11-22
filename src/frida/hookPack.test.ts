import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  HOOK_PACK_SOURCE,
  HOOK_PACK_TESTED_FRIDA_MAJOR,
  HOOK_PACK_VERSION,
} from "./hookPack.js";

describe("hook pack product asset", () => {
  it("is version 1.1.0, the ablation-proven pack, against the Frida 17 line", () => {
    expect(HOOK_PACK_VERSION).toBe("1.1.0");
    expect(HOOK_PACK_TESTED_FRIDA_MAJOR).toBe(17);
    expect(HOOK_PACK_SOURCE).toContain('const PACK_VERSION = "1.1.0";');
  });

  it("uses the Frida 17 API and reports pack_ready with hooked/missing", () => {
    expect(HOOK_PACK_SOURCE).toContain("Module.getGlobalExportByName");
    expect(HOOK_PACK_SOURCE).toContain('t: "pack_ready"');
    expect(HOOK_PACK_SOURCE).toContain('attach("dlopen"');
    expect(HOOK_PACK_SOURCE).toContain('attach("dlsym"');
    expect(HOOK_PACK_SOURCE).toContain('attach("write"');
  });

  it("has a stable source digest for run-outcome recording", () => {
    const digest = createHash("sha256").update(HOOK_PACK_SOURCE).digest("hex");
    expect(digest).toMatch(/^[a-f0-9]{64}$/u);
    expect(Buffer.byteLength(HOOK_PACK_SOURCE)).toBe(3089);
  });
});
