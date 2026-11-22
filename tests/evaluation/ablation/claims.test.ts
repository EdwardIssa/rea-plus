import { describe, expect, it } from "vitest";

import {
  candidateEdges,
  dynamicClaims,
  isContentString,
  staticClaims,
} from "../../../scripts/ablation/claims.mjs";
import {
  readDtNeeded,
  readElfMetadata,
} from "../../../scripts/ablation/elfFacts.mjs";
import {
  buildFixtures,
  FIXTURES_ROOT,
} from "../../../scripts/ablation/buildFixtures.mjs";
import { existsSync } from "node:fs";
import { join } from "node:path";

describe("content-string triage (SCORING.md)", () => {
  const symbols = new Set(["main", "reveal"]);
  it("accepts ordinary content strings", () => {
    expect(isContentString("alpha-secret-one", symbols)).toBe(true);
    expect(
      isContentString("https://delta.example.internal/feed", symbols),
    ).toBe(true);
  });
  it("rejects short, marker, symbol, version, and library-path strings", () => {
    expect(isContentString("abc", symbols)).toBe(false);
    expect(isContentString("MARK:reveal", symbols)).toBe(false);
    expect(isContentString("reveal", symbols)).toBe(false);
    expect(isContentString("GLIBC_2.34", symbols)).toBe(false);
    expect(isContentString("/lib/x86_64-linux-gnu/libc.so.6", symbols)).toBe(
      false,
    );
    expect(isContentString("has\ttab", symbols)).toBe(false);
  });
});

const factsBase = {
  stringFacts: [] as string[],
  procedureNames: new Set<string>(),
  symbolNames: new Set<string>(),
  sectionNames: new Set<string>(),
  dtNeeded: [] as string[],
  interpBasename: null as string | null,
  commentStrings: new Set<string>(),
  importsDlsym: false,
};

describe("static claims", () => {
  it("claims modules from .so strings except DT_NEEDED entries and the interpreter", () => {
    const claims = staticClaims({
      ...factsBase,
      stringFacts: [
        "./libplug1.so",
        "libc.so.6",
        "/lib64/ld-linux-x86-64.so.2",
      ],
      procedureNames: new Set(["main", "dlopen", "dlsym"]),
      dtNeeded: ["libc.so.6"],
      interpBasename: "ld-linux-x86-64.so.2",
      importsDlsym: true,
    } as never);
    expect(claims.items.has("module:libplug1.so")).toBe(true);
    expect(claims.items.has("module:libc.so.6")).toBe(false);
    expect(claims.items.has("module:ld-linux-x86-64.so.2")).toBe(false);
    // Follow-up vocabulary: a fact filed as a module is not also filed
    // as a string (run 1 filed "./libplug1.so" under both kinds).
    expect(claims.items.has("string:./libplug1.so")).toBe(false);
    expect(claims.items.has("string:/lib64/ld-linux-x86-64.so.2")).toBe(false);
  });

  it("files an unexpanded format template as a string only, never a module", () => {
    const claims = staticClaims({
      ...factsBase,
      stringFacts: ["./lib%s%s.so"],
      importsDlsym: true,
    } as never);
    expect(claims.items.has("module:lib%s%s.so")).toBe(false);
    expect(claims.items.has("string:./lib%s%s.so")).toBe(true);
  });

  it("excludes symbol-table names, section names, and versioned references as content", () => {
    const claims = staticClaims({
      ...factsBase,
      stringFacts: [
        "_edata",
        ".rodata",
        "puts@GLIBC_2.2.5",
        "real-content-string",
      ],
      symbolNames: new Set(["_edata"]),
      sectionNames: new Set([".rodata"]),
    } as never);
    expect(claims.items.has("string:_edata")).toBe(false);
    expect(claims.items.has("string:.rodata")).toBe(false);
    expect(claims.items.has("string:puts@GLIBC_2.2.5")).toBe(false);
    expect(claims.items.has("string:real-content-string")).toBe(true);
  });

  it("does not claim DT_NEEDED sonames or .comment content as content strings", () => {
    const claims = staticClaims({
      ...factsBase,
      stringFacts: [
        "libc.so.6",
        "GCC: (Ubuntu 13.3.0) 13.3.0",
        "real-content-string",
      ],
      dtNeeded: ["libc.so.6"],
      commentStrings: new Set(["GCC: (Ubuntu 13.3.0) 13.3.0"]),
    } as never);
    expect(claims.items.has("string:libc.so.6")).toBe(false);
    expect(claims.items.has("string:GCC: (Ubuntu 13.3.0) 13.3.0")).toBe(false);
    expect(claims.items.has("string:real-content-string")).toBe(true);
  });

  it("claims symbols only when the binary imports dlsym, and never for accounted names", () => {
    const base = {
      ...factsBase,
      stringFacts: ["plug_greet", "_edata"],
      symbolNames: new Set(["_edata"]),
    };
    const withDlsym = staticClaims({ ...base, importsDlsym: true } as never);
    const without = staticClaims({ ...base, importsDlsym: false } as never);
    expect(withDlsym.items.has("symbol:plug_greet")).toBe(true);
    expect(withDlsym.items.has("symbol:_edata")).toBe(false);
    expect(without.items.has("symbol:plug_greet")).toBe(false);
    // Follow-up vocabulary: a fact filed as a symbol is not also filed
    // as a string; without the symbol derivation the same fact is an
    // ordinary content string.
    expect(withDlsym.items.has("string:plug_greet")).toBe(false);
    expect(without.items.has("string:plug_greet")).toBe(true);
  });

  it("claims no functions, edges, or outputs", () => {
    const claims = staticClaims({ ...factsBase } as never);
    expect(claims.items.size).toBe(0);
    expect(claims.outputs.size).toBe(0);
  });
});

describe("dynamic claims", () => {
  const base = { items: new Set<string>(), outputs: new Map<string, string>() };
  const observation = {
    texts: ["plug-one-hello"],
    stdout: "MARK:main\nMARK:plug_greet\nplug-one-hello\n",
    dlopen: [{ path: "./libplug1.so", ok: true }],
    dlsym: [{ name: "plug_greet", ok: true }],
  };

  it("attributes executed functions from MARK lines and claims outputs verbatim", () => {
    const claims = dynamicClaims(
      base as never,
      observation as never,
      { candidateEdges: [["main", "plug_greet"]] } as never,
      "s1",
    );
    expect(claims.items.has("function:plug_greet@s1")).toBe(true);
    expect(claims.items.has("function:main@s1")).toBe(true);
    expect(claims.items.has("edge:main>plug_greet@s1")).toBe(true);
    expect(claims.outputs.get("s1")).toBe(observation.stdout);
    expect(claims.items.has("string:plug-one-hello")).toBe(true);
    expect(claims.items.has("module:libplug1.so")).toBe(true);
    expect(claims.items.has("symbol:plug_greet")).toBe(true);
  });

  it("never claims marker lines as strings", () => {
    const claims = dynamicClaims(
      base as never,
      observation as never,
      { candidateEdges: [] } as never,
      "s1",
    );
    for (const item of claims.items)
      expect(item.startsWith("string:MARK:")).toBe(false);
  });

  it("does not claim an edge whose caller did not execute", () => {
    const claims = dynamicClaims(
      base as never,
      { ...observation, stdout: "MARK:main\n" } as never,
      { candidateEdges: [["choose", "plug_greet"]] } as never,
      "s1",
    );
    expect(claims.items.has("edge:choose>plug_greet@s1")).toBe(false);
    expect(claims.items.has("function:plug_greet@s1")).toBe(false);
  });

  it("files dlopen paths as modules only and dlsym names as symbols only", () => {
    const claims = dynamicClaims(
      base as never,
      observation as never,
      { candidateEdges: [] } as never,
      "s1",
    );
    expect(claims.items.has("module:libplug1.so")).toBe(true);
    expect(claims.items.has("string:./libplug1.so")).toBe(false);
    expect(claims.items.has("symbol:plug_greet")).toBe(true);
    expect(claims.items.has("string:plug_greet")).toBe(false);
  });

  it("does not file stdout lines as strings; the stream is the output claim", () => {
    const claims = dynamicClaims(
      base as never,
      {
        texts: [],
        stdout: "MARK:main\nassembled-at-runtime\n",
        dlopen: [],
        dlsym: [],
      } as never,
      { candidateEdges: [] } as never,
      "s1",
    );
    expect(claims.items.has("string:assembled-at-runtime")).toBe(false);
    expect(claims.outputs.get("s1")).toBe("MARK:main\nassembled-at-runtime\n");
  });

  it("keeps a string claim when the text arrives through the argument channel", () => {
    // Channel principle: the same text observed via puts is a string
    // observation even when it is also a dlopen path.
    const claims = dynamicClaims(
      base as never,
      {
        texts: ["./libplug1.so"],
        stdout: "MARK:main\n",
        dlopen: [{ path: "./libplug1.so", ok: true }],
        dlsym: [],
      } as never,
      { candidateEdges: [] } as never,
      "s1",
    );
    expect(claims.items.has("string:./libplug1.so")).toBe(true);
    expect(claims.items.has("module:libplug1.so")).toBe(true);
  });

  it("ignores failed dlopen/dlsym observations", () => {
    const claims = dynamicClaims(
      base as never,
      {
        texts: [],
        stdout: "MARK:main\n",
        dlopen: [{ path: "./libplug1.so", ok: false }],
        dlsym: [{ name: "plug_greet", ok: false }],
      } as never,
      { candidateEdges: [] } as never,
      "s1",
    );
    expect(claims.items.has("module:libplug1.so")).toBe(false);
    expect(claims.items.has("symbol:plug_greet")).toBe(false);
  });
});

describe("candidate edges", () => {
  it("merges static edges with main>dlsym-resolved edges, deduplicated", () => {
    const edges = candidateEdges(
      {
        directEdges: [["main", "reveal"]],
        xrefEdges: [
          ["main", "op_add"],
          ["main", "reveal"],
        ],
      } as never,
      {
        dlsym: [
          { name: "plug_greet", ok: true },
          { name: "nope", ok: false },
        ],
      } as never,
    );
    const keys = edges.map(([c, f]) => `${c}>${f}`).sort();
    expect(keys).toEqual(["main>op_add", "main>plug_greet", "main>reveal"]);
  });
});

describe("elf facts", () => {
  it("reads DT_NEEDED from a built fixture (builds the corpus if absent)", () => {
    const binary = join(FIXTURES_ROOT, "bin", "b1", "b1");
    if (!existsSync(binary)) buildFixtures();
    const needed = readDtNeeded(binary);
    expect(needed).toContain("libc.so.6");
  });

  it("reads symbol names, section names, and the interpreter path", () => {
    const binary = join(FIXTURES_ROOT, "bin", "b1", "b1");
    if (!existsSync(binary)) buildFixtures();
    const meta = readElfMetadata(binary);
    expect(meta.symbolNames.has("main")).toBe(true);
    expect(meta.symbolNames.has("plug_greet")).toBe(false);
    expect(meta.sectionNames).toContain(".rodata");
    expect(meta.interp).toBe("/lib64/ld-linux-x86-64.so.2");
  });
});
