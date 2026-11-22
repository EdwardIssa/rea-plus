/**
 * Claim generation for the dynamic-execution ablation, implementing the
 * pre-registered rules in tests/fixtures/dynamic/SCORING.md exactly.
 * Pure functions: static facts / runtime observations in, claimed items out.
 * Ground truth is never an input to claim generation.
 *
 * A claim set is { items: Set<string>, outputs: Map<stimulusId, string> }.
 * Item keys: string:<v> | module:<v> | symbol:<v> | function:<n>@<s> |
 * edge:<c>><f>@<s>. Outputs are claimed verbatim per stimulus.
 */

export const stringItem = (v) => `string:${v}`;
export const moduleItem = (v) => `module:${v}`;
export const symbolItem = (v) => `symbol:${v}`;
export const functionItem = (name, s) => `function:${name}@${s}`;
export const edgeItem = (caller, callee, s) => `edge:${caller}>${callee}@${s}`;

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const SO_BASENAME = /^[^/]*\.so(\.\d+)*$/u;

export const isPrintableAscii = (value) => {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) return false;
  }
  return value.length > 0;
};

/**
 * The content-string triage of SCORING.md, applied to one static string
 * fact. `excludedNames` is every name the binary itself accounts for: its
 * procedure names, its symbol-table names, and its section names (all read
 * from the binary's own structures — metadata, not content). Versioned
 * symbol references (`name@GLIBC_*`) and system library paths are likewise
 * metadata, not content.
 */
export const isContentString = (value, excludedNames) => {
  if (value.length < 4) return false;
  if (!isPrintableAscii(value)) return false;
  if (value.startsWith("MARK:")) return false;
  if (excludedNames.has(value)) return false;
  if (value.startsWith("GLIBC_") || /@GLIBC_/u.test(value)) return false;
  if (value.startsWith("/lib") || value.startsWith("/usr/lib")) return false;
  return true;
};

export const soBasename = (path) => {
  const base = path.split("/").pop() ?? "";
  return SO_BASENAME.test(base) ? base : null;
};

/**
 * Static facts (from the supervised Ghidra pass plus the harness's own ELF
 * read of the binary, assembled by runBenchmark.mjs):
 * { stringFacts: string[], procedureNames: Set<string>,
 *   symbolNames: Set<string>, sectionNames: Set<string>,
 *   dtNeeded: string[], interpBasename: string | null,
 *   commentStrings: Set<string>, importsDlsym: boolean }
 * A string fact the binary itself accounts for as metadata is not content:
 * that covers the names above, the DT_NEEDED sonames (already accounted by
 * the module rule), and the .comment section's toolchain banner.
 */
export const staticClaims = (facts) => {
  const items = new Set();
  const excludedNames = new Set([
    ...facts.procedureNames,
    ...facts.symbolNames,
    ...facts.sectionNames,
    ...facts.dtNeeded,
    ...(facts.commentStrings ?? []),
  ]);
  for (const value of facts.stringFacts) {
    if (isContentString(value, excludedNames)) items.add(stringItem(value));
    const base = soBasename(value);
    if (
      base !== null &&
      !facts.dtNeeded.includes(base) &&
      base !== facts.interpBasename
    )
      items.add(moduleItem(base));
    if (
      facts.importsDlsym &&
      IDENTIFIER.test(value) &&
      value.length >= 4 &&
      !excludedNames.has(value)
    )
      items.add(symbolItem(value));
  }
  return { items, outputs: new Map() };
};

/**
 * Runtime observations for one stimulus (from the dynamic worker):
 * { texts: string[] (puts/fputs args), stdout: string,
 *   dlopen: {path, ok}[], dlsym: {name, ok}[] }
 * plus the target-level context both arms share:
 * { candidateEdges: [caller, callee][] }
 * Returns the claims Arm D adds for this stimulus, merged over `base`
 * (the static claim set), without mutating it.
 */
export const dynamicClaims = (base, observation, context, stimulusId) => {
  const items = new Set(base.items);
  const outputs = new Map(base.outputs);
  const observedTexts = new Set();
  for (const text of observation.texts) observedTexts.add(text);
  for (const line of observation.stdout.split("\n"))
    if (line.length > 0) observedTexts.add(line);
  for (const text of observedTexts) {
    if (text.startsWith("MARK:")) continue;
    items.add(stringItem(text));
  }
  for (const load of observation.dlopen) {
    if (!load.ok) continue;
    const baseName = soBasename(load.path);
    if (baseName !== null) items.add(moduleItem(baseName));
    items.add(stringItem(load.path));
  }
  for (const sym of observation.dlsym) {
    if (!sym.ok) continue;
    items.add(symbolItem(sym.name));
    items.add(stringItem(sym.name));
  }
  // Executed functions: a function's authored attribution line (MARK:<name>,
  // visible in the binary's own strings) appears in this stimulus's stdout.
  // main counts as executed in every completed session (SCORING.md).
  const executed = new Set(["main"]);
  for (const line of observation.stdout.split("\n")) {
    const match = /^MARK:(.+)$/u.exec(line);
    if (match !== null) executed.add(match[1]);
  }
  for (const fn of executed) items.add(functionItem(fn, stimulusId));
  // Edges: callee executed, caller executed (main always), candidate relation.
  for (const [caller, callee] of context.candidateEdges) {
    if (!executed.has(callee)) continue;
    if (!executed.has(caller)) continue;
    items.add(edgeItem(caller, callee, stimulusId));
  }
  outputs.set(stimulusId, observation.stdout);
  return { items, outputs };
};

/** Candidate edges from static facts + this session's dlsym resolutions. */
export const candidateEdges = (staticGraph, observation) => {
  const edges = new Map();
  const add = (c, f) => edges.set(`${c}>${f}`, [c, f]);
  for (const [c, f] of staticGraph.directEdges) add(c, f);
  for (const [c, f] of staticGraph.xrefEdges) add(c, f);
  for (const sym of observation.dlsym) if (sym.ok) add("main", sym.name);
  return [...edges.values()];
};
