# Dynamic-execution ablation — pre-registered scoring rules

Written before the first scored run, per `spec-dynamic-execution-ablation.md`.
These rules are fixed for the whole benchmark. Any change invalidates prior
scored runs (spec §3) and requires a restart with the change recorded here.

## Item vocabulary

Scored items, compared per target (target-level kinds) and per stimulus
(per-stimulus kinds):

- `string:<value>` — target-level. From ground truth `strings`.
- `module:<basename>` — target-level. From ground truth `loaded_modules`.
- `symbol:<name>` — target-level. From ground truth `resolved_symbols`.
- `function:<name>@<stimulus>` — from ground truth `executed_functions`.
- `edge:<caller>><callee>@<stimulus>` — from ground truth `call_edges`.
- `output@<stimulus>` — claimed output text vs ground truth `outputs`
  (exact match after no normalization; fixtures are authored deterministic).

## Arm S (static-only) claim rules

Static facts come from one REA+ MCP session per target per repetition
(`open_binary`, `binary_overview`, `list_procedures`, `list_strings`,
`get_call_graph` from `main`, `xrefs` per defined function), all through the
supervised Ghidra bridge. Claims are generated mechanically:

- **strings**: a `list_strings` value becomes a claim iff it is a _content
  string_: length ≥ 4, printable ASCII, not equal to any procedure name or
  symbol name in the binary, not a `GLIBC_*` version string, not a system
  library path (under `/lib`, `/usr/lib`), and not an attribution marker
  (prefix `MARK:`). This is the triage a string inventory applies; raw facts
  are recorded in the run record so the filter is auditable.
- **modules**: a string fact whose basename ends in `.so` (optionally with a
  version suffix) claims that basename, unless the basename is a `DT_NEEDED`
  entry of the target binary (read from the binary's own ELF dynamic section
  by the harness — a static fact, not ground truth).
- **symbols**: a string fact claims a symbol iff it is identifier-shaped
  (`^[A-Za-z_][A-Za-z0-9_]*$`, length ≥ 4), is not a procedure name in the
  binary, and the binary imports `dlsym` (the analyst's basis for treating an
  identifier string as a potential `dlsym` target).
- **functions / edges / outputs**: Arm S claims **none**. Static analysis has
  no per-stimulus resolution; per the spec, unresolved per-stimulus behavior
  claims nothing. This honesty is part of what is measured.

## Arm D (static + execution) claim rules

Arm D = Arm S claims ∪ runtime observations from the supervised Frida
sessions (hook pack v1.0.0), per stimulus:

- **strings**: every distinct text observed in `puts`/`fputs` argument
  capture, in the reconstructed stdout stream (split into lines), in
  `dlopen` path arguments, and in `dlsym` name arguments becomes a string
  claim (same `MARK:` exclusion; no content filter — an observed string is
  an observed string).
- **modules**: basename of every successful `dlopen` path observation.
- **symbols**: every name observed in a successful `dlsym` observation.
- **functions**: function `f` is claimed for stimulus `s` iff `f`'s authored
  attribution line (ground truth `function_markers[f]`) appears in `s`'s
  reconstructed stdout. Each scored function prints exactly one such line
  when it executes; the line names the function, so attribution is
  behavioral observation, not inference.
- **edges**: edge `(c, f)` is claimed for stimulus `s` iff `f` is claimed
  executed for `s`, `c` is claimed executed for `s` (`main` counts as
  executed in every session), and `(c, f)` is a _candidate edge_: a resolved
  static direct edge, or `f`'s address is referenced from inside `c` per
  Ghidra `xrefs` (an xref address inside `c`'s address range), or `f` was
  resolved via `dlsym` in `s` and `c` is `main`. Candidate edges derive from
  the binary and the session, never from the truth file.
- **outputs**: the reconstructed stdout byte stream for `s` (from the hook
  pack's `write` capture on fd 1), claimed verbatim.

## Scoring

Per class and overall, per arm, using the median repetition's claims
(repetitions must produce identical claim sets; a divergence is reported,
not silently absorbed):

- task success = recovered / truth items
- false-positive rate = false_claims / claimed items (null when 0 claimed)
- Arm D gain = D success − S success, in percentage points

The decision rule is the pre-registered one in the spec §5 (BUILD / KILL /
EXTEND), applied mechanically by the scorer.

## Amendment (2026-11-22, recorded before any scored verdict existed)

The first scored repetitions (targets a1–a5, partial) were discarded and
the scored phase restarted after the static-claim implementation was found
narrower than this document's own rule: it excluded only _procedure_ names
where the rule says any symbol name in the binary; it matched only `/lib/`
prefixes where the rule says system library paths; and it claimed versioned
symbol references (`name@GLIBC_*`), section names, and the ELF interpreter
(PT_INTERP) as content strings / a loaded module. The implementation now
reads the binary's full symbol tables, section names, DT_NEEDED, and
interpreter from its own ELF structures and excludes them, as the rule
intends. The decision rule and every other scoring rule are unchanged. The
discarded partial records are preserved under the run directory
`ablation-runs/run-2026-11-22-aborted/` for audit.

## Amendment 2 (2026-11-22, after the first scored run was invalidated)

The first complete scored run (verdict KILL, dynamic FP 47.1%) was
invalidated on fidelity grounds, not accepted: two harness bugs meant the
stimuli were never administered or observed as authored. (1) The dynamic
worker passed the program name inside `argv`, but REA's Frida manager
prepends the program itself, so every target received its own path as
`argv[1]` and all argv-gated stimuli silently took their default path.
(2) The worker read the session message snapshot too early; the target's
exit-time stdout flush message arrives after the detach is first observed,
so reconstructed outputs were empty or partial in most sessions. The
original fidelity gate covered only standalone runs; an instrumented
fidelity gate (a supervised Frida session per stimulus must reproduce the
authored stdout exactly, else the target is excluded with the reason)
now precedes scoring. Both bugs are fixed and the run restarted from
scratch; the invalid run's records are preserved under
`ablation-runs/run-2026-11-22-invalid1/`.

One claim-filter completion accompanies the restart, under the same
"accounted for as metadata" principle as Amendment 1: a string fact equal
to a DT_NEEDED soname or to the binary's `.comment` section content is
dependency/toolchain metadata (the module rule already accounts DT_NEEDED;
the section rules already account section names), so it is not also
claimed as a content string. The decision rule and all other rules are
unchanged. No further amendments follow this one: the restarted run's
verdict stands as measured.

Amendment 2, continued (same day, still before any valid scored run): the
first instrumented-fidelity pass after the fixes above reproduced truth
stdout in only 8/28 sessions — the exit-time stdio flush's `write` hook
message races the Frida channel teardown when the process dies (passing
sessions show exactly one write event; failing sessions show none, with
all `puts` captures intact). Hook pack 1.1.0 adds a 150 ms drain delay in
the `write` hook after queueing the message; a 9-session spot check over
previously failing stimuli then reproduced truth stdout 9/9. The pack
version is recorded in every run record, as before.

## EXTEND follow-up vocabulary (2026-11-22, separate pre-registration)

Run 1 above stands as measured under the original filing rules; its
verdict was EXTEND (dynamic FP 9.7%, in the 5–10% band). The follow-up
re-measurement is pre-registered separately in
`hidden_files/ablation-extend-preregistration.md` and changes ONLY the
filing vocabulary: every observation is filed under exactly one item
kind, determined by what the observation is and by the channel that
observed it. Run 1's rules filed a dlopen path as both `module:` and
`string:`, a dlsym name as both `symbol:` and `string:`, and stdout
lines as string claims on top of the output claim (10 of run 1's 17
dynamic false claims are this double filing).

Follow-up filing rules (implemented in `scripts/ablation/claims.mjs`):

- **Arm S**: one filing per string fact, by precedence — (1) module
  derivation (basename matches the `.so` pattern, contains no `%`, is
  not a `DT_NEEDED` entry, is not the interpreter basename) → `module:`
  only; (2) symbol derivation (identifier-shaped, length ≥ 4, binary
  imports `dlsym`, not an accounted name) → `symbol:` only; (3) the
  content-string triage above → `string:`. A basename containing `%` is
  an unexpanded format template, not a loadable module name: B3's
  `./lib%s%s.so` pair collapses to the string filing alone.
- **Arm D**: a successful `dlopen` observation files `module:` only; a
  successful `dlsym` observation files `symbol:` only; the stdout
  stream files as the `output` claim only (its lines are not re-filed
  as strings). Dynamic string claims come only from the output-function
  argument channel (`puts`/`fputs` arguments, printf-family format
  arguments). `MARK:` attribution, candidate edges, and outputs are
  unchanged.

Corpus, ground truth, budgets, repetitions, hook pack (1.1.0), and the
scoring math are unchanged. The follow-up's decision bands are in its
pre-registration, not in the spec's §5 rule.

## Known authored noise (declared in advance)

- A4's stored base64 text is a content string and will be a static false
  string claim; A3's design avoids a seed literal for the same reason.
- D2's env-var name `FEATURE_X` is a content string and an identifier-shaped
  string in a `dlsym`-importing binary is not present there — D2 does not
  import `dlsym`, so it yields one static false string claim only.
- B3's format string `./lib%s%s.so` claims module `lib%s%s.so` statically —
  a false module claim that records exactly what static analysis cannot
  assemble.
