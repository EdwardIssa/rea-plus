/**
 * Dynamic-execution ablation benchmark runner (spec section 5 gate order):
 * build+manifest -> containment proof -> harness fidelity -> static-arm
 * sanity -> paired interleaved repetitions -> deterministic scoring ->
 * verdict record. Run records land under the --out directory; the verdict
 * markdown is written to --verdict-md. Nothing here adjusts the decision
 * rule; exclusions and discards are recorded with reasons.
 *
 * Usage: node scripts/ablation/runBenchmark.mjs --out <dir> --verdict-md <path>
 *        [--phase containment|fidelity|sanity|score|all]
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { candidateEdges, dynamicClaims, staticClaims } from "./claims.mjs";
import { readElfMetadata } from "./elfFacts.mjs";
import { runDynamicJob, runPlainJob } from "./harness.mjs";
import {
  HOOK_PACK_SOURCE,
  HOOK_PACK_VERSION,
} from "../../dist/frida/hookPack.js";
import {
  buildFixtures,
  FIXTURES_ROOT,
  loadManifest,
  verifyManifest,
} from "./buildFixtures.mjs";
import { runStaticPass } from "./staticArm.mjs";
import {
  aggregateBenchmark,
  applyDecisionRule,
  median,
  scoreClaims,
} from "./scorer.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const GHIDRA_DIR = join(
  homedir(),
  "workspace",
  "tools",
  "ghidra_12.1.4_PUBLIC",
);
const JAVA_HOME = join(homedir(), "workspace", "tools", "jdk-21.0.13.1+2");
const GHIDRA_FIXTURES = join(homedir(), "workspace", "ghidra-fixtures");
const RSS_CAP = 3221225472; // 3 GiB
const REPETITIONS = 3;

const args = process.argv.slice(2);
const argValue = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : null;
};
const OUT = argValue("--out");
const VERDICT_MD = argValue("--verdict-md");
const PHASE = argValue("--phase") ?? "all";
if (OUT === null) {
  console.error("--out is required");
  process.exit(2);
}
mkdirSync(OUT, { recursive: true });

const log = (line) => {
  console.log(line);
  writeFileSync(join(OUT, "runner.log"), line + "\n", { flag: "a" });
};
const writeJson = (name, value) =>
  writeFileSync(join(OUT, name), JSON.stringify(value, null, 1) + "\n");
const loadAvg = () => readFileSync("/proc/loadavg", "utf8").trim();

const fridaVersion = JSON.parse(
  readFileSync(join(REPO, "node_modules", "frida", "package.json"), "utf8"),
).version;
const gccVersion = (() => {
  try {
    return execFileSync("gcc", ["-dumpfullversion"], {
      encoding: "utf8",
    }).trim();
  } catch {
    return "unknown";
  }
})();
const ghidraVersion = (() => {
  try {
    const props = readFileSync(
      join(GHIDRA_DIR, "Ghidra", "application.properties"),
      "utf8",
    );
    return /application\.version=(.+)/u.exec(props)?.[1]?.trim() ?? "unknown";
  } catch {
    return "unknown";
  }
})();

const truthOf = (target) => JSON.parse(readFileSync(target.truth_path, "utf8"));
const binDirOf = (target) => join(FIXTURES_ROOT, "bin", target.target_id);
const envKeysOf = (target) => [
  ...new Set(target.stimuli.flatMap((s) => Object.keys(s.env ?? {}))),
];

// ---------------------------------------------------------------- containment
const runContainment = async (manifest) => {
  const cases = [
    {
      id: "s1",
      deadlineMs: 10000,
      sessionTimeoutMs: 8000,
      hold: 0,
      rlimitNproc: 512,
      expect: ["memory", "deadline"],
    },
    {
      id: "s2",
      deadlineMs: 30000,
      sessionTimeoutMs: 25000,
      hold: 0,
      rlimitNproc: null,
      expect: ["memory", "deadline"],
    },
    {
      id: "s3",
      deadlineMs: 12000,
      sessionTimeoutMs: 10000,
      hold: 3600000,
      rlimitNproc: null,
      expect: ["deadline"],
    },
  ];
  const results = [];
  for (const c of cases) {
    const target = manifest.targets.find((t) => t.target_id === c.id);
    const stimulus = target.stimuli[0];
    log(`CONTAINMENT ${c.id}: deadline ${c.deadlineMs}ms cap ${RSS_CAP}`);
    const run = await runDynamicJob({
      job: {
        program: target.binary_path,
        argv: stimulus.argv,
        env_set: stimulus.env ?? {},
        env_unset: envKeysOf(target).filter(
          (k) => !(k in (stimulus.env ?? {})),
        ),
        cwd: binDirOf(target),
        hook_pack_source: HOOK_PACK_SOURCE,
        session_timeout_ms: c.sessionTimeoutMs,
        hold_after_exit_ms: c.hold,
      },
      fixtureBinDir: binDirOf(target),
      runDir: join(OUT, "containment", c.id),
      deadlineMs: c.deadlineMs,
      rssCapBytes: RSS_CAP,
      rlimitNproc: c.rlimitNproc,
    });
    const ok =
      c.expect.includes(run.outcome) &&
      run.containment_breach === false &&
      run.survivors_after.length === 0;
    log(
      `CONTAINMENT ${c.id}: outcome=${run.outcome} peak_rss=${run.peak_rss_bytes} breach=${run.containment_breach} survivors=${JSON.stringify(run.survivors_after)} ok=${ok}`,
    );
    results.push({
      target_id: c.id,
      expected_outcomes: c.expect,
      outcome: run.outcome,
      peak_rss_bytes: run.peak_rss_bytes,
      wall_ms: run.wall_ms,
      containment_breach: run.containment_breach,
      survivors_after: run.survivors_after,
      worker_status: run.result?.status ?? null,
      ok,
    });
    if (!ok) return { ok: false, results };
  }
  // The harness must complete a subsequent fixture normally.
  const a1 = manifest.targets.find((t) => t.target_id === "a1");
  const stimulus = a1.stimuli[0];
  const run = await runDynamicJob({
    job: {
      program: a1.binary_path,
      argv: stimulus.argv,
      env_set: {},
      env_unset: [],
      cwd: binDirOf(a1),
      hook_pack_source: HOOK_PACK_SOURCE,
      session_timeout_ms: stimulus.timeout_ms,
      hold_after_exit_ms: 0,
    },
    fixtureBinDir: binDirOf(a1),
    runDir: join(OUT, "containment", "subsequent-a1"),
    deadlineMs: stimulus.timeout_ms + 45000,
    rssCapBytes: RSS_CAP,
  });
  const subsequentOk =
    run.result?.status === "complete" &&
    run.result?.stdout_text === truthOf(a1).outputs[stimulus.stimulus_id];
  log(
    `CONTAINMENT subsequent a1: status=${run.result?.status} stdout_match=${subsequentOk}`,
  );
  results.push({
    target_id: "subsequent-a1",
    outcome: run.outcome,
    worker_status: run.result?.status ?? null,
    stdout_match: subsequentOk,
    ok: subsequentOk,
  });
  return { ok: results.every((r) => r.ok), results };
};

// ---------------------------------------------------------------- fidelity
const runFidelity = async (manifest) => {
  const failures = [];
  let checks = 0;
  for (const target of manifest.targets) {
    if (target.containment) continue;
    const truth = truthOf(target);
    for (const stimulus of target.stimuli) {
      checks++;
      const run = await runPlainJob({
        program: target.binary_path,
        argv: stimulus.argv,
        envSet: stimulus.env ?? {},
        fixtureBinDir: binDirOf(target),
        runDir: join(OUT, "fidelity", target.target_id, stimulus.stimulus_id),
        deadlineMs: 30000,
        rssCapBytes: RSS_CAP,
      });
      const expected = truth.outputs[stimulus.stimulus_id];
      if (run.stdout !== expected)
        failures.push({
          target_id: target.target_id,
          stimulus_id: stimulus.stimulus_id,
          expected,
          observed: run.stdout,
          outcome: run.outcome,
        });
    }
  }
  log(
    `FIDELITY: ${checks - failures.length}/${checks} stimulus outputs match truth`,
  );
  return { checks, failures };
};

/**
 * Instrumented fidelity: the dynamic path itself (supervised Frida session
 * per stimulus) must reproduce the authored stdout exactly. A target whose
 * instrumented sessions cannot administer or observe its stimuli faithfully
 * is excluded from scoring with the reason recorded (spec section 5).
 */
const runInstrumentedFidelity = async (manifest) => {
  const failures = [];
  let checks = 0;
  for (const target of manifest.targets) {
    if (target.containment) continue;
    const truth = truthOf(target);
    for (const stimulus of target.stimuli) {
      checks++;
      const run = await runDynamicJob({
        job: {
          program: target.binary_path,
          argv: stimulus.argv,
          env_set: stimulus.env ?? {},
          env_unset: envKeysOf(target).filter(
            (k) => !(k in (stimulus.env ?? {})),
          ),
          cwd: binDirOf(target),
          hook_pack_source: HOOK_PACK_SOURCE,
          session_timeout_ms: stimulus.timeout_ms,
          hold_after_exit_ms: 0,
        },
        fixtureBinDir: binDirOf(target),
        runDir: join(
          OUT,
          "instrumented-fidelity",
          target.target_id,
          stimulus.stimulus_id,
        ),
        deadlineMs: stimulus.timeout_ms + 45000,
        rssCapBytes: RSS_CAP,
      });
      const expected = truth.outputs[stimulus.stimulus_id];
      if (
        run.result?.status !== "complete" ||
        run.result.stdout_text !== expected
      )
        failures.push({
          target_id: target.target_id,
          stimulus_id: stimulus.stimulus_id,
          expected,
          observed: run.result?.stdout_text ?? null,
          worker_status: run.result?.status ?? null,
          failure_reason: run.result?.failure_reason ?? null,
        });
    }
  }
  log(
    `INSTRUMENTED FIDELITY: ${checks - failures.length}/${checks} sessions reproduce truth stdout`,
  );
  return { checks, failures };
};

// ---------------------------------------------------------------- sanity
const runSanity = async () => {
  const pass = await runStaticPass({
    binaryPath: join(GHIDRA_FIXTURES, "fixture_basic"),
    worktree: REPO,
    ghidraInstallDir: GHIDRA_DIR,
    javaHome: JAVA_HOME,
  });
  const expectedNames = [
    "main",
    "greet_user",
    "compute_score",
    "helper_add",
    "helper_multiply",
  ];
  const expectedEdges = [
    ["main", "greet_user"],
    ["main", "compute_score"],
    ["compute_score", "helper_add"],
    ["compute_score", "helper_multiply"],
  ];
  const edgeSet = new Set(
    (pass.facts?.directEdges ?? []).map(([c, f]) => `${c}>${f}`),
  );
  const checks = {
    status_complete: pass.status === "complete",
    procedure_count_27: pass.facts?.procedureCount === 27,
    names_present: expectedNames.every((n) =>
      pass.facts?.definedNames.includes(n),
    ),
    edges_present: expectedEdges.every(([c, f]) => edgeSet.has(`${c}>${f}`)),
  };
  const ok = Object.values(checks).every(Boolean);
  log(
    `SANITY: ok=${ok} checks=${JSON.stringify(checks)} wall=${pass.wall_ms}ms`,
  );
  return {
    ok,
    checks,
    wall_ms: pass.wall_ms,
    peak_rss_bytes: pass.peak_rss_bytes,
    failure_reason: pass.failure_reason,
  };
};

// ---------------------------------------------------------------- scored runs
const runTargetRep = async (manifest, target, rep) => {
  const truth = truthOf(target);
  const repDir = join(OUT, "runs", target.target_id, `rep${rep}`);
  const load = loadAvg();
  const pass = await runStaticPass({
    binaryPath: target.binary_path,
    worktree: REPO,
    ghidraInstallDir: GHIDRA_DIR,
    javaHome: JAVA_HOME,
  });
  if (pass.status !== "complete")
    return {
      target_id: target.target_id,
      rep,
      failed: `static: ${pass.failure_reason}`,
      load,
    };
  const elf = readElfMetadata(target.binary_path);
  const facts = {
    ...pass.facts,
    procedureNames: new Set(pass.facts.procedureNames),
    symbolNames: elf.symbolNames,
    sectionNames: new Set(elf.sectionNames),
    dtNeeded: elf.dtNeeded,
    interpBasename: elf.interp?.split("/").pop() ?? null,
    commentStrings: elf.commentStrings,
  };
  const claimsS = staticClaims(facts);
  let claimsD = { items: new Set(claimsS.items), outputs: new Map() };
  const graph = {
    directEdges: pass.facts.directEdges,
    xrefEdges: pass.facts.xrefEdges,
  };
  let dynamicWall = 0;
  let dynamicPeak = 0;
  for (const stimulus of target.stimuli) {
    const run = await runDynamicJob({
      job: {
        program: target.binary_path,
        argv: stimulus.argv,
        env_set: stimulus.env ?? {},
        env_unset: envKeysOf(target).filter(
          (k) => !(k in (stimulus.env ?? {})),
        ),
        cwd: binDirOf(target),
        hook_pack_source: HOOK_PACK_SOURCE,
        session_timeout_ms: stimulus.timeout_ms,
        hold_after_exit_ms: 0,
      },
      fixtureBinDir: binDirOf(target),
      runDir: join(repDir, stimulus.stimulus_id),
      deadlineMs: stimulus.timeout_ms + 45000,
      rssCapBytes: RSS_CAP,
    });
    if (run.result?.status !== "complete")
      return {
        target_id: target.target_id,
        rep,
        failed: `dynamic ${stimulus.stimulus_id}: worker=${run.result?.status ?? "no-result"} ${run.result?.failure_reason ?? ""} supervisor=${run.outcome}`,
        load,
      };
    if (run.containment_breach || run.survivors_after.length > 0)
      return {
        target_id: target.target_id,
        rep,
        failed: `dynamic ${stimulus.stimulus_id}: containment breach survivors=${JSON.stringify(run.survivors_after)}`,
        load,
      };
    dynamicWall += run.result.wall_ms;
    dynamicPeak = Math.max(dynamicPeak, run.peak_rss_bytes);
    const observation = {
      texts: run.result.observations.texts,
      stdout: run.result.stdout_text,
      dlopen: run.result.observations.dlopen,
      dlsym: run.result.observations.dlsym,
    };
    claimsD = dynamicClaims(
      claimsD,
      observation,
      { candidateEdges: candidateEdges(graph, observation) },
      stimulus.stimulus_id,
    );
  }
  const record = {
    target_id: target.target_id,
    class: target.class,
    rep,
    load,
    static: {
      wall_ms: pass.wall_ms,
      peak_rss_bytes: pass.peak_rss_bytes,
      provider: pass.provider,
      facts_summary: {
        strings: pass.facts.stringFacts.length,
        procedures: pass.facts.procedureCount,
        direct_edges: pass.facts.directEdges.length,
        xref_edges: pass.facts.xrefEdges.length,
      },
    },
    dynamic: {
      wall_ms: dynamicWall,
      peak_rss_bytes: dynamicPeak,
    },
    claims_static: {
      items: [...claimsS.items].sort(),
      outputs: [...claimsS.outputs.entries()],
    },
    claims_dynamic: {
      items: [...claimsD.items].sort(),
      outputs: [...claimsD.outputs.entries()],
    },
  };
  writeJson(`runs/${target.target_id}/rep${rep}/record.json`, record);
  return { ...record, claimsS, claimsD };
};

const serializeClaims = (claims) =>
  JSON.stringify({
    items: [...claims.items].sort(),
    outputs: [...claims.outputs.entries()].sort(([a], [b]) => (a < b ? -1 : 1)),
  });

/** A completed repetition's record on disk is reused verbatim (resume). */
const loadExistingRep = (target, rep) => {
  const path = join(OUT, "runs", target.target_id, `rep${rep}`, "record.json");
  if (!existsSync(path)) return null;
  try {
    const record = JSON.parse(readFileSync(path, "utf8"));
    if (!record.claims_static || !record.claims_dynamic) return null;
    return {
      ...record,
      claimsS: {
        items: new Set(record.claims_static.items),
        outputs: new Map(record.claims_static.outputs),
      },
      claimsD: {
        items: new Set(record.claims_dynamic.items),
        outputs: new Map(record.claims_dynamic.outputs),
      },
    };
  } catch {
    return null;
  }
};

const infrastructureRetries = [];
const obtainRep = async (manifest, target, rep) => {
  const existing = loadExistingRep(target, rep);
  if (existing) {
    log(`SCORED ${target.target_id} rep${rep}: resumed from record`);
    return existing;
  }
  let record = await runTargetRep(manifest, target, rep);
  if (record.failed) {
    infrastructureRetries.push({
      target_id: target.target_id,
      rep,
      reason: record.failed,
    });
    log(
      `SCORED ${target.target_id} rep${rep}: infrastructure failure, retrying once: ${record.failed}`,
    );
    record = await runTargetRep(manifest, target, rep);
  }
  return record;
};

const runScored = async (manifest, excluded) => {
  const targets = manifest.targets.filter(
    (t) => !t.containment && !excluded.has(t.target_id),
  );
  const perTarget = [];
  const discards = [];
  const divergences = [];
  for (const target of targets) {
    const truth = truthOf(target);
    let reps = [];
    for (let rep = 1; rep <= REPETITIONS; rep++) {
      const record = await obtainRep(manifest, target, rep);
      if (record.failed) {
        log(`SCORED ${target.target_id} rep${rep}: FAILED ${record.failed}`);
        return {
          failed: `${target.target_id} rep${rep}: ${record.failed}`,
          perTarget,
          discards,
          divergences,
        };
      }
      reps.push(record);
      log(
        `SCORED ${target.target_id} rep${rep}: static_wall=${record.static.wall_ms} dynamic_wall=${record.dynamic.wall_ms}`,
      );
    }
    // Outlier rule (spec section 2): a rep whose arm wall exceeds 2x the
    // cell median is discarded and repeated once; the discard is recorded.
    for (let attempt = 0; attempt < 1; attempt++) {
      const staticWalls = reps.map((r) => r.static.wall_ms);
      const dynamicWalls = reps.map(
        (r) => r.static.wall_ms + r.dynamic.wall_ms,
      );
      const medS = median(staticWalls);
      const medD = median(dynamicWalls);
      const outlierIndex = reps.findIndex(
        (r) =>
          r.static.wall_ms > 2 * medS ||
          r.static.wall_ms + r.dynamic.wall_ms > 2 * medD,
      );
      if (outlierIndex < 0) break;
      const dropped = reps[outlierIndex];
      discards.push({
        target_id: target.target_id,
        rep: dropped.rep,
        static_wall_ms: dropped.static.wall_ms,
        dynamic_wall_ms: dropped.static.wall_ms + dropped.dynamic.wall_ms,
        median_static_wall_ms: medS,
        median_dynamic_wall_ms: medD,
        reason: "wall exceeded 2x cell median",
      });
      log(
        `SCORED ${target.target_id}: discarded rep${dropped.rep} (outlier), repeating once`,
      );
      const replacement = await obtainRep(
        manifest,
        target,
        REPETITIONS + 1 + attempt,
      );
      if (replacement.failed)
        return {
          failed: `${target.target_id} repeat: ${replacement.failed}`,
          perTarget,
          discards,
          divergences,
        };
      reps = reps.filter((_, i) => i !== outlierIndex).concat(replacement);
    }
    // Claim sets must be identical across repetitions.
    const first = reps[0];
    for (const rep of reps.slice(1)) {
      if (serializeClaims(rep.claimsS) !== serializeClaims(first.claimsS))
        divergences.push({
          target_id: target.target_id,
          rep: rep.rep,
          arm: "static",
        });
      if (serializeClaims(rep.claimsD) !== serializeClaims(first.claimsD))
        divergences.push({
          target_id: target.target_id,
          rep: rep.rep,
          arm: "dynamic",
        });
    }
    perTarget.push({
      target_id: target.target_id,
      class: target.class,
      static: scoreClaims(truth, first.claimsS),
      dynamic: scoreClaims(truth, first.claimsD),
      static_wall_ms: median(reps.map((r) => r.static.wall_ms)),
      dynamic_wall_ms: median(
        reps.map((r) => r.static.wall_ms + r.dynamic.wall_ms),
      ),
      static_peak_rss_bytes: median(reps.map((r) => r.static.peak_rss_bytes)),
      dynamic_peak_rss_bytes: median(
        reps.map((r) =>
          Math.max(r.static.peak_rss_bytes, r.dynamic.peak_rss_bytes),
        ),
      ),
      repetitions: reps.length,
    });
  }
  return { perTarget, discards, divergences, infrastructureRetries };
};

// ---------------------------------------------------------------- verdict
const renderVerdictMd = (verdict) => {
  const pct = (v) => (v === null ? "n/a" : `${(v * 100).toFixed(1)}%`);
  const rows = (title, data) => {
    const lines = [
      `| ${title} | S success | D success | gain (pts) | S FP | D FP | S wall ms | D wall ms | S peak RSS | D peak RSS |`,
      `|---|---|---|---|---|---|---|---|---|---|`,
    ];
    const push = (name, row) => {
      const gain = ((row.dynamic.success - row.static.success) * 100).toFixed(
        1,
      );
      lines.push(
        `| ${name} | ${pct(row.static.success)} | ${pct(row.dynamic.success)} | ${gain} | ${pct(row.static.fp_rate)} | ${pct(row.dynamic.fp_rate)} | ${Math.round(row.static_wall_ms)} | ${Math.round(row.dynamic_wall_ms)} | ${row.static_peak_rss_bytes} | ${row.dynamic_peak_rss_bytes} |`,
      );
    };
    for (const [name, row] of Object.entries(data.classes))
      push(`class ${name}`, row);
    push("OVERALL", data.overall);
    return lines.join("\n");
  };
  return [
    `# Dynamic-execution ablation — verdict record`,
    ``,
    `Generated: ${verdict.generated_at}`,
    `Run records: ${verdict.run_records_dir}`,
    ``,
    `## Versions`,
    ``,
    `- Frida (Node binding, REA+ composition): ${verdict.versions.frida}`,
    `- Ghidra: ${verdict.versions.ghidra}`,
    `- Hook pack: ${verdict.versions.hook_pack}`,
    `- Node: ${verdict.versions.node}, gcc: ${verdict.versions.gcc}`,
    ``,
    `## Gates`,
    ``,
    `- Containment: ${verdict.containment.ok ? "PASS" : "FAIL"} (${verdict.containment.results.map((r) => `${r.target_id}:${r.outcome ?? r.worker_status}`).join(", ")})`,
    `- Harness fidelity: ${verdict.fidelity.checks - verdict.fidelity.failures.length}/${verdict.fidelity.checks} stimulus outputs match truth`,
    `- Instrumented fidelity: ${verdict.instrumented_fidelity ? `${verdict.instrumented_fidelity.checks - verdict.instrumented_fidelity.failures.length}/${verdict.instrumented_fidelity.checks} sessions reproduce truth stdout` : "not run"}`,
    `- Static-arm sanity (Ghidra lane fixtures): ${verdict.sanity.ok ? "PASS" : "FAIL"}`,
    `- Fidelity exclusions: ${verdict.exclusions.length === 0 ? "none" : JSON.stringify(verdict.exclusions)}`,
    `- Discarded/repeated runs: ${verdict.discards.length} (${verdict.discards.map((d) => `${d.target_id} rep${d.rep}: ${d.reason}`).join("; ") || "none"})`,
    `- Claim-set divergences across repetitions: ${verdict.divergences.length}`,
    `- Infrastructure retries (failed pass retried once, no data scored from the failed attempt): ${(verdict.infrastructure_retries ?? []).length}${(verdict.infrastructure_retries ?? []).length ? ` (${verdict.infrastructure_retries.map((r) => `${r.target_id} rep${r.rep}`).join("; ")})` : ""}`,
    ``,
    `## Results (median repetition per target; item-weighted class/overall)`,
    ``,
    rows("scope", verdict.aggregate),
    ``,
    `Per-target detail is in the verdict JSON beside the run records.`,
    ``,
    `## Decision rule (pre-registered, applied mechanically)`,
    ``,
    `- Overall gain: ${verdict.decision.inputs.gain_points.toFixed(1)} points`,
    `- Classes with gain >= 25 points: ${verdict.decision.inputs.classes_with_gain_at_least_25} of 4 (${Object.entries(
      verdict.decision.inputs.class_gains_points,
    )
      .map(([c, g]) => `${c}: ${g.toFixed(1)}`)
      .join(", ")})`,
    `- Dynamic FP rate: ${pct(verdict.decision.inputs.dynamic_fp_rate)}`,
    `- Median wall ratio D/S: ${verdict.decision.inputs.wall_ratio.toFixed(2)}`,
    `- Containment proven: ${verdict.decision.inputs.containment_ok}`,
    `- Reasons: ${verdict.decision.reasons.join("; ")}`,
    ``,
    `## VERDICT: ${verdict.decision.verdict}`,
    ``,
  ].join("\n");
};

// ---------------------------------------------------------------- main
const manifest = (() => {
  if (PHASE === "all") return buildFixtures();
  return existsSync(join(FIXTURES_ROOT, "manifest.json"))
    ? loadManifest()
    : buildFixtures();
})();
const hashProblems = verifyManifest(manifest);
if (hashProblems.length > 0) {
  log(`MANIFEST HASH FAILURE: ${hashProblems.join("; ")} — refusing to score`);
  process.exit(1);
}
log(
  `MANIFEST OK: ${manifest.targets.length} targets, frida=${fridaVersion} ghidra=${ghidraVersion} hook_pack=${HOOK_PACK_VERSION}`,
);

let containment = { ok: false, results: [] };
let fidelity = { checks: 0, failures: [] };
let sanity = { ok: false };
if (PHASE === "all" || PHASE === "containment") {
  containment = await runContainment(manifest);
  writeJson("containment.json", containment);
  if (!containment.ok) {
    log(
      "CONTAINMENT FAILED — no scored run counts (spec section 3). Verdict: KILL by containment.",
    );
    const verdict = {
      generated_at: new Date().toISOString(),
      run_records_dir: OUT,
      versions: {
        frida: fridaVersion,
        ghidra: ghidraVersion,
        hook_pack: HOOK_PACK_VERSION,
        node: process.version,
        gcc: gccVersion,
      },
      containment,
      fidelity,
      sanity,
      exclusions: [],
      discards: [],
      divergences: [],
      aggregate: null,
      decision: {
        verdict: "KILL",
        inputs: {
          gain_points: 0,
          dynamic_fp_rate: null,
          wall_ratio: 0,
          class_gains_points: {},
          classes_with_gain_at_least_25: 0,
          containment_ok: false,
        },
        reasons: ["containment could not be proven"],
      },
    };
    writeJson("verdict.json", verdict);
    if (VERDICT_MD)
      writeFileSync(
        VERDICT_MD,
        renderVerdictMd({
          ...verdict,
          aggregate: {
            classes: {},
            overall: {
              static: { success: 0, fp_rate: null },
              dynamic: { success: 0, fp_rate: null },
              static_wall_ms: 0,
              dynamic_wall_ms: 0,
              static_peak_rss_bytes: 0,
              dynamic_peak_rss_bytes: 0,
            },
          },
        }),
      );
    process.exit(0);
  }
}
if (PHASE === "all" || PHASE === "fidelity") {
  fidelity = await runFidelity(manifest);
  writeJson("fidelity.json", fidelity);
}
if (PHASE === "all" || PHASE === "sanity") {
  sanity = await runSanity();
  writeJson("sanity.json", sanity);
  if (!sanity.ok) {
    log(
      "STATIC-ARM SANITY FAILED — the static arm is not the real Ghidra path; stopping.",
    );
    process.exit(1);
  }
}
if (PHASE === "all" || PHASE === "score") {
  // Phase-wise reruns reuse earlier gate results recorded in --out.
  if (containment.ok === false && existsSync(join(OUT, "containment.json")))
    containment = JSON.parse(
      readFileSync(join(OUT, "containment.json"), "utf8"),
    );
  if (fidelity.checks === 0 && existsSync(join(OUT, "fidelity.json")))
    fidelity = JSON.parse(readFileSync(join(OUT, "fidelity.json"), "utf8"));
  if (sanity.ok === false && existsSync(join(OUT, "sanity.json")))
    sanity = JSON.parse(readFileSync(join(OUT, "sanity.json"), "utf8"));
  const instrumented = await runInstrumentedFidelity(manifest);
  writeJson("instrumented-fidelity.json", instrumented);
  const excluded = new Map();
  for (const failure of fidelity.failures)
    excluded.set(
      failure.target_id,
      "fidelity failure: standalone output diverged from truth",
    );
  for (const failure of instrumented.failures)
    excluded.set(
      failure.target_id,
      `instrumented fidelity failure at ${failure.stimulus_id}: worker=${failure.worker_status} ${failure.failure_reason ?? ""}`.trim(),
    );
  const scored = await runScored(manifest, excluded);
  if (scored.failed) {
    log(`SCORED RUN FAILED: ${scored.failed}`);
    writeJson("scored-failure.json", scored);
    process.exit(1);
  }
  const aggregate = aggregateBenchmark(scored.perTarget);
  const decision = applyDecisionRule(aggregate, containment.ok);
  const verdict = {
    generated_at: new Date().toISOString(),
    run_records_dir: OUT,
    versions: {
      frida: fridaVersion,
      ghidra: ghidraVersion,
      hook_pack: HOOK_PACK_VERSION,
      node: process.version,
      gcc: gccVersion,
    },
    containment,
    fidelity,
    instrumented_fidelity: instrumented,
    sanity,
    exclusions: [...excluded.entries()].map(([target_id, reason]) => ({
      target_id,
      reason,
    })),
    discards: scored.discards,
    divergences: scored.divergences,
    infrastructure_retries: scored.infrastructureRetries,
    per_target: scored.perTarget,
    aggregate,
    decision,
  };
  // Determinism: re-derive the decision from the same aggregates and
  // compare the verdict bytes modulo the timestamp.
  const verdictAgain = {
    ...verdict,
    generated_at: "determinism-check",
    decision: applyDecisionRule(aggregate, containment.ok),
  };
  const strip = (v) => JSON.stringify({ ...v, generated_at: "x" });
  const deterministic = strip(verdict) === strip(verdictAgain);
  verdict.deterministic_scoring = deterministic;
  writeJson("verdict.json", verdict);
  writeJson("per-target.json", scored.perTarget);
  if (VERDICT_MD) writeFileSync(VERDICT_MD, renderVerdictMd(verdict));
  log(
    `VERDICT: ${decision.verdict} — ${decision.reasons.join("; ")}; deterministic=${deterministic}`,
  );
}
log("DONE");
