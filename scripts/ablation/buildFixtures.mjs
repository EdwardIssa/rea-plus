/**
 * Build the dynamic-execution ablation fixtures with the host gcc and emit
 * the fixture manifest with binary hashes (spec-dynamic-execution-ablation
 * section 5, touch item 1). Sources and truth files live in
 * tests/fixtures/dynamic/<id>/; binaries and the manifest are build outputs
 * (gitignored) under tests/fixtures/dynamic/bin/ and manifest.json.
 *
 * Usage: node scripts/ablation/buildFixtures.mjs [--verify]
 *   --verify  rebuild nothing; recompute hashes and compare to the manifest.
 */
import { createCipheriv, createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const FIXTURES_ROOT = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "tests",
  "fixtures",
  "dynamic",
);

const sha256File = (path) =>
  createHash("sha256").update(readFileSync(path)).digest("hex");

/** AES-128-CBC blob for a3: key = SHA256(seed bytes)[0:16], zero IV, PKCS7. */
const generateA3BlobHeader = () => {
  const seed = Buffer.from([97, 51, 45, 107, 100, 102, 45, 115, 101, 101, 100]);
  const key = createHash("sha256").update(seed).digest().subarray(0, 16);
  const cipher = createCipheriv("aes-128-cbc", key, Buffer.alloc(16, 0));
  const blob = Buffer.concat([
    cipher.update("charlie-config-secret", "utf8"),
    cipher.final(),
  ]);
  const bytes = [...blob].join(", ");
  return `static const unsigned char BLOB[] = { ${bytes} };\nstatic const unsigned int BLOB_LEN = ${blob.length};\n`;
};

const listTargets = () =>
  readdirSync(FIXTURES_ROOT, { withFileTypes: true })
    .filter((e) => e.isDirectory() && e.name !== "bin")
    .map((e) => e.name)
    .sort();

export const buildFixtures = () => {
  const targets = [];
  for (const id of listTargets()) {
    const dir = join(FIXTURES_ROOT, id);
    const spec = JSON.parse(readFileSync(join(dir, "fixture.json"), "utf8"));
    const outDir = join(FIXTURES_ROOT, "bin", id);
    const buildDir = join(outDir, ".build");
    mkdirSync(buildDir, { recursive: true });
    for (const src of spec.build.sources)
      copyFileSync(join(dir, src), join(buildDir, src));
    for (const plugin of spec.build.plugins ?? [])
      copyFileSync(join(dir, plugin.source), join(buildDir, plugin.source));
    if ((spec.build.generated ?? []).includes("blob.h"))
      writeFileSync(join(buildDir, "blob.h"), generateA3BlobHeader());
    const gcc = ["-O0", "-Wall", "-I", buildDir];
    const pluginFacts = [];
    for (const plugin of spec.build.plugins ?? []) {
      const out = join(outDir, plugin.name);
      execFileSync(
        "gcc",
        [...gcc, "-shared", "-fPIC", join(buildDir, plugin.source), "-o", out],
        { stdio: "pipe" },
      );
      pluginFacts.push({ name: plugin.name, sha256: sha256File(out) });
    }
    const binaryPath = join(outDir, id);
    execFileSync(
      "gcc",
      [
        ...gcc,
        ...spec.build.sources.map((s) => join(buildDir, s)),
        "-o",
        binaryPath,
        ...(spec.build.link ?? []),
      ],
      { stdio: "pipe" },
    );
    targets.push({
      target_id: id,
      class: spec.class,
      containment: spec.build.containment === true,
      binary: `bin/${id}/${id}`,
      binary_path: binaryPath,
      sha256: sha256File(binaryPath),
      plugins: pluginFacts,
      stimuli: spec.stimuli,
      truth_path: join(dir, "truth.json"),
    });
  }
  const manifest = { version: 1, generated_by: "buildFixtures.mjs", targets };
  writeFileSync(
    join(FIXTURES_ROOT, "manifest.json"),
    JSON.stringify(manifest, null, 1) + "\n",
  );
  return manifest;
};

export const loadManifest = () =>
  JSON.parse(readFileSync(join(FIXTURES_ROOT, "manifest.json"), "utf8"));

/** Recompute every binary hash; returns a list of mismatch descriptions. */
export const verifyManifest = (manifest) => {
  const problems = [];
  for (const t of manifest.targets) {
    if (!existsSync(t.binary_path)) {
      problems.push(`${t.target_id}: binary missing`);
      continue;
    }
    if (sha256File(t.binary_path) !== t.sha256)
      problems.push(`${t.target_id}: binary hash mismatch`);
    for (const p of t.plugins) {
      const ppath = join(FIXTURES_ROOT, "bin", t.target_id, p.name);
      if (!existsSync(ppath) || sha256File(ppath) !== p.sha256)
        problems.push(`${t.target_id}: plugin ${p.name} hash mismatch`);
    }
  }
  return problems;
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--verify")) {
    const problems = verifyManifest(loadManifest());
    if (problems.length > 0) {
      console.error("MANIFEST VERIFY FAILED:\n" + problems.join("\n"));
      process.exit(1);
    }
    console.log("MANIFEST VERIFY OK");
  } else {
    const manifest = buildFixtures();
    console.log(
      `BUILT ${manifest.targets.length} fixtures; manifest at tests/fixtures/dynamic/manifest.json`,
    );
  }
}
