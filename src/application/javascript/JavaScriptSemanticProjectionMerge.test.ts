import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import type { JavaScriptArtifactFile } from "../../domain/javascript/javascriptArtifactFiles.js";
import { analyzeJavaScriptSemantics } from "../../domain/javascript/javascriptSemanticAnalysis.js";
import { mergeJavaScriptSemanticFileProjections } from "../../domain/javascript/javascriptSemanticFileProjection.js";
import { projectJavaScriptSemanticFileSteps } from "./JavaScriptSemanticGraphBuilder.js";
import { completeJavaScriptAnalysisSteps } from "./JavaScriptAnalysisControl.js";

const digest = "a".repeat(64);
const source = (value: string): JavaScriptArtifactFile => ({
  path: "app.js",
  sha256: createHash("sha256").update(value).digest("hex"),
  container_sha256: digest,
  bytes: Buffer.byteLength(value),
  inventory_artifact_id: `art_${digest}`,
  kind: "javascript",
  unpacked: false,
  text: { included: true, value },
});

const projectFile = async (value: string, nodes = 20_000, unknowns = 2_000) => {
  const file = source(value);
  if (!file.text.included) throw new Error("Expected inert source");
  return completeJavaScriptAnalysisSteps(
    projectJavaScriptSemanticFileSteps(
      file,
      analyzeJavaScriptSemantics(value),
      { nodes, unknowns },
    ),
  );
};

it("dedupes a shard projection merged with itself", async () => {
  const projection = await projectFile(
    "globalThis.alpha.run(globalThis.beta);\n",
  );
  const merged = mergeJavaScriptSemanticFileProjections([
    projection,
    projection,
  ]);
  expect(merged.nodes).toEqual(projection.nodes);
  expect(merged.relations).toEqual(projection.relations);
  expect(merged.unknowns).toEqual(projection.unknowns);
  expect(merged.roots).toEqual(projection.roots);
});

it("sums omitted unknown occurrences across shards", async () => {
  const text = "globalThis.u.p(globalThis.v[k]);\n".repeat(4);
  const bounded = await projectFile(text, 200, 2);
  expect(bounded.omittedUnknownOccurrences?.length).toBeGreaterThan(0);
  const merged = mergeJavaScriptSemanticFileProjections([bounded, bounded]);
  const total = (rows: typeof bounded.omittedUnknownOccurrences) =>
    (rows ?? []).reduce((sum, row) => sum + row.occurrences, 0);
  expect(total(merged.omittedUnknownOccurrences)).toBe(
    2 * total(bounded.omittedUnknownOccurrences),
  );
});

it("propagates node truncation from any shard", async () => {
  const complete = await projectFile("globalThis.a.b();\n");
  const truncated = { ...complete, nodesTruncated: true };
  const merged = mergeJavaScriptSemanticFileProjections([complete, truncated]);
  expect(merged.nodesTruncated).toBe(true);
});
