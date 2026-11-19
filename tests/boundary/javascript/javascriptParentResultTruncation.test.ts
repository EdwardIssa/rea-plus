import { createHash } from "node:crypto";
import { afterAll, expect, it, vi } from "vitest";

const heapObservation = vi.hoisted(() => ({
  remainingBytes: 320 * 1024 * 1024,
}));

// Script the parent's live heap envelope: healthy for the first source, then
// collapsed to the transfer-reserve floor so every later source's static
// admission trips the parent's result capacity. The child analyzer remains a
// real separately owned Node process.
vi.mock("node:v8", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:v8")>();
  return {
    ...actual,
    getHeapStatistics: () => {
      const snapshot = actual.getHeapStatistics();
      return {
        ...snapshot,
        heap_size_limit:
          snapshot.used_heap_size + heapObservation.remainingBytes,
      };
    },
  };
});

import { JavaScriptAnalysisWorker } from "../../../src/javascript/analysis/JavaScriptAnalysisWorker.js";
import { AnalysisResourceConstraintError } from "../../../src/domain/analysisErrorCore.js";
import type { JavaScriptArtifactFile } from "../../../src/domain/javascript/javascriptArtifactFiles.js";

afterAll(() => {
  vi.doUnmock("node:v8");
  vi.resetModules();
});

const file = (path: string): JavaScriptArtifactFile => {
  const text = `export const marker = "${path}";`;
  return {
    path,
    sha256: createHash("sha256").update(text).digest("hex"),
    container_sha256: "1".repeat(64),
    bytes: Buffer.byteLength(text),
    inventory_artifact_id: `truncation-fixture-${path}`,
    kind: "javascript",
    unpacked: false,
    text: { included: true, value: text },
  };
};

// Pins the resume contract of the parent result-budget degradation: the
// first source past capacity reports parent_result_budget_exhausted, and a
// later source still completes its static facts while reporting
// parent_result_budget_truncated with a resume cursor naming the first
// truncated source. No other test asserts these markers.
it("reports the truncation marker and resume cursor on sources after the first capacity exhaustion", async () => {
  heapObservation.remainingBytes = 320 * 1024 * 1024;
  const worker = new JavaScriptAnalysisWorker(
    { heapMb: 128, timeoutMs: 30_000 },
    undefined,
    3,
  );
  try {
    const capacity = { nodes: 100, unknowns: 100 };
    const first = await worker.analyze(file("first.js"), capacity);
    expect(first.ok).toBe(true);

    const collapseAtStatic = async (phase: string) => {
      if (phase === "static")
        heapObservation.remainingBytes = 128 * 1024 * 1024;
    };
    const second = await worker.analyze(
      file("second.js"),
      capacity,
      undefined,
      collapseAtStatic,
    );
    if (second.ok)
      throw new Error("Expected the second source to exhaust capacity");
    expect(second.error.javascript?.parse_status).toBe("complete");
    const secondError = second.error.error;
    if (!(secondError instanceof AnalysisResourceConstraintError))
      throw new Error("Expected a typed resource constraint");
    expect(secondError.reportedLimits).toMatchObject({
      parent_result_budget_exhausted: true,
    });
    expect(
      secondError.reportedLimits?.parent_result_budget_truncated,
    ).toBeUndefined();

    const third = await worker.analyze(
      file("third.js"),
      capacity,
      undefined,
      collapseAtStatic,
    );
    if (third.ok)
      throw new Error("Expected the third source to report truncation");
    expect(third.error.javascript?.parse_status).toBe("complete");
    const thirdError = third.error.error;
    if (!(thirdError instanceof AnalysisResourceConstraintError))
      throw new Error("Expected a typed resource constraint");
    expect(thirdError.reason).toContain("truncated");
    expect(thirdError.reportedLimits).toMatchObject({
      parent_result_budget_truncated: true,
      resume_source_index: 1,
      resume_source_path: "second.js",
    });
    expect(
      thirdError.reportedLimits?.parent_result_budget_exhausted,
    ).toBeUndefined();
  } finally {
    heapObservation.remainingBytes = 320 * 1024 * 1024;
    await worker.close();
  }
}, 60_000);
