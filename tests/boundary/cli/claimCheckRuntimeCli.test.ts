import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { parseClaimCheckLedger } from "../../../src/domain/claimCheck/claimCheckLedger.js";
import {
  buildRuntimeClaimCheckReport,
  type RuntimeClaimCheckOutcome,
} from "../../../src/domain/claimCheck/claimCheckRuntimeReport.js";
import {
  runtimeAdjudicationReasonSchema,
  RUNTIME_CLAIM_VALIDATOR,
} from "../../../src/domain/claimCheck/runtimeReplayValidator.js";
import {
  runtimeEvidenceRecord,
  type RuntimeRecordOptions,
} from "../../fixtures/claimCheck/runtimeClaimCheckFixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const writeEvidence = async (
  root: string,
  records: readonly RuntimeRecordOptions[],
): Promise<string> => {
  const path = join(root, "evidence.json");
  await writeFile(
    path,
    JSON.stringify(records.map((options) => runtimeEvidenceRecord(options))),
  );
  return path;
};

const truthOutcomes = (
  ledgerPath: string,
): Promise<readonly RuntimeClaimCheckOutcome[]> =>
  readFile(ledgerPath, "utf8").then((text) => {
    const ledger = parseClaimCheckLedger(JSON.parse(text));
    return ledger.entries
      .filter((entry) => entry.kind === "adjudication")
      .map((entry) => ({
        claim_id: entry.claim_id,
        claim_version: entry.claim_version,
        state: entry.state,
        // This ledger is runtime-class only; the ledger reason union is
        // wider than the runtime report's vocabulary, so narrow through
        // its schema.
        reason: runtimeAdjudicationReasonSchema.parse(entry.reason),
        validator: entry.validator,
        adjudication_digest: entry.record_digest,
        evidence_refs: entry.evidence_refs,
        observation_digest:
          entry.observed !== undefined && "observation_digest" in entry.observed
            ? entry.observed.observation_digest
            : "",
      }));
  });

cliTest(
  "claim-check-runtime adjudicates the known-supported set as supported",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-runtime-claim-check-cli-");
    const evidencePath = await writeEvidence(
      root,
      [11, 22, 33].map((pid) => ({ pid, filed: ["alpha-secret-one"] })),
    );
    const ledgerPath = join(root, "ledger.json");
    const result = await cli.run({
      arguments: ["claim-check-runtime", evidencePath, ledgerPath, "--json"],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const outcome = result.json as {
      counts: { supported: number; refuted: number; unknown: number };
      claims_considered: number;
      report_digest: string;
    };
    expect(outcome.counts).toEqual({ supported: 1, refuted: 0, unknown: 0 });
    expect(outcome.claims_considered).toBe(1);
    expect(outcome.report_digest).toMatch(/^[a-f0-9]{64}$/u);
    const outcomes = await truthOutcomes(ledgerPath);
    expect(outcomes[0]?.reason).toBe("replay_recurred");
    const report = buildRuntimeClaimCheckReport({
      validator: RUNTIME_CLAIM_VALIDATOR,
      truthSetId: "runtime-fixture-truth",
      outcomes: outcomes.map((entry) => ({
        ...entry,
        truth_state: "supported" as const,
      })),
      groups: [],
    });
    expect(report.precision).toBe(1);
    expect(report.coverage).toBe(1);
  },
);

cliTest(
  "claim-check-runtime leaves a lone source record's claim unknown, never supported",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-runtime-claim-check-cli-");
    const evidencePath = await writeEvidence(root, [
      { pid: 11, filed: ["alpha-secret-one"] },
    ]);
    const ledgerPath = join(root, "ledger.json");
    const result = await cli.run({
      arguments: ["claim-check-runtime", evidencePath, ledgerPath, "--json"],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const outcome = result.json as {
      counts: { supported: number; refuted: number; unknown: number };
    };
    expect(outcome.counts).toEqual({ supported: 0, refuted: 0, unknown: 1 });
    const outcomes = await truthOutcomes(ledgerPath);
    expect(outcomes[0]?.reason).toBe("recurrence_unconfirmed");
  },
);
