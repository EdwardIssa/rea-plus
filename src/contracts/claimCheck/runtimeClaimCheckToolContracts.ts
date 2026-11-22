import { z } from "zod";

import { runtimeClaimCheckRunOutcomeSchema } from "../../domain/claimCheck/claimCheckRuntimeReport.js";
import { localPathStringSchema } from "../../domain/localPath.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";

/** Caller-selected Evidence and ledger paths for one runtime claim check. */
export const adjudicateRuntimeClaimsInputSchema = z.strictObject({
  evidence_path: localPathStringSchema.describe(
    "Path to Evidence JSON: execute_dynamically records (one record or an array); present at least three records per stimulus (one source record and two replay records) for a claim to be able to reach supported",
  ),
  ledger_path: localPathStringSchema.describe(
    "Path the committed claim-check ledger JSON is written to",
  ),
});

/** Runtime claim-check adjudication is independent of any active native-analysis target. */
export const RUNTIME_CLAIM_CHECK_TOOL_CONTRACTS = [
  {
    name: "adjudicate_runtime_claims",
    ...toolContractMetadata("adjudicate_runtime_claims"),
    kind: "application",
    description:
      "Adjudicate runtime string claims from execute_dynamically Evidence by replay recurrence. A claim is one string row filed by a Frida execute_dynamically record, keyed to the artifact and to the exact stimulus (argv and environment set) that produced it. This tool only reads records: produce them first with execute_dynamically, at least three per stimulus (one source record and two replay witnesses), and present all of them together; no provider is consulted again. The validator re-derives every record's observed strings from its preserved raw hook log with its own implementation, never trusting the filed rows: a claim its own filing record's complete log does not contain is refuted as record-inconsistent, and a claim is supported only when it recurs in the re-derived logs of at least two further eligible witnesses under the same stimulus. With fewer usable witnesses a claim stays unknown (recurrence_unconfirmed); it is never supported on a single record's say-so. Terminated, truncated, hook-incomplete, pack-skewed, or containment-breaching records are ineligible as witnesses and are counted by cause, never read as absences. Values that differ between records only in digit or address segments are screened as volatile and stay unknown rather than refuted. Verdicts are committed to an append-only, hash-chained claim-check ledger written to ledger_path; returns the ledger, verdict counts, and the report digest (a digest commitment, not a cryptographic signature). No artifact path is taken: the artifact's bytes are not this class's truth source. Observed modules, symbols, and output text are not adjudicated by this class.",
    inputSchema: adjudicateRuntimeClaimsInputSchema,
    outputSchema: runtimeClaimCheckRunOutcomeSchema,
    examples: [
      {
        title: "Adjudicate runtime string claims from replay Evidence",
        input: {
          evidence_path: "/artifacts/app-runs.evidence.json",
          ledger_path: "/artifacts/app.runtime-claim-check.json",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
