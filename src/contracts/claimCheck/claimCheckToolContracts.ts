import { z } from "zod";

import { claimCheckRunOutcomeSchema } from "../../application/claimCheck/runClaimCheck.js";
import { localPathStringSchema } from "../../domain/localPath.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";

/** Caller-selected Evidence, artifact, and ledger paths for one claim check. */
export const adjudicateStringClaimsInputSchema = z.strictObject({
  evidence_path: localPathStringSchema.describe(
    "Path to Evidence JSON: one list_strings/search_strings record or an array of records",
  ),
  artifact_path: localPathStringSchema.describe(
    "Path to the local artifact the Evidence describes",
  ),
  ledger_path: localPathStringSchema.describe(
    "Path the committed claim-check ledger JSON is written to",
  ),
});

/** Claim-check adjudication is independent of any active native-analysis target. */
export const CLAIM_CHECK_TOOL_CONTRACTS = [
  {
    name: "adjudicate_string_claims",
    ...toolContractMetadata("adjudicate_string_claims"),
    kind: "application",
    description:
      "Adjudicate native string claims from list_strings/search_strings Evidence against the artifact's own bytes. The Evidence is authenticated, the artifact's SHA-256 must match the Evidence subject (a mismatch aborts before any verdict), and each claim is re-derived from the artifact bytes by a deterministic validator that shares no code path with any producing provider: supported when the bytes at the claimed address equal the assertion, refuted when they differ, unknown with a reason when the bytes cannot adjudicate it (unmapped address, undeclared encoding, unsupported format). ELF artifacts are mapped through their program headers; other formats adjudicate unknown/format_not_supported. Verdicts are committed to an append-only, hash-chained claim-check ledger written to ledger_path; refuting a claim appends stale marks to its dependents without changing their states. Returns the ledger, verdict counts, and the report digest (a digest commitment, not a cryptographic signature). The validator reads only the artifact bytes; no provider is consulted again.",
    inputSchema: adjudicateStringClaimsInputSchema,
    outputSchema: claimCheckRunOutcomeSchema,
    examples: [
      {
        title: "Adjudicate string claims for one artifact",
        input: {
          evidence_path: "/artifacts/app-strings.evidence.json",
          artifact_path: "/artifacts/app",
          ledger_path: "/artifacts/app.claim-check.json",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
