import { z } from "zod";

import { dynamicExecutionRunOutcomeSchema } from "../../domain/dynamicExecution/dynamicExecutionReport.js";
import { localPathStringSchema } from "../../domain/localPath.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";

/** Caller-selected target, stimulus, budgets, and Evidence output path for one dynamic run. */
export const executeDynamicallyInputSchema = z.strictObject({
  target_path: localPathStringSchema.describe(
    "Path to the local target executable to run once under supervision",
  ),
  argv: z
    .array(z.string())
    .optional()
    .describe("Stimulus arguments passed to the target (default: none)"),
  env_set: z
    .record(z.string(), z.string())
    .optional()
    .describe(
      "Environment entries added to the scrubbed allowlist environment for the target (default: none)",
    ),
  session_timeout_ms: z
    .int()
    .min(1000)
    .max(600000)
    .optional()
    .describe("Worker session timeout in milliseconds (default: 30000)"),
  deadline_ms: z
    .int()
    .positive()
    .max(900000)
    .optional()
    .describe(
      "Supervisor wall-clock deadline in milliseconds; must exceed session_timeout_ms (default: session_timeout_ms + 45000)",
    ),
  rss_cap_bytes: z
    .int()
    .min(268435456)
    .optional()
    .describe(
      "Supervisor process-tree RSS cap in bytes (default: 3221225472 = 3 GiB)",
    ),
  evidence_path: localPathStringSchema.describe(
    "Path the Evidence JSON record is written to",
  ),
});

/** Dynamic execution is independent of any active native-analysis session. */
export const DYNAMIC_EXECUTION_TOOL_CONTRACTS = [
  {
    name: "execute_dynamically",
    ...toolContractMetadata("execute_dynamically"),
    kind: "application",
    description:
      "Execute one caller-designated local target once, with one stimulus (argv + env entries), inside user, net, and mount namespaces on Linux: the target's directory is bind-mounted read-only, the environment is scrubbed to an allowlist plus the caller's entries, a subreaper shim keeps escaped descendants inside the accounting, and a supervisor enforces a wall-clock deadline and a process-tree RSS cap with a full termination cascade and a post-settle survivor sweep. Runtime observations from the shipped, versioned Frida hook pack (version recorded in the result) are filed under exactly one kind each, a loaded module path as a module only, a resolved symbol name as a symbol only, stream bytes as output only, and strings only from output-function argument captures, and are returned as one content-addressed Evidence record written to evidence_path; the verbatim hook message log is preserved in that record's raw_result. A run the deadline or RSS cap ends still produces Evidence with the termination recorded in its limitations; a worker that crashes without publishing a result fails with no Evidence. The isolation is rated for analyst-designated targets on the analyst's own machine; a user namespace is not a hard boundary against a kernel-exploit target. Runtime observations are not adjudicated by claim-check in this release: claim-check adjudicates native string claims from static Evidence only, and silence from it must not be read as adjudication of dynamic Evidence. One run at a time per server process; a second request while a run is in flight is refused as busy, not queued. If the Frida binding cannot load, or its major version differs from the hook pack's tested major, the command refuses before any target process starts, naming the real cause, and writes no Evidence.",
    inputSchema: executeDynamicallyInputSchema,
    outputSchema: dynamicExecutionRunOutcomeSchema,
    examples: [
      {
        title: "Execute a target once and record runtime Evidence",
        input: {
          target_path: "/artifacts/app",
          argv: ["--self-test"],
          evidence_path: "/artifacts/app.dynamic.evidence.json",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
