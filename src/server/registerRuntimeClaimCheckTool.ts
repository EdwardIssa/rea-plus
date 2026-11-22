import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { runRuntimeClaimCheckCommand } from "../application/claimCheck/runRuntimeClaimCheck.js";
import { toolContract } from "../contracts/toolContracts.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Runtime claim-check adjudication needs no session, provider, or active target. */
export const registerRuntimeClaimCheckTool = (
  server: EvidenceMcpServer,
): void => {
  const contract = toolContract("adjudicate_runtime_claims");
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input, context) =>
      server.delivery.toCallToolResult(
        await runRuntimeClaimCheckCommand(
          {
            evidencePath: input.evidence_path,
            ledgerPath: input.ledger_path,
          },
          context.mcpReq.signal,
        ),
        contract,
      ),
  );
};
