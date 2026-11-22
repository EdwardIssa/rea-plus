import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { runClaimCheckCommand } from "../application/claimCheck/runClaimCheck.js";
import { toolContract } from "../contracts/toolContracts.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Claim-check adjudication needs no session, provider, or active target. */
export const registerClaimCheckTool = (server: EvidenceMcpServer): void => {
  const contract = toolContract("adjudicate_string_claims");
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input, context) =>
      server.delivery.toCallToolResult(
        await runClaimCheckCommand(
          {
            evidencePath: input.evidence_path,
            artifactPath: input.artifact_path,
            ledgerPath: input.ledger_path,
          },
          context.mcpReq.signal,
        ),
        contract,
      ),
  );
};
