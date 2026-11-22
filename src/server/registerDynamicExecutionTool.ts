import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { createDynamicExecutionService } from "../application/dynamicExecution/runDynamicExecution.js";
import { toolContract } from "../contracts/toolContracts.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/**
 * Register dynamic execution with its own service instance: the
 * concurrency-1 guard and the provider-state projection live in the
 * service, so one instance serves this server process.
 */
export const registerDynamicExecutionTool = (
  server: EvidenceMcpServer,
): void => {
  const contract = toolContract("execute_dynamically");
  const service = createDynamicExecutionService();
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input, context) =>
      server.delivery.toCallToolResult(
        await service.run(
          {
            targetPath: input.target_path,
            evidencePath: input.evidence_path,
            ...(input.argv === undefined ? {} : { argv: input.argv }),
            ...(input.env_set === undefined ? {} : { envSet: input.env_set }),
            ...(input.session_timeout_ms === undefined
              ? {}
              : { sessionTimeoutMs: input.session_timeout_ms }),
            ...(input.deadline_ms === undefined
              ? {}
              : { deadlineMs: input.deadline_ms }),
            ...(input.rss_cap_bytes === undefined
              ? {}
              : { rssCapBytes: input.rss_cap_bytes }),
          },
          context.mcpReq.signal,
        ),
        contract,
      ),
  );
};
