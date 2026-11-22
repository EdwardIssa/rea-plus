import { z } from "zod";

import { ConfigurationError } from "../domain/configurationErrors.js";
import { err, ok, type Result } from "../domain/result.js";

/**
 * Which MCP tools a server advertises at connect. `full` advertises every
 * registered tool (the historical surface). `lazy` advertises only the core
 * group plus the discovery tools; every other tool stays registered and is
 * advertised on demand through `search_tools` and `load_tool_schema`, so a
 * client never pays the full catalog's schema tokens up front and a host
 * with a frame-capped tools/list still accepts the surface.
 */
export const mcpToolSurfaceSchema = z.enum(["full", "lazy"]);

export type McpToolSurfaceMode = z.infer<typeof mcpToolSurfaceSchema>;

const surfaceConstraint =
  'REA_MCP_TOOL_SURFACE must be "full" or "lazy" (default "lazy"). The lazy surface advertises only core and discovery tools at connect; all other tools remain registered and load on demand.';

/** Parse the advertised-surface selection at server composition. */
export const parseMcpToolSurface = (
  value: string | undefined,
): Result<McpToolSurfaceMode | undefined, ConfigurationError> => {
  if (value === undefined) return ok(undefined);
  const parsed = mcpToolSurfaceSchema.safeParse(value);
  return parsed.success
    ? ok(parsed.data)
    : err(
        new ConfigurationError(surfaceConstraint, {
          settings: [
            {
              setting: "REA_MCP_TOOL_SURFACE",
              constraint: surfaceConstraint,
            },
          ],
        }),
      );
};
