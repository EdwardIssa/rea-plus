import type { CallToolResult } from "@modelcontextprotocol/server";
import { z } from "zod";

import type { McpToolSurfaceMode } from "../config/mcpToolSurface.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  READ_TOOL_RESULT_PAGE_TOOL_NAME,
  type SurfaceToolBinder,
} from "./toolResultSpillover.js";

/** Intent search over the registered catalog; part of the core surface. */
export const SEARCH_TOOLS_TOOL_NAME = "search_tools";
/** Load one tool's advertised schema and advertise it; core surface. */
export const LOAD_TOOL_SCHEMA_TOOL_NAME = "load_tool_schema";

export const MCP_DISCOVERY_TOOL_NAMES: ReadonlySet<string> = new Set([
  SEARCH_TOOLS_TOOL_NAME,
  LOAD_TOOL_SCHEMA_TOOL_NAME,
]);

/**
 * Tools advertised at connect under the lazy surface before anything is
 * loaded: the target lifecycle, the Evidence spine, settings, and guidance
 * entry points. Every other registered tool stays reachable through
 * discovery; a name listed here that a composition does not register is
 * simply absent.
 */
export const MCP_CORE_TOOL_NAMES: ReadonlySet<string> = new Set([
  "binary_session",
  "open_binary",
  "close_binary",
  "reset_investigation",
  "get_evidence_bundle",
  "export_evidence_bundle",
  "inspect_analysis_view",
  "list_unknowns",
  "inspect_analysis_settings",
  "update_analysis_settings",
  "search_guidance",
  "guided_workflows",
]);

/** One catalog entry the discovery index searches and load returns. */
export interface AdvertisedToolEntry {
  readonly name: string;
  readonly title?: string;
  readonly description?: string;
  readonly family?: string;
}

/** The advertised JSON schemas load returns for one tool. */
export interface AdvertisedToolSchemas {
  readonly inputSchema: Record<string, unknown>;
  readonly outputSchema?: Record<string, unknown>;
}

/**
 * Host operations the surface needs from the owning server: the registry
 * built as tools bind, family advertisement, and schema presentation. The
 * core server implements this over its registration map.
 */
export interface ToolSurfaceHost {
  entries(): readonly AdvertisedToolEntry[];
  schemas(name: string): AdvertisedToolSchemas | undefined;
  /** Whether family scoping advertises this tool at all in this process. */
  advertises(name: string): boolean;
  /** Advertise a registered tool now; false when it is not registered. */
  enable(name: string): boolean;
  /** Withdraw a registered tool's advertisement; false when not registered. */
  disable(name: string): boolean;
}

const tokenize = (text: string): readonly string[] =>
  text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length > 0);

/**
 * Reduce a token to a light stem so inflections meet: a single trailing
 * "s" drops when the token stays longer than three characters (calls ->
 * call, strings -> string, xrefs -> xref). Applied to both sides of every
 * comparison, so exact matches keep matching.
 */
const stem = (token: string): string =>
  token.length > 3 && token.endsWith("s") ? token.slice(0, -1) : token;

const stemmedTokens = (text: string): ReadonlySet<string> =>
  new Set(tokenize(text).map(stem));

/** Whether two stemmed tokens share a prefix of at least four characters. */
const sharesPrefix = (left: string, right: string): boolean =>
  Math.min(left.length, right.length) >= 4 &&
  (left.startsWith(right) || right.startsWith(left));

/**
 * Score one token set against a query token: full weight for a stemmed
 * exact match, half weight for a prefix relative (call ~ callers,
 * entropi ~ entropy), else zero.
 */
const tokenScore = (
  tokens: ReadonlySet<string>,
  queryToken: string,
  weight: number,
): number => {
  if (tokens.has(queryToken)) return weight;
  for (const token of tokens)
    if (sharesPrefix(token, queryToken)) return Math.floor(weight / 2);
  return 0;
};

/** Score one entry against query tokens; higher is a better intent match. */
const scoreEntry = (
  entry: AdvertisedToolEntry,
  queryTokens: ReadonlySet<string>,
  rawQuery: string,
): number => {
  let score = 0;
  if (entry.name === rawQuery) score += 100;
  if (entry.name.includes(rawQuery) && rawQuery.length >= 3) score += 25;
  const nameTokens = stemmedTokens(entry.name);
  const familyTokens = stemmedTokens(entry.family ?? "");
  const textTokens = new Set([
    ...stemmedTokens(entry.title ?? ""),
    ...stemmedTokens(entry.description ?? ""),
  ]);
  for (const token of queryTokens) {
    const queryToken = stem(token);
    score += tokenScore(nameTokens, queryToken, 10);
    score += tokenScore(familyTokens, queryToken, 5);
    score += tokenScore(textTokens, queryToken, 3);
  }
  return score;
};

/** A search match returned by `search_tools`. */
export interface ToolSearchMatch extends AdvertisedToolEntry {
  readonly advertised: boolean;
}

/** Outcome of a load request: the advertised schema entry, or a refusal. */
export type ToolLoadOutcome =
  | {
      readonly ok: true;
      readonly name: string;
      readonly title?: string;
      readonly description?: string;
      readonly inputSchema: Record<string, unknown>;
      readonly outputSchema?: Record<string, unknown>;
    }
  | {
      readonly ok: false;
      readonly reason: string;
      readonly suggestions: readonly string[];
    };

/**
 * Per-server lazy-surface state: which tools the connect-time advertisement
 * includes and which have been loaded since. In `full` mode every tool is
 * advertised and the discovery tools are not registered; in `lazy` mode the
 * core group, the discovery tools, and the spillover reader are advertised
 * at connect and each load advertises one more tool for the connection.
 */
export class McpToolSurface {
  private readonly loaded = new Set<string>();

  constructor(
    readonly mode: McpToolSurfaceMode,
    private readonly host: ToolSurfaceHost,
  ) {}

  /** Whether this tool is in the connect-time advertisement. */
  isInitiallyAdvertised(name: string): boolean {
    if (this.mode === "full") return true;
    return (
      MCP_CORE_TOOL_NAMES.has(name) ||
      MCP_DISCOVERY_TOOL_NAMES.has(name) ||
      name === READ_TOOL_RESULT_PAGE_TOOL_NAME ||
      this.loaded.has(name)
    );
  }

  /** Whether discovery machinery should be registered for this surface. */
  get discoveryEnabled(): boolean {
    return this.mode === "lazy";
  }

  /** Search the whole registered catalog by intent, best matches first. */
  search(query: string, limit: number): readonly ToolSearchMatch[] {
    const queryTokens = new Set(tokenize(query));
    const rawQuery = query.trim().toLowerCase();
    return this.host
      .entries()
      .map((entry) => ({
        entry,
        score: scoreEntry(entry, queryTokens, rawQuery),
      }))
      .filter(({ score }) => score > 0)
      .sort(
        (left, right) =>
          right.score - left.score ||
          left.entry.name.localeCompare(right.entry.name),
      )
      .slice(0, Math.max(1, limit))
      .map(({ entry }) => ({
        ...entry,
        advertised:
          this.isInitiallyAdvertised(entry.name) &&
          this.host.advertises(entry.name),
      }));
  }

  /** Advertise one tool and return its advertised schemas. */
  load(name: string): ToolLoadOutcome {
    const entry = this.host.entries().find((item) => item.name === name);
    if (entry === undefined || !this.host.advertises(name)) {
      const suggestions = this.search(name, 3).map((match) => match.name);
      return {
        ok: false,
        reason: `No tool named "${name}" is registered on this server.`,
        suggestions,
      };
    }
    const schemas = this.host.schemas(name);
    if (schemas === undefined || !this.host.enable(name)) {
      const suggestions = this.search(name, 3).map((match) => match.name);
      return {
        ok: false,
        reason: `Tool "${name}" is registered without an advertised schema on this server.`,
        suggestions,
      };
    }
    this.loaded.add(name);
    return {
      ok: true,
      name: entry.name,
      ...(entry.title === undefined ? {} : { title: entry.title }),
      ...(entry.description === undefined
        ? {}
        : { description: entry.description }),
      inputSchema: schemas.inputSchema,
      ...(schemas.outputSchema === undefined
        ? {}
        : { outputSchema: schemas.outputSchema }),
    };
  }

  /**
   * Revoke a tool this surface loaded: withdraw its advertisement so later
   * calls fail at execution instead of running. The connect-time machinery
   * (core group, discovery tools, spillover reader) is not revocable through
   * this path. Returns false when the tool was not loaded here.
   */
  unload(name: string): boolean {
    if (
      MCP_CORE_TOOL_NAMES.has(name) ||
      MCP_DISCOVERY_TOOL_NAMES.has(name) ||
      name === READ_TOOL_RESULT_PAGE_TOOL_NAME ||
      !this.loaded.has(name)
    )
      return false;
    if (!this.host.disable(name)) return false;
    this.loaded.delete(name);
    return true;
  }

  /** Catalog size and advertised count, for coverage reporting. */
  coverage(): { readonly registered: number; readonly advertised: number } {
    const entries = this.host.entries();
    return {
      registered: entries.length,
      advertised: entries.filter(
        (entry) =>
          this.isInitiallyAdvertised(entry.name) &&
          this.host.advertises(entry.name),
      ).length,
    };
  }
}

const searchToolsInputSchema = z.object({
  query: z
    .string()
    .min(1)
    .describe(
      "Intent or name fragment to find tools by, for example \"decompile a function\" or \"wasm\".",
    ),
  limit: z
    .number()
    .int()
    .min(1)
    .max(25)
    .optional()
    .describe("Maximum matches to return; defaults to 10."),
});

const searchToolsOutputSchema = z.object({
  matches: z.array(
    z.object({
      name: z.string(),
      title: z.string().optional(),
      description: z.string().optional(),
      family: z.string().optional(),
      advertised: z.boolean(),
    }),
  ),
  registered_tools: z.number().int().min(0),
  advertised_tools: z.number().int().min(0),
});

const loadToolSchemaInputSchema = z.object({
  name: z
    .string()
    .min(1)
    .describe("Exact tool name, as returned by search_tools."),
});

const loadToolSchemaOutputSchema = z.object({
  name: z.string(),
  title: z.string().optional(),
  description: z.string().optional(),
  inputSchema: z.record(z.string(), z.unknown()),
  outputSchema: z.record(z.string(), z.unknown()).optional(),
  advertised: z.literal(true),
});

const textResult = (value: Record<string, JsonValue>): CallToolResult => ({
  content: [{ type: "text", text: JSON.stringify(value) }],
  structuredContent: value,
});

const errorResult = (text: string): CallToolResult => ({
  content: [{ type: "text", text }],
  isError: true,
});

/** Register `search_tools` and `load_tool_schema` through the binder seam. */
export const registerDiscoveryTools = (
  bind: SurfaceToolBinder,
  surface: McpToolSurface,
): void => {
  bind(
    SEARCH_TOOLS_TOOL_NAME,
    {
      title: "Search tools by intent",
      description:
        "Find registered tools by intent or name fragment. This server advertises only its core tools at connect; every other tool is registered and discoverable here. Search first, then call load_tool_schema with the exact name to advertise a tool and read its full schema before calling it.",
      inputSchema: searchToolsInputSchema,
      outputSchema: searchToolsOutputSchema,
    },
    (input) => {
      const query = typeof input.query === "string" ? input.query : "";
      const limit = typeof input.limit === "number" ? input.limit : 10;
      const coverage = surface.coverage();
      const matches = surface.search(query, limit).map((match) => ({
        name: match.name,
        ...(match.title === undefined ? {} : { title: match.title }),
        ...(match.description === undefined
          ? {}
          : { description: match.description.slice(0, 240) }),
        ...(match.family === undefined ? {} : { family: match.family }),
        advertised: match.advertised,
      }));
      return textResult({
        matches: matches as unknown as JsonValue,
        registered_tools: coverage.registered,
        advertised_tools: coverage.advertised,
      });
    },
  );
  bind(
    LOAD_TOOL_SCHEMA_TOOL_NAME,
    {
      title: "Load a tool's schema",
      description:
        "Advertise one registered tool on this connection and return its full advertised input and output schemas, exactly as tools/list presents them once loaded. Call this after search_tools, then call the tool by name.",
      inputSchema: loadToolSchemaInputSchema,
      outputSchema: loadToolSchemaOutputSchema,
    },
    (input) => {
      const name = typeof input.name === "string" ? input.name : "";
      const outcome = surface.load(name);
      if (!outcome.ok)
        return errorResult(
          outcome.suggestions.length === 0
            ? outcome.reason
            : `${outcome.reason} Closest matches: ${outcome.suggestions.join(", ")}. Call search_tools to find the intended tool.`,
        );
      return textResult({
        name: outcome.name,
        ...(outcome.title === undefined ? {} : { title: outcome.title }),
        ...(outcome.description === undefined
          ? {}
          : { description: outcome.description }),
        inputSchema: outcome.inputSchema as JsonValue,
        ...(outcome.outputSchema === undefined
          ? {}
          : { outputSchema: outcome.outputSchema as JsonValue }),
        advertised: true,
      });
    },
  );
};
