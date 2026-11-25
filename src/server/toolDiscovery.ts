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
 * Query words that carry no intent signal in this catalog. They are
 * dropped from the query side only; index text keeps every token. A
 * query made only of these words matches nothing rather than ranking
 * the whole catalog by prose overlap.
 */
const QUERY_STOPWORDS: ReadonlySet<string> = new Set([
  "a",
  "about",
  "am",
  "an",
  "and",
  "any",
  "are",
  "as",
  "at",
  "be",
  "been",
  "between",
  "by",
  "can",
  "could",
  "did",
  "do",
  "does",
  "done",
  "for",
  "from",
  "he",
  "her",
  "his",
  "how",
  "i",
  "if",
  "in",
  "into",
  "is",
  "it",
  "its",
  "me",
  "my",
  "no",
  "not",
  "of",
  "on",
  "or",
  "our",
  "over",
  "per",
  "shall",
  "she",
  "should",
  "so",
  "such",
  "than",
  "that",
  "the",
  "their",
  "them",
  "then",
  "these",
  "they",
  "this",
  "those",
  "to",
  "under",
  "via",
  "was",
  "we",
  "were",
  "what",
  "when",
  "where",
  "which",
  "who",
  "whom",
  "whose",
  "why",
  "will",
  "with",
  "would",
  "you",
  "your",
]);

/**
 * Curated query-side equivalences between the words analysts type and
 * the vocabulary tool names are built from. Keys are raw (unstemmed)
 * query tokens; values are extra index tokens scored alongside the
 * query token's own stem at a discount. The map stays deliberately
 * small and domain-shaped: verbs of display and mutation, the guidance
 * corpus's own synonyms, and format words users substitute for the
 * catalog's terms.
 */
const QUERY_SYNONYMS: ReadonlyMap<string, readonly string[]> = new Map([
  ["change", ["update"]],
  ["config", ["setting"]],
  ["configuration", ["setting"]],
  ["cross", ["xref"]],
  ["decode", ["demangle"]],
  ["doc", ["guidance"]],
  ["docs", ["guidance"]],
  ["documentation", ["guidance"]],
  ["enumerate", ["list"]],
  ["executable", ["binary"]],
  ["file", ["binary"]],
  ["function", ["procedure"]],
  ["functions", ["procedure"]],
  ["guide", ["guidance"]],
  ["mangle", ["demangle"]],
  ["mangled", ["demangle"]],
  ["modify", ["update"]],
  ["open", ["read"]],
  ["packed", ["entropy"]],
  ["page", ["section"]],
  ["reference", ["xref"]],
  ["references", ["xref"]],
  ["show", ["list"]],
]);

/** Weight kept by a match that arrives through a synonym expansion. */
const SYNONYM_DISCOUNT = 0.75;

/**
 * Whether two tokens are within one Damerau edit: a single insertion,
 * deletion, substitution, or adjacent transposition. Catches the
 * misspellings analysts actually type (serach, guidence, architecure)
 * without the false positives a wider radius admits.
 */
const withinOneEdit = (left: string, right: string): boolean => {
  const lengthDelta = left.length - right.length;
  if (lengthDelta < -1 || lengthDelta > 1) return false;
  if (lengthDelta === 0) {
    let first = -1;
    let second = -1;
    for (let index = 0; index < left.length; index += 1) {
      if (left[index] === right[index]) continue;
      if (first === -1) first = index;
      else if (second === -1) second = index;
      else return false;
    }
    if (second === -1) return true;
    return (
      second === first + 1 &&
      left[first] === right[second] &&
      left[second] === right[first]
    );
  }
  const [shorter, longer] = lengthDelta < 0 ? [left, right] : [right, left];
  let shortIndex = 0;
  let longIndex = 0;
  let skipped = false;
  while (shortIndex < shorter.length) {
    if (shorter[shortIndex] === longer[longIndex]) {
      shortIndex += 1;
      longIndex += 1;
    } else {
      if (skipped) return false;
      skipped = true;
      longIndex += 1;
    }
  }
  return true;
};

/** A token match against one field: quality 1 exact, 0.7 fuzzy, 0.5 prefix. */
interface TokenMatch {
  readonly quality: number;
  readonly token: string;
}

/**
 * Best match of one index token in a field's token set. Fuzzy matching
 * (one edit) applies only where the caller allows it: names and
 * families are small curated vocabularies where a misspelling has one
 * plausible target; prose is not.
 */
const bestMatch = (
  tokens: ReadonlySet<string>,
  token: string,
  fuzzy: boolean,
): TokenMatch | undefined => {
  if (tokens.has(token)) return { quality: 1, token };
  let best: TokenMatch | undefined;
  for (const candidate of tokens) {
    if (sharesPrefix(candidate, token)) {
      if (best === undefined || best.quality < 0.5)
        best = { quality: 0.5, token: candidate };
    } else if (
      fuzzy &&
      token.length >= 5 &&
      candidate.length >= 5 &&
      withinOneEdit(candidate, token)
    ) {
      if (best === undefined || best.quality < 0.7)
        best = { quality: 0.7, token: candidate };
    }
  }
  return best;
};

/** One catalog entry with its indexed token sets, built per search. */
interface IndexedEntry {
  readonly entry: AdvertisedToolEntry;
  readonly nameTokens: ReadonlySet<string>;
  readonly familyTokens: ReadonlySet<string>;
  readonly textTokens: ReadonlySet<string>;
}

const indexEntry = (entry: AdvertisedToolEntry): IndexedEntry => ({
  entry,
  nameTokens: stemmedTokens(entry.name),
  familyTokens: stemmedTokens(entry.family ?? ""),
  textTokens: new Set([
    ...stemmedTokens(entry.title ?? ""),
    ...stemmedTokens(entry.description ?? ""),
  ]),
});

/**
 * Rarity weight for a matched token: how much of the catalog mentions
 * it. A token in every description (binary, analysis) carries little
 * intent signal; a token in a handful (guidance, entropy) carries the
 * query. The factor keeps a floor so common-token matches still count.
 */
const rarityFactor = (
  token: string,
  documentFrequency: ReadonlyMap<string, number>,
  entryCount: number,
): number => {
  const frequency = documentFrequency.get(token) ?? 0;
  const idf = Math.log(1 + entryCount / (frequency + 1));
  const idfMax = Math.log(1 + entryCount);
  return 0.35 + 0.65 * (idf / idfMax);
};

/** Catalog-wide token statistics one search scores against. */
interface IndexStatistics {
  readonly documentFrequency: ReadonlyMap<string, number>;
  readonly entryCount: number;
}

/** Score one entry against expanded query tokens; higher is better. */
const scoreEntry = (
  indexed: IndexedEntry,
  queryTokens: readonly string[],
  rawQuery: string,
  statistics: IndexStatistics,
): number => {
  const { documentFrequency, entryCount } = statistics;
  const { entry, nameTokens, familyTokens, textTokens } = indexed;
  let score = 0;
  if (entry.name === rawQuery) score += 100;
  if (entry.name.includes(rawQuery) && rawQuery.length >= 3) score += 25;
  let nameQuality = 0;
  for (const rawToken of queryTokens) {
    const expanded: readonly { token: string; synonym: boolean }[] = [
      { token: stem(rawToken), synonym: false },
      ...(QUERY_SYNONYMS.get(rawToken) ?? []).map((token) => ({
        token,
        synonym: true,
      })),
    ];
    const fieldScore = (
      tokens: ReadonlySet<string>,
      weight: number,
      fuzzy: boolean,
      exactOnlySynonyms: boolean,
    ): number => {
      let best = 0;
      for (const { token, synonym } of expanded) {
        const match = bestMatch(tokens, token, fuzzy);
        if (match === undefined) continue;
        if (exactOnlySynonyms && synonym && match.quality !== 1) continue;
        const weighted =
          weight *
          match.quality *
          rarityFactor(match.token, documentFrequency, entryCount) *
          (synonym ? SYNONYM_DISCOUNT : 1);
        if (weighted > best) best = weighted;
      }
      return best;
    };
    // The name match is chosen by quality first (an exact synonym beats
    // a prefix relative of the typed word), then weighted like the rest.
    let bestName: (TokenMatch & { readonly synonym: boolean }) | undefined;
    for (const { token, synonym } of expanded) {
      const match = bestMatch(nameTokens, token, true);
      if (match === undefined) continue;
      if (bestName === undefined || match.quality > bestName.quality)
        bestName = { ...match, synonym };
    }
    if (bestName !== undefined) {
      score +=
        10 *
        bestName.quality *
        rarityFactor(bestName.token, documentFrequency, entryCount) *
        (bestName.synonym ? SYNONYM_DISCOUNT : 1);
      nameQuality += Math.min(bestName.quality, bestName.synonym ? 0.7 : 1);
    }
    score += fieldScore(familyTokens, 5, true, false);
    score += fieldScore(textTokens, 3, false, true);
  }
  // Coverage: a query that accounts for most of a short tool name is a
  // stronger intent signal than the same matches scattered across a
  // long one. Synonym and partial matches count at their quality.
  if (nameTokens.size > 0) score += 8 * (nameQuality / nameTokens.size);
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
    const queryTokens = [
      ...new Set(
        tokenize(query).filter((token) => !QUERY_STOPWORDS.has(token)),
      ),
    ];
    const rawQuery = query.trim().toLowerCase();
    const indexed = this.host.entries().map(indexEntry);
    const documentFrequency = new Map<string, number>();
    for (const { nameTokens, familyTokens, textTokens } of indexed) {
      const union = new Set([...nameTokens, ...familyTokens, ...textTokens]);
      for (const token of union)
        documentFrequency.set(token, (documentFrequency.get(token) ?? 0) + 1);
    }
    return indexed
      .map((indexedEntry) => ({
        entry: indexedEntry.entry,
        score: scoreEntry(indexedEntry, queryTokens, rawQuery, {
          documentFrequency,
          entryCount: indexed.length,
        }),
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
      'Intent or name fragment to find tools by, for example "decompile a function" or "wasm".',
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
