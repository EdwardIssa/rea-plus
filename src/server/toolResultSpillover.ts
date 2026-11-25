import type { CallToolResult } from "@modelcontextprotocol/server";
import { z } from "zod";

import type { JsonValue } from "../domain/jsonValue.js";
import type {
  EvidenceMcpServerCore,
  StandardToolRegistration,
} from "./EvidenceMcpServerCore.js";

/**
 * Registration seam shared by the surface tools: eager composition binds
 * through the server's canonical registerTool, while the deferred server
 * binds the same configs directly before its runtime materializes. Inputs
 * reach handlers already validated by the registered schema.
 */
export type SurfaceToolBinder = (
  name: string,
  config: StandardToolRegistration,
  callback: (
    input: Readonly<Record<string, unknown>>,
  ) => CallToolResult | Promise<CallToolResult>,
) => void;

/** Tool that pages back a retained oversized result. Always core surface. */
export const READ_TOOL_RESULT_PAGE_TOOL_NAME = "read_tool_result_page";

/** Largest complete result text retained for paging, in UTF-16 code units. */
export const MAX_SPILLOVER_CODE_UNITS = 64 * 1024 * 1024;

/** Retained records per connection; the oldest record is evicted first. */
const MAX_SPILLOVER_RECORDS = 16;

/** One retained oversized result, paged back verbatim by its id. */
export interface ToolResultSpilloverRecord {
  readonly id: string;
  readonly tool: string;
  readonly text: string;
}

/** One verbatim page of a retained result. */
export interface ToolResultSpilloverPage {
  readonly id: string;
  readonly tool: string;
  readonly offset: number;
  readonly nextOffset: number | undefined;
  readonly totalCodeUnits: number;
  readonly text: string;
}

/**
 * Bounded in-memory retention for oversized tool results. A result that
 * exceeds the response budget is delivered as a schema-shaped projection;
 * its complete canonical text is retained here under an id the caller pages
 * back with `read_tool_result_page`. Records live for the connection's
 * lifetime only; nothing is written to disk or into Evidence.
 */
export class ToolResultSpilloverStore {
  private readonly records = new Map<string, ToolResultSpilloverRecord>();
  private sequence = 0;

  /** Retain one complete result text and return its spillover id. */
  put(tool: string, text: string): string {
    this.sequence += 1;
    const id = `spillover-${this.sequence}`;
    this.records.set(id, { id, tool, text });
    while (this.records.size > MAX_SPILLOVER_RECORDS) {
      const oldest = this.records.keys().next().value;
      if (oldest === undefined) break;
      this.records.delete(oldest);
    }
    return id;
  }

  /** Read one page of a retained result; unknown ids return undefined. */
  page(
    id: string,
    offset: number,
    limit: number,
  ): ToolResultSpilloverPage | undefined {
    const record = this.records.get(id);
    if (record === undefined) return undefined;
    const start = Math.min(Math.max(0, offset), record.text.length);
    const end = Math.min(record.text.length, start + Math.max(1, limit));
    return {
      id: record.id,
      tool: record.tool,
      offset: start,
      nextOffset: end < record.text.length ? end : undefined,
      totalCodeUnits: record.text.length,
      text: record.text.slice(start, end),
    };
  }

  /** Whether a spillover id is still retained. */
  has(id: string): boolean {
    return this.records.has(id);
  }
}

/** Strings shorter than this are never shortened by the projection. */
const MIN_SHORTENABLE_STRING = 256;
/** A shortened string keeps at least this many leading code units. */
const MIN_STRING_PREFIX = 64;

/** Shrink one node toward the given fraction, preserving its JSON type. */
const shrinkNode = (node: JsonValue, fraction: number): JsonValue => {
  if (typeof node === "string") {
    if (node.length <= MIN_SHORTENABLE_STRING) return node;
    const keep = Math.max(
      MIN_STRING_PREFIX,
      Math.floor(node.length * fraction),
    );
    return keep >= node.length ? node : node.slice(0, keep);
  }
  if (Array.isArray(node)) {
    const keep = Math.floor(node.length * fraction);
    return node.slice(0, keep).map((item) => shrinkNode(item, fraction));
  }
  if (typeof node === "object" && node !== null) {
    const projected: Record<string, JsonValue> = {};
    for (const [key, value] of Object.entries(node))
      projected[key] = shrinkNode(value, fraction);
    return projected;
  }
  return node;
};

/**
 * Project a result value down to a serialized-size target without changing
 * its schema shape: object keys are all kept, array items are a prefix of
 * the original items, strings keep a prefix, and numbers, booleans, and
 * null pass through untouched. Returns undefined when even the maximally
 * shrunk projection exceeds the target (for example an object with more
 * keys than the budget can name), so the caller keeps its refusal path.
 */
export const projectValueToSerializedBytes = (
  value: JsonValue,
  targetBytes: number,
): JsonValue | undefined => {
  const fits = (candidate: JsonValue): boolean =>
    Buffer.byteLength(JSON.stringify(candidate)) <= targetBytes;
  if (fits(value)) return value;
  let low = 0;
  let high = 1;
  let best: JsonValue | undefined;
  for (let iteration = 0; iteration < 24; iteration += 1) {
    const fraction = (low + high) / 2;
    const candidate = shrinkNode(value, fraction);
    if (fits(candidate)) {
      best = candidate;
      low = fraction;
    } else {
      high = fraction;
    }
    if (high - low < 1e-4) break;
  }
  if (best !== undefined) return best;
  const floor = shrinkNode(value, 0);
  return fits(floor) ? floor : undefined;
};

const readToolResultPageInputSchema = z.object({
  spillover_id: z
    .string()
    .min(1)
    .describe("Spillover id from a truncated tool result's _meta.spillover."),
  offset: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe("Code-unit offset to start from; defaults to 0."),
  limit: z
    .number()
    .int()
    .min(1)
    .max(200_000)
    .optional()
    .describe("Maximum code units to return; defaults to 50000."),
});

const readToolResultPageOutputSchema = z.object({
  spillover_id: z.string(),
  tool: z.string(),
  offset: z.number().int().min(0),
  next_offset: z.number().int().min(0).nullable(),
  total_code_units: z.number().int().min(0),
  text: z.string(),
});

/**
 * Register the spillover reader on a server. The store is read from the
 * server's current delivery at call time, so a deferred server whose
 * delivery is attached at materialization still reads the active store.
 */
export const registerSpilloverTool = (
  bind: SurfaceToolBinder,
  server: EvidenceMcpServerCore,
): void => {
  bind(
    READ_TOOL_RESULT_PAGE_TOOL_NAME,
    {
      title: "Read a spilled tool result page",
      description:
        "Page back the complete text of an oversized tool result that was delivered truncated. The truncated result carries _meta.spillover with the spillover_id, the originating tool, and the full size; pages are verbatim slices of the complete canonical result text and concatenate back to it byte for byte. Ids live only for this connection and the most recent results are retained.",
      inputSchema: readToolResultPageInputSchema,
      outputSchema: readToolResultPageOutputSchema,
    },
    (input) => {
      const page = server.delivery.spillover.page(
        typeof input.spillover_id === "string" ? input.spillover_id : "",
        typeof input.offset === "number" ? input.offset : 0,
        typeof input.limit === "number" ? input.limit : 50_000,
      );
      if (page === undefined)
        return {
          content: [
            {
              type: "text",
              text: `Unknown or evicted spillover id "${input.spillover_id}". Spillover ids are issued in a truncated result's _meta.spillover and only the most recent results on this connection are retained; repeat the original tool call if the complete result is still needed.`,
            },
          ],
          isError: true,
        };
      const structured: Record<string, JsonValue> = {
        spillover_id: page.id,
        tool: page.tool,
        offset: page.offset,
        next_offset: page.nextOffset ?? null,
        total_code_units: page.totalCodeUnits,
        text: page.text,
      };
      return {
        content: [{ type: "text", text: JSON.stringify(structured) }],
        structuredContent: structured,
      };
    },
  );
};
