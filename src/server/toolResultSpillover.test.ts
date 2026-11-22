import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { toolContract } from "../contracts/toolContracts.js";
import { ok } from "../domain/result.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { ToolResultDelivery } from "./ToolResultDelivery.js";
import {
  MAX_SPILLOVER_CODE_UNITS,
  projectValueToSerializedBytes,
  READ_TOOL_RESULT_PAGE_TOOL_NAME,
  registerSpilloverTool,
  ToolResultSpilloverStore,
} from "./toolResultSpillover.js";

describe("ToolResultSpilloverStore", () => {
  it("pages a retained result back byte for byte", () => {
    const store = new ToolResultSpilloverStore();
    const text = "abcdefghij".repeat(1000);
    const id = store.put("fixture_tool", text);
    let reconstructed = "";
    let offset = 0;
    for (;;) {
      const page = store.page(id, offset, 333);
      if (page === undefined) throw new Error("missing spillover page");
      reconstructed += page.text;
      if (page.nextOffset === undefined) break;
      offset = page.nextOffset;
    }
    expect(reconstructed).toBe(text);
    const first = store.page(id, 0, 10);
    expect(first).toMatchObject({
      id,
      tool: "fixture_tool",
      offset: 0,
      totalCodeUnits: text.length,
    });
  });

  it("returns undefined for unknown and evicted ids", () => {
    const store = new ToolResultSpilloverStore();
    expect(store.page("spillover-99", 0, 10)).toBeUndefined();
    const ids = Array.from({ length: 20 }, (_, index) =>
      store.put("fixture_tool", `value-${index}`),
    );
    expect(store.page(ids[0] ?? "", 0, 10)).toBeUndefined();
    expect(store.page(ids[19] ?? "", 0, 10)?.text).toBe("value-19");
  });
});

describe("projectValueToSerializedBytes", () => {
  it("returns a fitting value unchanged", () => {
    const value: JsonValue = { title: "small", items: ["a", "b"] };
    expect(projectValueToSerializedBytes(value, 4096)).toEqual(value);
  });

  it("preserves schema shape while shrinking strings and arrays", () => {
    const schema = z.object({
      title: z.string(),
      detail: z.string(),
      entries: z.array(z.object({ name: z.string(), score: z.number() })),
      count: z.number(),
      flag: z.boolean(),
      missing: z.null(),
    });
    const value = {
      title: "report",
      detail: "d".repeat(5000),
      entries: Array.from({ length: 300 }, (_, index) => ({
        name: `entry-${index}`,
        score: index,
      })),
      count: 300,
      flag: true,
      missing: null,
    };
    const projected = projectValueToSerializedBytes(value, 2048);
    if (projected === undefined)
      throw new Error("expected a projection within budget");
    const parsed = schema.parse(projected);
    expect(Buffer.byteLength(JSON.stringify(projected))).toBeLessThanOrEqual(
      2048,
    );
    expect(parsed.title).toBe("report");
    expect(parsed.count).toBe(300);
    expect(parsed.flag).toBe(true);
    expect(parsed.missing).toBeNull();
    expect(parsed.detail.length).toBeLessThan(5000);
    expect(value.detail.startsWith(parsed.detail)).toBe(true);
    expect(parsed.entries.length).toBeLessThan(300);
    expect(parsed.entries).toEqual(value.entries.slice(0, parsed.entries.length));
  });

  it("refuses a value whose keys alone exceed the target", () => {
    const value: JsonValue = Object.fromEntries(
      Array.from({ length: 500 }, (_, index) => [`key-${index}`, "v"]),
    );
    expect(projectValueToSerializedBytes(value, 128)).toBeUndefined();
  });
});

describe("oversized plain result delivery with spillover", () => {
  const contract = toolContract("search_guidance");
  const resultSchema = z.object({
    title: z.string(),
    detail: z.string(),
    entries: z.array(z.string()),
  });
  const bigValue: JsonValue = {
    title: "guidance",
    detail: "d".repeat(6000),
    entries: Array.from({ length: 200 }, (_, index) => `entry-${index}`),
  };

  it("keeps the established refusal for a target-content contract", () => {
    const delivery = new ToolResultDelivery(8192, undefined, undefined, {
      spilloverTruncationEnabled: true,
    });
    const result = delivery.toCallToolResult(
      ok({ text: "x".repeat(8192) }),
      toolContract("procedure_pseudo_code"),
    );
    expect(result.isError).toBe(true);
  });

  it("truncates a plain oversized result and pages the complete text back", async () => {
    expect(contract.returnsTargetContent).toBe(false);
    const delivery = new ToolResultDelivery(8192, undefined, undefined, {
      spilloverTruncationEnabled: true,
    });
    const server = new EvidenceMcpServer(
      { name: "spillover-test", version: "1" },
      { capabilities: {} },
      undefined,
      delivery,
    );
    server.registerTool(
      "fixture_big_result",
      {
        title: "Fixture big result",
        description: "Returns the oversized fixture value through delivery.",
        inputSchema: z.object({}),
      },
      async () => delivery.toCallToolResult(ok(bigValue), contract),
    );
    registerSpilloverTool(
      (name, config, callback) => {
        server.registerTool(name, config as never, callback as never);
      },
      server,
    );
    const client = new Client({ name: "spillover-client", version: "1" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const result = await client.callTool({
        name: "fixture_big_result",
        arguments: {},
      });
      expect(result.isError).not.toBe(true);
      const parsed = resultSchema.parse(result.structuredContent);
      expect(parsed.title).toBe("guidance");
      expect(parsed.detail.length).toBeLessThan(6000);
      expect(
        JSON.stringify(result.structuredContent).length,
      ).toBeLessThanOrEqual(delivery.resultBudgetBytes);
      const meta = result._meta as {
        spillover?: { spillover_id: string; full_code_units: number };
      };
      const spilloverId = meta.spillover?.spillover_id;
      if (spilloverId === undefined)
        throw new Error("missing spillover reference");
      expect(meta.spillover?.full_code_units).toBe(
        JSON.stringify(bigValue).length,
      );
      let reconstructed = "";
      let offset = 0;
      for (;;) {
        const page = await client.callTool({
          name: READ_TOOL_RESULT_PAGE_TOOL_NAME,
          arguments: { spillover_id: spilloverId, offset, limit: 977 },
        });
        expect(page.isError).not.toBe(true);
        const structured = page.structuredContent as {
          text: string;
          next_offset: number | null;
          total_code_units: number;
        };
        reconstructed += structured.text;
        if (structured.next_offset === null) {
          expect(structured.total_code_units).toBe(
            JSON.stringify(bigValue).length,
          );
          break;
        }
        offset = structured.next_offset;
      }
      expect(reconstructed).toBe(JSON.stringify(bigValue));
      const unknown = await client.callTool({
        name: READ_TOOL_RESULT_PAGE_TOOL_NAME,
        arguments: { spillover_id: "spillover-404" },
      });
      expect(unknown.isError).toBe(true);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("keeps the established refusal when spillover truncation is not enabled", () => {
    const delivery = new ToolResultDelivery(8192);
    const result = delivery.toCallToolResult(ok(bigValue), contract);
    expect(result.isError).toBe(true);
    expect(result._meta).toBeUndefined();
    expect(delivery.spillover.page("spillover-1", 0, 10)).toBeUndefined();
  });

  it("retains nothing beyond the spillover size cap", () => {
    expect(MAX_SPILLOVER_CODE_UNITS).toBeGreaterThan(0);
    const delivery = new ToolResultDelivery(8192);
    const huge: JsonValue = {
      title: "guidance",
      detail: "d".repeat(MAX_SPILLOVER_CODE_UNITS + 1),
      entries: [],
    };
    const result = delivery.toCallToolResult(ok(huge), contract);
    expect(result.isError).toBe(true);
  });
});
