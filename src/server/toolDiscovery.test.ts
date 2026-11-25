import { describe, expect, it } from "vitest";

import {
  LOAD_TOOL_SCHEMA_TOOL_NAME,
  McpToolSurface,
  SEARCH_TOOLS_TOOL_NAME,
  type AdvertisedToolEntry,
  type ToolSurfaceHost,
} from "./toolDiscovery.js";
import { READ_TOOL_RESULT_PAGE_TOOL_NAME } from "./toolResultSpillover.js";

const entries: readonly AdvertisedToolEntry[] = [
  {
    name: "binary_session",
    title: "Binary session",
    description: "Inspect the current binary session.",
    family: "session",
  },
  {
    name: "search_tools",
    title: "Search tools by intent",
    description: "Find registered tools by intent.",
  },
  {
    name: "load_tool_schema",
    title: "Load a tool's schema",
    description: "Advertise one registered tool.",
  },
  {
    name: "read_tool_result_page",
    title: "Read a spilled tool result page",
    description: "Page back an oversized result.",
  },
  {
    name: "list_strings",
    title: "List strings",
    description: "List the strings found in the current target.",
    family: "native",
  },
  {
    name: "inspect_wasm_artifact",
    title: "Inspect WASM artifact",
    description: "Inspect a WebAssembly artifact's exports and imports.",
    family: "wasm",
  },
  {
    name: "decompile_function",
    title: "Decompile function",
    description: "Decompile one function to pseudo-code.",
    family: "native",
  },
];

const host = (
  overrides: Partial<ToolSurfaceHost> = {},
): { host: ToolSurfaceHost; enabled: string[] } => {
  const enabled: string[] = [];
  return {
    enabled,
    host: {
      entries: () => entries,
      schemas: (name) =>
        entries.some((entry) => entry.name === name)
          ? {
              inputSchema: {
                type: "object",
                properties: { needle: { type: "string" } },
              },
              outputSchema: { type: "object" },
            }
          : undefined,
      advertises: () => true,
      enable: (name) => {
        if (!entries.some((entry) => entry.name === name)) return false;
        enabled.push(name);
        return true;
      },
      disable: (name) => {
        const index = enabled.indexOf(name);
        if (index < 0) return false;
        enabled.splice(index, 1);
        return true;
      },
      ...overrides,
    },
  };
};

describe("McpToolSurface advertisement", () => {
  it("advertises every tool in full mode", () => {
    const { host: stub } = host();
    const surface = new McpToolSurface("full", stub);
    for (const entry of entries)
      expect(surface.isInitiallyAdvertised(entry.name)).toBe(true);
    expect(surface.discoveryEnabled).toBe(false);
  });

  it("advertises only core, discovery, and the spillover reader in lazy mode", () => {
    const { host: stub } = host();
    const surface = new McpToolSurface("lazy", stub);
    expect(surface.isInitiallyAdvertised("binary_session")).toBe(true);
    expect(surface.isInitiallyAdvertised(SEARCH_TOOLS_TOOL_NAME)).toBe(true);
    expect(surface.isInitiallyAdvertised(LOAD_TOOL_SCHEMA_TOOL_NAME)).toBe(
      true,
    );
    expect(surface.isInitiallyAdvertised(READ_TOOL_RESULT_PAGE_TOOL_NAME)).toBe(
      true,
    );
    expect(surface.isInitiallyAdvertised("list_strings")).toBe(false);
    expect(surface.isInitiallyAdvertised("inspect_wasm_artifact")).toBe(false);
    expect(surface.discoveryEnabled).toBe(true);
    expect(surface.coverage()).toEqual({ registered: 7, advertised: 4 });
  });
});

describe("McpToolSurface search", () => {
  it("ranks exact and name-token matches above description matches", () => {
    const { host: stub } = host();
    const surface = new McpToolSurface("lazy", stub);
    const [first] = surface.search("list_strings", 10);
    expect(first?.name).toBe("list_strings");
    const byIntent = surface.search("strings in the target", 10);
    expect(byIntent.map((match) => match.name)).toContain("list_strings");
    const byFamily = surface.search("wasm", 10);
    expect(byFamily[0]?.name).toBe("inspect_wasm_artifact");
  });

  it("respects the limit and reports advertisement state", () => {
    const { host: stub } = host();
    const surface = new McpToolSurface("lazy", stub);
    const matches = surface.search("tool", 2);
    expect(matches).toHaveLength(2);
    const wasm = surface.search("wasm", 10)[0];
    expect(wasm?.advertised).toBe(false);
    const core = surface.search("binary session", 10)[0];
    expect(core?.advertised).toBe(true);
  });

  it("returns no matches for an unrelated intent", () => {
    const { host: stub } = host();
    const surface = new McpToolSurface("lazy", stub);
    expect(surface.search("astrophysics", 10)).toEqual([]);
  });
});

describe("McpToolSurface load", () => {
  it("enables the tool, returns its schemas, and advertises it afterwards", () => {
    const { host: stub, enabled } = host();
    const surface = new McpToolSurface("lazy", stub);
    const outcome = surface.load("inspect_wasm_artifact");
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error("expected a successful load");
    expect(outcome.inputSchema).toMatchObject({ type: "object" });
    expect(outcome.outputSchema).toMatchObject({ type: "object" });
    expect(enabled).toEqual(["inspect_wasm_artifact"]);
    expect(surface.isInitiallyAdvertised("inspect_wasm_artifact")).toBe(true);
    const match = surface.search("wasm", 10)[0];
    expect(match?.advertised).toBe(true);
  });

  it("refuses an unknown tool with closest-match suggestions", () => {
    const { host: stub } = host();
    const surface = new McpToolSurface("lazy", stub);
    const outcome = surface.load("inspect_wasm_artifacts");
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("expected a refused load");
    expect(outcome.reason).toContain("inspect_wasm_artifacts");
    expect(outcome.suggestions).toContain("inspect_wasm_artifact");
  });

  it("refuses a tool the process does not advertise by family", () => {
    const { host: stub } = host({ advertises: () => false });
    const surface = new McpToolSurface("lazy", stub);
    expect(surface.load("list_strings").ok).toBe(false);
  });
});
