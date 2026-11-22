import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { beforeAll, describe, expect, it } from "vitest";

import { parseEvidence } from "../../../src/domain/evidence.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import {
  buildFixtures,
  FIXTURES_ROOT,
} from "../../../scripts/ablation/buildFixtures.mjs";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const binaryOf = (id: string): string => join(FIXTURES_ROOT, "bin", id, id);

beforeAll(() => {
  buildFixtures();
}, 300_000);

const connect = async (
  surface: "lazy" | "full",
): Promise<{ client: Client; close: () => Promise<void> }> => {
  const session = createTestBinarySession(() => {
    throw new Error("Dynamic execution must not start a deep provider");
  });
  const server = createServer(
    { kind: "session", session },
    { environment: { REA_MCP_TOOL_SURFACE: surface } },
  );
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "dynamic-execution-test", version: "0" });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    client,
    close: async () => {
      await client.close();
      await server.close();
      await session.close();
    },
  };
};

const toolText = (result: unknown): string =>
  (result as { content: { type: string; text?: string }[] }).content
    .filter((item) => item.type === "text")
    .map((item) => item.text ?? "")
    .join("\n");

describe("execute_dynamically MCP tool", () => {
  it("is deferred under the lazy surface, then runs a1 end to end after discovery", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-mcp-lazy-");
    const evidencePath = join(temp, "a1.evidence.json");
    const { client, close } = await connect("lazy");
    try {
      const listed = await client.listTools();
      expect(
        listed.tools.some((tool) => tool.name === "execute_dynamically"),
      ).toBe(false);

      const search = await client.callTool({
        name: "search_tools",
        arguments: { query: "execute binary dynamically frida" },
      });
      expect(toolText(search)).toContain("execute_dynamically");

      const loaded = (await client.callTool({
        name: "load_tool_schema",
        arguments: { name: "execute_dynamically" },
      })) as { isError?: boolean };
      expect(loaded.isError).not.toBe(true);

      const result = (await client.callTool({
        name: "execute_dynamically",
        arguments: { target_path: binaryOf("a1"), evidence_path: evidencePath },
      })) as {
        isError?: boolean;
        structuredContent?: {
          status: string;
          counts: { strings: number };
          supervisor: { reason: string };
        };
      };
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent?.status).toBe("complete");
      expect(result.structuredContent?.counts.strings).toBe(1);
      expect(result.structuredContent?.supervisor.reason).toBe("exited");

      const evidence = parseEvidence(
        JSON.parse(await readFile(evidencePath, "utf8")),
      );
      const nr = evidence.normalized_result as { strings: unknown };
      expect(nr.strings).toEqual([
        { value: "alpha-secret-one", channel: "puts" },
      ]);
      // The Evidence subject is the fixture binary itself.
      expect(evidence.subject?.digest.sha256).toBe(
        createHash("sha256")
          .update(readFileSync(binaryOf("a1")))
          .digest("hex"),
      );
    } finally {
      await close();
    }
  }, 180_000);

  it("is advertised at connect under the full surface and honors stimulus argv", async () => {
    const temp = await createTestTempDirectory("rea-dynexec-mcp-full-");
    const evidencePath = join(temp, "c1.evidence.json");
    const { client, close } = await connect("full");
    try {
      const listed = await client.listTools();
      expect(
        listed.tools.some((tool) => tool.name === "execute_dynamically"),
      ).toBe(true);

      const result = (await client.callTool({
        name: "execute_dynamically",
        arguments: {
          target_path: binaryOf("c1"),
          evidence_path: evidencePath,
          argv: ["1"],
        },
      })) as {
        isError?: boolean;
        structuredContent?: { status: string };
      };
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent?.status).toBe("complete");

      const evidence = parseEvidence(
        JSON.parse(await readFile(evidencePath, "utf8")),
      );
      const nr = evidence.normalized_result as {
        output: { stdout: string };
      };
      expect(nr.output.stdout).toContain("result-sub");
      expect(nr.output.stdout).not.toContain("result-add");
    } finally {
      await close();
    }
  }, 180_000);
});
