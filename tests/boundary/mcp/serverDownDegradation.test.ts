import {
  Client,
  InMemoryTransport,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { createServer as createNetServer } from "node:net";
import { resolve } from "node:path";
import { describe, expect, it, onTestFinished } from "vitest";

import { SERVER_START_FAILED } from "../../../src/main/messages.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { startMcpHttpProcess } from "../../support/mcp/streamableHttpProcess.js";
import {
  processTest,
  waitForExit,
} from "../../support/process/processFixture.js";

const HTTP_BOUNDARY_TIMEOUT_MS = 90_000;

/** Settle a promise within a deadline; a missed deadline fails the test. */
const settleWithin = async <T>(
  promise: Promise<T>,
  ms: number,
  label: string,
): Promise<T> => {
  let deadline: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        deadline = setTimeout(
          () => reject(new Error(`${label} did not settle within ${ms} ms`)),
          ms,
        );
      }),
    ]);
  } finally {
    if (deadline !== undefined) clearTimeout(deadline);
  }
};

/** The rejection a caller observes, bounded by the same no-hang deadline. */
const rejectionOf = async (
  promise: Promise<unknown>,
  ms: number,
  label: string,
): Promise<unknown> => {
  const outcome = await settleWithin(
    promise.then(
      () => ({ kind: "fulfilled" as const }),
      (cause: unknown) => ({ kind: "rejected" as const, cause }),
    ),
    ms,
    label,
  );
  if (outcome.kind === "fulfilled")
    throw new Error(`${label} unexpectedly succeeded`);
  return outcome.cause;
};

/** A loopback port that was listening a moment ago and now refuses. */
const reserveClosedPort = async (): Promise<number> => {
  const listener = createNetServer();
  await new Promise<void>((resolveListen) =>
    listener.listen(0, "127.0.0.1", resolveListen),
  );
  const address = listener.address();
  if (address === null || typeof address === "string")
    throw new Error("Reserved listener has no port");
  const { port } = address;
  await new Promise<void>((resolveClose) =>
    listener.close(() => resolveClose()),
  );
  return port;
};

it("rejects the client handshake when the server process exits during startup", async () => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve("scripts/rea.mjs"), "mcp"],
    cwd: process.cwd(),
    env: {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? "",
      REA_LOG_LEVEL: "silent",
      // An unparseable surface selection fails composition before the
      // server can answer initialize: the process exits during startup.
      REA_MCP_TOOL_SURFACE: "bogus-surface",
    },
    stderr: "pipe",
  });
  let stderr = "";
  transport.stderr?.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });
  const client = new Client(
    { name: "server-down-startup", version: "1" },
    { versionNegotiation: { mode: "legacy" } },
  );
  onTestFinished(async () => {
    await client.close().catch(() => undefined);
    await transport.close().catch(() => undefined);
  });
  const cause = await rejectionOf(
    client.connect(transport),
    15_000,
    "startup handshake with a dying server",
  );
  expect(cause).toBeInstanceOf(Error);
  // The operator-facing shape is the startup failure line on stderr,
  // delivered before the process exited.
  const deadline = Date.now() + 5_000;
  while (!stderr.includes(SERVER_START_FAILED) && Date.now() < deadline)
    await new Promise((resolveWait) => setTimeout(resolveWait, 25));
  expect(stderr).toContain(SERVER_START_FAILED);
});

it("rejects the client handshake when no server listens on the HTTP endpoint", async () => {
  const port = await reserveClosedPort();
  const transport = new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${String(port)}/mcp`),
  );
  const client = new Client(
    { name: "server-down-refused", version: "1" },
    { versionNegotiation: { mode: "legacy" } },
  );
  onTestFinished(async () => {
    await client.close().catch(() => undefined);
    await transport.close().catch(() => undefined);
  });
  const cause = await rejectionOf(
    client.connect(transport),
    15_000,
    "HTTP handshake with no listener",
  );
  expect(cause).toBeInstanceOf(Error);
});

it("fails later calls promptly after the server connection dies between requests", async () => {
  const session = createTestBinarySession(() => {
    throw new Error("Discovery must not start a deep provider");
  });
  const server = createServer(
    { kind: "session", session },
    { environment: { REA_MCP_TOOL_SURFACE: "lazy" } },
  );
  const client = new Client({ name: "server-down-between", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  onTestFinished(async () => {
    await client.close().catch(() => undefined);
    await server.close().catch(() => undefined);
    await session.close();
  });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  // Baseline: discovery answers while the server is up.
  expect((await client.listTools()).tools.length).toBeGreaterThan(0);
  const search = await client.callTool({
    name: "search_tools",
    arguments: { query: "record an unknown question", limit: 5 },
  });
  expect(search.isError).not.toBe(true);

  // Abrupt death: the transport closes with no shutdown handshake, the
  // same client-visible shape as the server process exiting.
  await serverTransport.close();
  const callCause = await rejectionOf(
    client.callTool({ name: "binary_session", arguments: {} }),
    10_000,
    "tool call after server death",
  );
  expect(callCause).toBeInstanceOf(Error);
  const loadCause = await rejectionOf(
    client.callTool({
      name: "load_tool_schema",
      arguments: { name: "record_unknown" },
    }),
    10_000,
    "schema load after server death",
  );
  expect(loadCause).toBeInstanceOf(Error);
  const listCause = await rejectionOf(
    client.listTools(),
    10_000,
    "tools/list after server death",
  );
  expect(listCause).toBeInstanceOf(Error);
});

describe("rea mcp server-down degradation", () => {
  processTest(
    "fails later calls promptly after the HTTP server process is killed mid-session",
    async ({ processes }) => {
      const started = await startMcpHttpProcess(processes);
      const transport = new StreamableHTTPClientTransport(started.url);
      const client = new Client(
        { name: "server-down-http-kill", version: "1" },
        { versionNegotiation: { mode: "legacy" } },
      );
      onTestFinished(async () => {
        await client.close().catch(() => undefined);
      });
      await client.connect(transport);
      expect(transport.sessionId).toEqual(expect.any(String));
      // Baseline: a loaded call answers while the server is up.
      const before = await client.callTool({
        name: "binary_session",
        arguments: {},
      });
      expect(before.isError).not.toBe(true);

      started.child.kill("SIGKILL");
      expect(await waitForExit(started.child, 10_000)).toBe(true);

      const cause = await rejectionOf(
        client.callTool({ name: "binary_session", arguments: {} }),
        15_000,
        "tool call after the HTTP server was killed",
      );
      expect(cause).toBeInstanceOf(Error);
      await settleWithin(
        client.close(),
        10_000,
        "client close after server death",
      );
    },
    HTTP_BOUNDARY_TIMEOUT_MS,
  );
});
