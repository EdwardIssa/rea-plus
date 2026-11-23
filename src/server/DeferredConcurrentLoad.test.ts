import { awaitAcknowledgement } from "../../tests/fixtures/lifecycleAcknowledgement.js";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import type { Tool } from "@modelcontextprotocol/server";
import { afterEach, expect, it } from "vitest";
import { z } from "zod";
import { SERVER_START_FAILED } from "../main/messages.js";
import type { RecordedMcpCatalog } from "../recordedMcpCatalog.js";
import { DeferredEvidenceMcpServer } from "./DeferredEvidenceMcpServer.js";
import { ToolResultDelivery } from "./ToolResultDelivery.js";

const barrier = () => {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
};

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

const input = z.strictObject({ n: z.number().int().nonnegative().default(3) });
const output = z.strictObject({ n: z.number().int() });

const toolEntry = (name: string): Tool => ({
  name,
  inputSchema: z.toJSONSchema(input, {
    io: "input",
  }) as Tool["inputSchema"],
  outputSchema: z.toJSONSchema(output),
});

const TOOL_NAMES = [
  "list_unknowns",
  "fixture_alpha",
  "fixture_beta",
  "fixture_gamma",
] as const;

const catalog: RecordedMcpCatalog = {
  version: 1,
  info: { name: "deferred-concurrent-fixture", version: "1" },
  instructions: "Fixture",
  capabilities: { tools: { listChanged: true } },
  identity: {
    counts: { cli_commands: 0, mcp_tools: TOOL_NAMES.length, mcp_prompts: 0 },
    digests: {
      tools_sha256: "fixture",
      prompts_sha256: "fixture",
      combined_sha256: "fixture",
    },
  },
  tools: TOOL_NAMES.map(toolEntry),
  evidenceReferenceAlternatives: [],
  prompts: [],
};

interface FixtureOptions {
  readonly holdInitialize?: ReturnType<typeof barrier>;
  readonly failLoad?: boolean;
  readonly holdExecution?: {
    readonly entered: ReturnType<typeof barrier>;
    readonly hold: ReturnType<typeof barrier>;
  };
}

const cleanups: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()?.();
});

const fixture = async (options: FixtureOptions = {}) => {
  const started = barrier();
  const calls: string[] = [];
  let loads = 0;
  let runtimeCleanups = 0;
  const server = new DeferredEvidenceMcpServer(
    catalog,
    new ToolResultDelivery(1024 * 1024),
    async (target) => {
      loads++;
      target.ownRuntimeCleanup(async () => {
        runtimeCleanups++;
        await target.closePartialRuntime();
      });
      started.release();
      await options.holdInitialize?.promise;
      if (options.failLoad) throw new Error("PRIVATE startup cause");
      target.materialize(() => {
        for (const name of TOOL_NAMES)
          target.registerTool(
            name,
            { inputSchema: input, outputSchema: output },
            async (args) => {
              calls.push(name);
              if (options.holdExecution !== undefined && calls.length === 1) {
                options.holdExecution.entered.release();
                await options.holdExecution.hold.promise;
              }
              return { content: [], structuredContent: { n: args.n } };
            },
          );
      });
    },
    { toolSurfaceMode: "lazy" },
  );
  const client = new Client({
    name: "deferred-concurrent-client",
    version: "1",
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  cleanups.push(async () => {
    await client.close().catch(() => undefined);
    await server.close().catch(() => undefined);
  });
  return {
    server,
    client,
    serverTransport,
    started,
    calls,
    loads: () => loads,
    runtimeCleanups: () => runtimeCleanups,
  };
};

const toolNames = async (client: Client): Promise<readonly string[]> =>
  (await client.listTools()).tools.map(({ name }) => name);

it("advertises tools loaded concurrently while the shared runtime load is still pending", async () => {
  const hold = barrier();
  const f = await fixture({ holdInitialize: hold });
  const initial = await toolNames(f.client);
  expect(initial).toContain("list_unknowns");
  expect(initial).toContain("search_tools");
  expect(initial).not.toContain("fixture_alpha");
  expect(initial).not.toContain("fixture_beta");

  // A core tool is advertised at connect, so its call starts the shared
  // runtime load; hidden tools answer only after a load advertises them.
  const pending = f.client.callTool({
    name: "list_unknowns",
    arguments: { n: 5 },
  });
  const settled: Promise<unknown>[] = [pending];
  try {
    await awaitAcknowledgement(
      f.started.promise,
      pending,
      "shared runtime load",
    );
    // Dynamic registration races the pending materialization: duplicate
    // loads of one tool, a load of the very tool being called, and a
    // search, all while the runtime load is held.
    const [betaFirst, betaDuplicate, alphaLoad, search] = await Promise.all([
      f.client.callTool({
        name: "load_tool_schema",
        arguments: { name: "fixture_beta" },
      }),
      f.client.callTool({
        name: "load_tool_schema",
        arguments: { name: "fixture_beta" },
      }),
      f.client.callTool({
        name: "load_tool_schema",
        arguments: { name: "fixture_alpha" },
      }),
      f.client.callTool({
        name: "search_tools",
        arguments: { query: "fixture", limit: 10 },
      }),
    ]);
    settled.push(
      Promise.resolve(betaFirst),
      Promise.resolve(betaDuplicate),
      Promise.resolve(alphaLoad),
      Promise.resolve(search),
    );
    for (const load of [betaFirst, betaDuplicate, alphaLoad]) {
      expect(load.isError).not.toBe(true);
      expect(load.structuredContent).toMatchObject({ advertised: true });
    }
    expect(betaFirst.structuredContent).toMatchObject({
      name: "fixture_beta",
    });
    expect(alphaLoad.structuredContent).toMatchObject({
      name: "fixture_alpha",
    });
    expect(search.isError).not.toBe(true);
    expect(search.structuredContent).toMatchObject({ registered_tools: 7 });
    expect(f.loads()).toBe(1);

    hold.release();
    const called = await pending;
    expect(called.isError).not.toBe(true);
    expect(called.structuredContent).toEqual({ n: 5 });
    expect(f.loads()).toBe(1);

    // The tool loaded during the pending materialization stayed
    // advertised through it and now executes on the shared runtime.
    const alpha = await f.client.callTool({
      name: "fixture_alpha",
      arguments: { n: 7 },
    });
    expect(alpha.isError).not.toBe(true);
    expect(alpha.structuredContent).toEqual({ n: 7 });
    expect(f.calls).toEqual(["list_unknowns", "fixture_alpha"]);
    expect(f.loads()).toBe(1);

    const advertised = await toolNames(f.client);
    expect(advertised).toContain("fixture_alpha");
    expect(advertised).toContain("fixture_beta");
    expect(advertised).not.toContain("fixture_gamma");
  } finally {
    hold.release();
    await Promise.allSettled(settled);
  }
});

it("shares one failed runtime load across concurrent callers and keeps the failure terminal", async () => {
  const f = await fixture({ failLoad: true });
  // A hidden tool is refused as disabled before the runtime is ever
  // consulted: the refusal neither starts nor observes the load.
  const refused = await rejectionOf(
    f.client.callTool({ name: "fixture_alpha", arguments: {} }),
    5_000,
    "unloaded tool call",
  );
  expect(refused).toBeInstanceOf(Error);
  expect((refused as Error).message).toMatch(/disabled/);
  expect(f.loads()).toBe(0);

  const results = await Promise.all([
    f.client.callTool({ name: "list_unknowns", arguments: {} }),
    f.client.callTool({ name: "list_unknowns", arguments: { n: 1 } }),
    f.client.callTool({ name: "list_unknowns", arguments: { n: 2 } }),
  ]);
  for (const result of results) {
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toContain(SERVER_START_FAILED);
    expect(JSON.stringify(result)).not.toContain("PRIVATE");
  }
  expect(f.loads()).toBe(1);
  expect(f.calls).toEqual([]);

  // The failure is terminal for this connection: a later caller gets the
  // same redacted error without the load running again.
  const retry = await f.client.callTool({
    name: "list_unknowns",
    arguments: {},
  });
  expect(retry.isError).toBe(true);
  expect(JSON.stringify(retry)).toContain(SERVER_START_FAILED);
  expect(f.loads()).toBe(1);

  // Discovery is served from the recorded catalog and stays available
  // while the runtime is down; only execution degrades.
  const search = await f.client.callTool({
    name: "search_tools",
    arguments: { query: "fixture", limit: 10 },
  });
  expect(search.isError).not.toBe(true);
  expect(search.structuredContent).toMatchObject({ registered_tools: 7 });
  const load = await f.client.callTool({
    name: "load_tool_schema",
    arguments: { name: "fixture_gamma" },
  });
  expect(load.isError).not.toBe(true);
  const gamma = await f.client.callTool({
    name: "fixture_gamma",
    arguments: {},
  });
  expect(gamma.isError).toBe(true);
  expect(f.loads()).toBe(1);

  await f.server.close();
  expect(f.runtimeCleanups()).toBe(1);
});

it("keeps concurrent connections over one recorded catalog isolated", async () => {
  const a = await fixture();
  const b = await fixture();
  const [loadA, loadB] = await Promise.all([
    a.client.callTool({
      name: "load_tool_schema",
      arguments: { name: "fixture_alpha" },
    }),
    b.client.callTool({
      name: "load_tool_schema",
      arguments: { name: "fixture_beta" },
    }),
  ]);
  expect(loadA.isError).not.toBe(true);
  expect(loadB.isError).not.toBe(true);
  const [callA, callB] = await Promise.all([
    a.client.callTool({ name: "fixture_alpha", arguments: { n: 1 } }),
    b.client.callTool({ name: "fixture_beta", arguments: { n: 2 } }),
  ]);
  expect(callA.structuredContent).toEqual({ n: 1 });
  expect(callB.structuredContent).toEqual({ n: 2 });
  expect(a.loads()).toBe(1);
  expect(b.loads()).toBe(1);
  expect(a.calls).toEqual(["fixture_alpha"]);
  expect(b.calls).toEqual(["fixture_beta"]);
  // Advertisement is per connection: neither side sees the other's load.
  expect(await toolNames(a.client)).not.toContain("fixture_beta");
  expect(await toolNames(b.client)).not.toContain("fixture_alpha");
});

it("rejects an in-flight call when the connection dies during tool execution", async () => {
  const holdExecution = { entered: barrier(), hold: barrier() };
  const f = await fixture({ holdExecution });
  const load = await f.client.callTool({
    name: "load_tool_schema",
    arguments: { name: "fixture_alpha" },
  });
  expect(load.isError).not.toBe(true);
  const pending = f.client.callTool({
    name: "fixture_alpha",
    arguments: { n: 9 },
  });
  try {
    await awaitAcknowledgement(
      holdExecution.entered.promise,
      pending,
      "tool execution entry",
    );
    await f.serverTransport.close();
    const cause = await rejectionOf(
      pending,
      5_000,
      "in-flight call after server death",
    );
    expect(cause).toBeInstanceOf(Error);
  } finally {
    holdExecution.hold.release();
    await Promise.allSettled([pending]);
  }
  // Cleanup ownership survives the transport death: close still settles
  // and runs the runtime cleanup exactly once.
  await settleWithin(f.server.close(), 5_000, "server close after death");
  expect(f.runtimeCleanups()).toBe(1);
  await settleWithin(f.client.close(), 5_000, "client close after death");
});

it("rejects a first call when the connection dies during the runtime load", async () => {
  const hold = barrier();
  const f = await fixture({ holdInitialize: hold });
  const pending = f.client.callTool({
    name: "list_unknowns",
    arguments: {},
  });
  try {
    await awaitAcknowledgement(
      f.started.promise,
      pending,
      "runtime load before death",
    );
    await f.serverTransport.close();
    const cause = await rejectionOf(
      pending,
      5_000,
      "first call after server death during load",
    );
    expect(cause).toBeInstanceOf(Error);
  } finally {
    hold.release();
    await Promise.allSettled([pending]);
  }
  await settleWithin(f.server.close(), 5_000, "server close after death");
  expect(f.loads()).toBe(1);
  expect(f.runtimeCleanups()).toBe(1);
  // The dead connection's call never reaches the tool handler, even
  // though the load it started completes during close.
  expect(f.calls).not.toContain("list_unknowns");
  await settleWithin(f.client.close(), 5_000, "client close after death");
});

it("times out a slow call at the client deadline and stays healthy for the next call", async () => {
  const holdExecution = { entered: barrier(), hold: barrier() };
  const f = await fixture({ holdExecution });
  const load = await f.client.callTool({
    name: "load_tool_schema",
    arguments: { name: "fixture_alpha" },
  });
  expect(load.isError).not.toBe(true);
  const timedOut = f.client.callTool(
    { name: "fixture_alpha", arguments: { n: 1 } },
    { timeout: 250 },
  );
  try {
    await awaitAcknowledgement(
      holdExecution.entered.promise,
      timedOut,
      "slow tool execution entry",
    );
    const cause = await rejectionOf(timedOut, 5_000, "client request timeout");
    expect(cause).toBeInstanceOf(Error);
    expect((cause as Error).message).toMatch(/timed out/i);
  } finally {
    holdExecution.hold.release();
    await Promise.allSettled([timedOut]);
  }
  // The late completion corrupts nothing: the next call runs the handler
  // once more and answers normally on the same shared runtime.
  const next = await f.client.callTool({
    name: "fixture_alpha",
    arguments: { n: 2 },
  });
  expect(next.isError).not.toBe(true);
  expect(next.structuredContent).toEqual({ n: 2 });
  expect(f.calls).toEqual(["fixture_alpha", "fixture_alpha"]);
  expect(f.loads()).toBe(1);
});
