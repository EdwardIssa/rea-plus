/**
 * Static arm of the ablation: one REA+ MCP session per target against the
 * supervised Ghidra bridge (the product surface, full tool surface so the
 * analysis tools are directly callable), assembling the static facts that
 * claims.mjs turns into Arm S claims. The server process tree's RSS is
 * polled with the repo's own /proc accounting; the pass is killed at the
 * spec budget. Facts only — no claim rules live here.
 */
import { spawn } from "node:child_process";
import { readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";

import { readProcessTreeRssBytes } from "../../dist/ghidra/GhidraWorkerSupervisor.js";
import { descendantsOf } from "./harness.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const stripExternal = (value) =>
  typeof value === "string" && value.startsWith("<EXTERNAL>::")
    ? value.slice("<EXTERNAL>::".length)
    : value;

export const runStaticPass = async ({
  binaryPath,
  worktree,
  ghidraInstallDir,
  javaHome,
  budgetMs = 120000,
}) => {
  const startedAt = Date.now();
  // The Ghidra bridge leaves a rea-ghidra-* temp dir per analysis; a killed
  // server never cleans up, and /tmp here is a small tmpfs — snapshot the
  // set now and remove this pass's dirs in the finally block.
  const ghidraTempBefore = new Set(
    readdirSync(tmpdir()).filter((n) => n.startsWith("rea-ghidra-")),
  );
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    REA_LOG_LEVEL: "silent",
    REA_MCP_TOOL_SURFACE: "full",
    GHIDRA_INSTALL_DIR: ghidraInstallDir,
    JAVA_HOME: javaHome,
  };
  const child = spawn("node", ["scripts/rea.mjs", "mcp"], {
    cwd: worktree,
    env,
    detached: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
  let peakRss = 0;
  let polling = true;
  const poller = (async () => {
    while (polling) {
      try {
        const rss = await readProcessTreeRssBytes(child.pid);
        if (typeof rss === "number" && rss > peakRss) peakRss = rss;
      } catch {
        // Tree gone.
      }
      await sleep(200);
    }
  })();
  const pending = new Map();
  let nextId = 1;
  const lines = createInterface({ input: child.stdout });
  lines.on("line", (line) => {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      return;
    }
    if (message.id !== undefined && pending.has(message.id)) {
      pending.get(message.id)(message);
      pending.delete(message.id);
    }
  });
  const request = (method, params, timeoutMs) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      const timer = setTimeout(
        () => reject(new Error(`MCP request ${method} timed out`)),
        timeoutMs,
      );
      pending.set(id, (message) => {
        clearTimeout(timer);
        if (message.error)
          reject(new Error(`MCP ${method}: ${JSON.stringify(message.error)}`));
        else resolve(message.result);
      });
      child.stdin.write(
        JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n",
      );
    });
  const notify = (method) =>
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method }) + "\n");
  const callTool = async (name, args, timeoutMs) => {
    const result = await request(
      "tools/call",
      { name, arguments: args },
      timeoutMs,
    );
    if (result?.isError)
      throw new Error(
        `tool ${name} failed: ${JSON.stringify(result.content).slice(0, 300)}`,
      );
    return result.structuredContent;
  };
  const remaining = () => Math.max(1000, budgetMs - (Date.now() - startedAt));
  try {
    await request(
      "initialize",
      {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "ablation-static-arm", version: "1.0.0" },
      },
      remaining(),
    );
    notify("notifications/initialized");
    await callTool("open_binary", { path: binaryPath }, remaining());
    const overview = await callTool("binary_overview", {}, remaining());
    const proceduresResult = await callTool(
      "list_procedures",
      { detail: "complete" },
      remaining(),
    );
    const stringsResult = await callTool(
      "list_strings",
      { detail: "complete" },
      remaining(),
    );
    const procedures = (proceduresResult?.normalized_result ?? []).map(
      (row) => ({
        address: row.address,
        name: stripExternal(row.value),
        external: row.symbol?.external === true,
        thunk: row.procedure?.thunk === true,
      }),
    );
    const defined = procedures.filter((p) => !p.external);
    const byAddress = new Map(procedures.map((p) => [p.address, p.name]));
    const mainProcedure = defined.find((p) => p.name === "main");
    const directEdges = [];
    if (mainProcedure !== undefined) {
      const graphResult = await callTool(
        "get_call_graph",
        {
          address: mainProcedure.address,
          direction: "forward",
          detail: "complete",
        },
        remaining(),
      );
      const levels = Object.values(graphResult?.normalized_result?.graph ?? {});
      for (const level of levels)
        for (const node of level) {
          const caller = byAddress.get(node.address);
          if (caller === undefined) continue;
          for (const calleeAddress of node.calls ?? []) {
            const callee = byAddress.get(calleeAddress);
            if (callee !== undefined) directEdges.push([caller, callee]);
          }
        }
    }
    // Caller attribution for address-taken functions: an xref address inside
    // a defined function's address range attributes that function.
    const sortedDefined = [...defined].sort((a, b) =>
      a.address.localeCompare(b.address, undefined, { numeric: false }),
    );
    const rangeOf = (address) => {
      let owner = null;
      for (const proc of sortedDefined) {
        if (address >= proc.address) owner = proc.name;
        else break;
      }
      return owner;
    };
    const xrefEdges = [];
    for (const proc of defined) {
      if (proc.thunk) continue;
      const xrefsResult = await callTool(
        "xrefs",
        { address: proc.address },
        remaining(),
      );
      for (const refAddress of xrefsResult?.normalized_result ?? []) {
        const owner = rangeOf(refAddress);
        if (owner !== null && owner !== proc.name)
          xrefEdges.push([owner, proc.name]);
      }
    }
    const facts = {
      stringFacts: (stringsResult?.normalized_result ?? []).map((r) => r.value),
      procedureNames: [...new Set(procedures.map((p) => p.name))],
      definedNames: [...new Set(defined.map((p) => p.name))],
      directEdges,
      xrefEdges,
      procedureCount: procedures.length,
      definedCount: defined.length,
      importsDlsym: procedures.some((p) => p.name === "dlsym" && p.external),
    };
    return {
      status: "complete",
      failure_reason: null,
      facts,
      provider: overview?.provider ?? overview?.evidence?.provider ?? null,
      wall_ms: Date.now() - startedAt,
      peak_rss_bytes: peakRss,
    };
  } catch (error) {
    return {
      status: "failed",
      failure_reason: `static pass failed: ${error?.message ?? String(error)}`,
      facts: null,
      provider: null,
      wall_ms: Date.now() - startedAt,
      peak_rss_bytes: peakRss,
    };
  } finally {
    polling = false;
    await poller;
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      // Already gone.
    }
    for (const pid of descendantsOf(child.pid))
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // Already gone.
      }
    child.stdin.destroy();
    await sleep(300);
    for (const name of readdirSync(tmpdir())) {
      if (!name.startsWith("rea-ghidra-") || ghidraTempBefore.has(name))
        continue;
      try {
        rmSync(join(tmpdir(), name), { recursive: true, force: true });
      } catch {
        // Best effort; a leftover dir is recorded by the next df check.
      }
    }
  }
};
