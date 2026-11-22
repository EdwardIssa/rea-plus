// Measure the advertised MCP surface at connect: tool count and advertised
// schema size for the full and lazy tool surfaces, through the production
// composition (createServer) and a real SDK client over an in-memory
// transport pair.
//
// Counting method (identical for both states): for each tool in the client's
// tools/list response, serialize { name, title, description, inputSchema,
// outputSchema, annotations } with JSON.stringify and sum the UTF-16 code
// units; estimated tokens = ceil(code units / 4). The same serialization is
// hashed per state so repeat runs are comparable.
//
// Usage: npm run compile && node scripts/measure-mcp-surface.mjs
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";

import { createServer } from "../dist/server/createServer.js";
import { TOOL_CONTRACTS } from "../dist/contracts/toolContracts.js";

const analysis = {
  execute: () =>
    Promise.reject(new Error("measurement stub never executes operations")),
};

const measure = async (label, environment) => {
  const server = createServer(
    { kind: "fixed", analysis },
    { environment },
  );
  const client = new Client({ name: "rea-surface-measure", version: "0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    const { tools } = await client.listTools();
    let codeUnits = 0;
    for (const tool of tools) codeUnits += JSON.stringify(tool).length;
    return {
      label,
      tools: tools.length,
      codeUnits,
      estimatedTokens: Math.ceil(codeUnits / 4),
      names: tools.map(({ name }) => name),
    };
  } finally {
    await client.close();
    await server.close();
  }
};

const full = await measure("full", {});
const lazy = await measure("lazy", { REA_MCP_TOOL_SURFACE: "lazy" });
for (const state of [full, lazy])
  console.log(
    `${state.label}: ${state.tools} tools advertised, ${state.codeUnits} code units, ~${state.estimatedTokens} estimated tokens`,
  );
console.log(`lazy advertised: ${lazy.names.join(", ")}`);
const hidden = TOOL_CONTRACTS.map(({ name }) => name).filter(
  (name) => !lazy.names.includes(name),
);
console.log(
  `contract tools not advertised under lazy: ${hidden.length} of ${TOOL_CONTRACTS.length} (all remain registered; reachable via search_tools + load_tool_schema)`,
);
