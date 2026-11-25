#!/usr/bin/env node
/**
 * Discovery-quality benchmarks for the lazy MCP tool surface (gate items
 * 1, 3, 4 from the iteration-3 verification extension):
 *
 * 1. Intent recall: paraphrased natural-language intents (with misspellings
 *    and ambiguous phrasings) are run through `search_tools` on the real
 *    lazy composition; Recall@3 for the canonical tool is reported with
 *    every miss listed.
 * 3. Near-duplicate adversarial pairs: intents written for each side of six
 *    semantically similar tool pairs; the wrong-tool (sibling) top-1 rate
 *    and every confusion are reported.
 * 4. Discovery overhead: one fixed five-call task is executed on the lazy
 *    surface (search + load for the two non-core tools) and on the full
 *    surface (direct calls); end-to-end latency and the schema tokens each
 *    side pays (advertised at connect plus loaded on demand) are reported.
 *
 * Method: in-process transport against createServer's sessionless fixed
 * composition, the same composition the surface measurement uses. Tokens
 * are estimated as ceil(JSON code units / 4) per payload, the same
 * estimator as scripts/measure-mcp-surface.mjs. Latency is a single warm
 * run per surface after one warm-up connect per surface; it excludes any
 * network transport.
 */
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";

import { createServer } from "../dist/server/createServer.js";

const tokensOf = (value) => Math.ceil(JSON.stringify(value).length / 4);

const connect = async (environment) => {
  const analysis = { execute: () => Promise.reject(new Error("stub")) };
  const server = createServer({ kind: "fixed", analysis }, { environment });
  const client = new Client({ name: "discovery-quality", version: "0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client, server };
};

const searchNames = async (client, query, limit = 3) => {
  const result = await client.callTool({
    name: "search_tools",
    arguments: { query, limit },
  });
  return result.structuredContent.matches.map((match) => match.name);
};

/** [canonical tool, intent] pairs for the recall benchmark. */
const INTENTS = [
  ["binary_overview", "give me an overview of this binary"],
  ["binary_overview", "what kind of file is this executable"],
  ["list_strings", "show me all the strings in the binary"],
  ["list_strings", "list every string you can find"],
  ["search_strings", "find strings mentioning password"],
  ["search_strings", "search the strings for a url"],
  ["read_bytes", "read the bytes at this offset"],
  ["read_bytes", "dump raw bytes from the file"],
  ["search_bytes", "search for a byte pattern in the binary"],
  ["search_bytes", "find this hex pattern"],
  ["procedure_pseudo_code", "show the psuedo code for the selected procedure"],
  ["decompile_all", "decompile everything in the binary"],
  ["get_call_graph", "show me the call graph"],
  ["get_call_graph", "which functions call which"],
  ["inspect_analysis_settings", "what are the current analysis settings"],
  ["inspect_analysis_settings", "show my analysis configuration"],
  ["update_analysis_settings", "change how deep the analysis goes"],
  ["update_analysis_settings", "update the analysis settings to be faster"],
  ["search_guidance", "search the documentation for how to analyze a module"],
  ["search_guidance", "find guidance about javascript analysis"],
  ["read_guidance_section", "read that guidance section"],
  ["read_guidance_section", "open the guide page about workflows"],
  ["inspect_binary_layout", "inspect the binary layout and segments"],
  ["inspect_byte_entropy", "is this binary packed, check entropi"],
  ["demangle_swift", "demangle this swift symbol"],
  ["demangle_swift", "decode a mangled swift name"],
  ["list_procedures", "list all the procedures"],
  ["search_procedures", "search for procedures named encrypt"],
  ["procedure_callers", "what calls this function"],
  ["procedure_callees", "what does this function call"],
  ["xrefs", "show cross references to this address"],
  ["inspect_macho", "inspect the macho headers"],
  ["list_architectures", "list the architecures in the fat binary"],
  ["cutter_command", "run a cutter command"],
  ["start_gdb_session", "start a gdb session"],
  ["inspect_pe_resources", "inspect the pe resources"],
  ["inspect_elf_notes", "read the elf notes"],
  ["find_xrefs_to_name", "find references to the name memcpy"],
  ["analyze_function", "analyze this function"],
  ["batch_decompile", "decompile a batch of procedures"],
  ["list_names", "list all named addresses"],
  ["inspect_signature", "check the code signature"],
  ["get_objc_classes", "list the objective-c classes"],
  ["trace_call_path", "trace the call path between these functions"],
  ["execute_rizin_command", "run a rizin command"],
  ["search_guidance", "serach the guidence for wasm"],
  ["list_strings", "strings"],
];

/** [tool A, tool B, intents for A, intents for B] near-duplicate pairs. */
const PAIRS = [
  [
    "list_strings",
    "search_strings",
    [
      "list all strings in the binary",
      "show me every string",
      "enumerate the strings",
      "dump the full strings table",
    ],
    [
      "search strings for token",
      "find strings containing http",
      "look for a specific string",
      "which strings mention password",
    ],
  ],
  [
    "inspect_analysis_settings",
    "update_analysis_settings",
    [
      "view the current analysis settings",
      "read my analysis config",
      "what settings is the analysis using",
      "show analysis settings",
    ],
    [
      "change the analysis settings",
      "set the analysis timeout higher",
      "modify my analysis config",
      "update analysis settings",
    ],
  ],
  [
    "search_guidance",
    "read_guidance_section",
    [
      "search the guidance docs",
      "find documentation about modules",
      "look up guidance for modules",
      "search the built in guide",
    ],
    [
      "read the guidance section you found",
      "open that doc section",
      "show me the full guide page",
      "read the selected guidance entry",
    ],
  ],
  [
    "list_procedures",
    "search_procedures",
    [
      "list all procedures",
      "show every procedure",
      "enumerate functions",
      "dump the procedure list",
    ],
    [
      "search procedures by name",
      "find a procedure called main",
      "look for procedures matching crypto",
      "which procedures contain init",
    ],
  ],
  [
    "procedure_callers",
    "procedure_callees",
    [
      "who calls this procedure",
      "list the callers of this function",
      "what calls into here",
      "show incoming calls",
    ],
    [
      "what does this procedure call",
      "list the callees",
      "what functions does it invoke",
      "show outgoing calls from here",
    ],
  ],
  [
    "read_bytes",
    "search_bytes",
    [
      "read bytes at offset 0x100",
      "dump the raw bytes here",
      "show me the bytes at this address",
      "get the byte content",
    ],
    [
      "search for this byte pattern",
      "find the hex sequence",
      "scan for bytes 4d5a",
      "locate a byte signature",
    ],
  ],
];

const recallBenchmark = async (client) => {
  let hits = 0;
  const misses = [];
  for (const [canonical, intent] of INTENTS) {
    const top = await searchNames(client, intent, 3);
    if (top.includes(canonical)) hits += 1;
    else misses.push({ intent, canonical, top });
  }
  return { total: INTENTS.length, hits, misses };
};

const pairBenchmark = async (client) => {
  let intents = 0;
  let siblingTop1 = 0;
  let otherTop1 = 0;
  const confusions = [];
  for (const [a, b, intentsA, intentsB] of PAIRS) {
    for (const [canonical, sibling, list] of [
      [a, b, intentsA],
      [b, a, intentsB],
    ]) {
      for (const intent of list) {
        intents += 1;
        const [top1] = await searchNames(client, intent, 3);
        if (top1 === sibling) {
          siblingTop1 += 1;
          confusions.push({ intent, canonical, picked: top1 });
        } else if (top1 !== canonical) {
          otherTop1 += 1;
          confusions.push({ intent, canonical, picked: top1 ?? "(none)" });
        }
      }
    }
  }
  return { intents, siblingTop1, otherTop1, confusions };
};

const TASK_CALLS = [
  ["inspect_analysis_settings", {}],
  ["search_guidance", { query: "javascript module" }],
  ["guided_workflows", { action: "list" }],
  ["demangle_swift", { symbols: ["_$sSi1gSi_tcfC"] }],
  ["read_guidance_section", { locator: "workflows" }],
];
const DISCOVERED = ["demangle_swift", "read_guidance_section"];

const overheadBenchmark = async () => {
  const run = async (environment, lazy) => {
    const { client, server } = await connect(environment);
    try {
      const started = performance.now();
      const listed = await client.listTools();
      let schemaTokens = listed.tools.reduce(
        (sum, tool) => sum + tokensOf(tool),
        0,
      );
      if (lazy) {
        for (const name of DISCOVERED) {
          await client.callTool({
            name: "search_tools",
            arguments: { query: name, limit: 3 },
          });
          const load = await client.callTool({
            name: "load_tool_schema",
            arguments: { name },
          });
          const { inputSchema, outputSchema } = load.structuredContent;
          schemaTokens +=
            tokensOf(inputSchema) +
            (outputSchema === undefined ? 0 : tokensOf(outputSchema));
        }
      }
      for (const [name, args] of TASK_CALLS)
        await client.callTool({ name, arguments: args }).catch(() => undefined);
      return { ms: performance.now() - started, schemaTokens };
    } finally {
      await client.close();
      await server.close();
    }
  };
  // One warm-up connect per surface, then the measured run per surface.
  for (const environment of [
    { REA_MCP_TOOL_SURFACE: "full" },
    { REA_MCP_TOOL_SURFACE: "lazy" },
  ]) {
    const { client, server } = await connect(environment);
    await client.close();
    await server.close();
  }
  const full = await run({ REA_MCP_TOOL_SURFACE: "full" }, false);
  const lazy = await run({ REA_MCP_TOOL_SURFACE: "lazy" }, true);
  return { full, lazy };
};

const { client, server } = await connect({ REA_MCP_TOOL_SURFACE: "lazy" });
try {
  const recall = await recallBenchmark(client);
  console.log(
    `recall@3: ${recall.hits}/${recall.total} = ${(recall.hits / recall.total).toFixed(3)}`,
  );
  for (const miss of recall.misses)
    console.log(
      `  miss: intent=${JSON.stringify(miss.intent)} canonical=${miss.canonical} top3=${miss.top.join(",") || "(none)"}`,
    );
  const pairs = await pairBenchmark(client);
  console.log(
    `near-duplicate: ${pairs.intents} intents, sibling top-1 ${pairs.siblingTop1} (${(pairs.siblingTop1 / pairs.intents).toFixed(3)}), other top-1 ${pairs.otherTop1}`,
  );
  for (const confusion of pairs.confusions)
    console.log(
      `  confusion: intent=${JSON.stringify(confusion.intent)} canonical=${confusion.canonical} picked=${confusion.picked}`,
    );
} finally {
  await client.close();
  await server.close();
}
const overhead = await overheadBenchmark();
console.log(
  `overhead full: ${overhead.full.ms.toFixed(1)} ms, ${overhead.full.schemaTokens} schema tokens`,
);
console.log(
  `overhead lazy: ${overhead.lazy.ms.toFixed(1)} ms, ${overhead.lazy.schemaTokens} schema tokens`,
);
