import { expect, it } from "vitest";
import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

const rpcEndpoints = (source: string) =>
  analyzeJavaScriptStaticSource(source).endpoints.filter(
    ({ mechanism }) => mechanism === "rpc:call",
  );

it("surfaces a direct createClient binding's rpc procedures as candidates", () => {
  const source = [
    'const supabase = createClient("https://example.test", "anon-key");',
    'supabase.rpc("issue_guest_token");',
    'supabase.rpc("cast_guest_vote", { p_token: "t" });',
  ].join("\n");
  expect(rpcEndpoints(source)).toMatchObject([
    {
      kind: "network",
      value: "issue_guest_token",
      interpretation: "candidate",
    },
    { kind: "network", value: "cast_guest_vote", interpretation: "candidate" },
  ]);
});

it("surfaces rpc procedures through a module namespace member holding a client", () => {
  // The Metro bundle shape: one module publishes the client as an exports
  // member; another loads the module namespace and calls through it.
  const source = [
    "__d(function (global, require, module, exports) {",
    '  exports.supabase = (0, require("supabase").createClient)("https://example.test", "anon-key");',
    "}, 1, []);",
    "__d(function (global, require, module, exports) {",
    "  var e = require(1);",
    '  e.supabase.rpc("cast_guest_vote", { p_token: "t" });',
    "}, 2, [1]);",
  ].join("\n");
  expect(rpcEndpoints(source)).toMatchObject([
    { kind: "network", value: "cast_guest_vote", interpretation: "candidate" },
  ]);
});

it("surfaces rpc procedures through a top-level require namespace member", () => {
  const source = [
    "const clientModule = {};",
    'clientModule.supabase = createClient("https://example.test", "anon-key");',
    'const e = require("./client.js");',
    'e.supabase.rpc("get_guest_ballot");',
  ].join("\n");
  expect(rpcEndpoints(source)).toMatchObject([
    { kind: "network", value: "get_guest_ballot", interpretation: "candidate" },
  ]);
});

it("surfaces rpc procedures through a destructured client member", () => {
  const source = [
    "const clientModule = {};",
    'clientModule.supabase = createClient("https://example.test", "anon-key");',
    'const { supabase } = require("./client.js");',
    'supabase.rpc("claim_guest_votes");',
  ].join("\n");
  expect(rpcEndpoints(source)).toMatchObject([
    {
      kind: "network",
      value: "claim_guest_votes",
      interpretation: "candidate",
    },
  ]);
});

it.each([
  // No member anywhere holds a client factory result.
  'const e = require("./other.js"); e.supabase.rpc("nope");',
  // The root is unbound; a same-named member on another object proves nothing.
  'const o = {}; o.supabase = createClient("https://example.test", "k"); foo.supabase.rpc("nope");',
  // The member read is not the member that holds the client.
  'const o = {}; o.supabase = createClient("https://example.test", "k"); const e = require("./client.js"); e.other.rpc("nope");',
  // The procedure name is not a literal.
  'const supabase = createClient("https://example.test", "k"); supabase.rpc(name);',
  // A local object with an rpc method is not a client.
  'const e = { supabase: { rpc(name) { return name; } } }; e.supabase.rpc("nope");',
])("omits unproven rpc receivers: %s", (source) => {
  expect(rpcEndpoints(source)).toEqual([]);
});
