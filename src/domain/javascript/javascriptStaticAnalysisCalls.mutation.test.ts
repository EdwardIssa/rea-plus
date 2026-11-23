import { expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

// Scenario tests for the endpoint-inspection and partial-endpoint
// finishing behaviors in javascriptStaticAnalysisCalls.ts (lines
// 519-831), driven through the public static-analysis entry with
// fixtures shaped so each guard is load-bearing: a proven versus an
// unproven XMLHttpRequest open call, a BrowserWindow loadURL versus a
// loadURL spelling on an unproven receiver, a fetch target a nested
// function may reassign, a target declared only after the call, a
// conditional initializer, prototype writes that must block URL-object
// resolution, a three-argument URL constructor, a non-literal base
// beside an absolute input, cyclic alias chains, and a binding rebound
// after aliasing. These pin the behaviors the Stryker pilot left
// unmeasured in this file (see the goal's survivor inventory).

const endpoints = (source: string) =>
  analyzeJavaScriptStaticSource(source).endpoints.map((endpoint) => ({
    kind: endpoint.kind,
    value: endpoint.value,
    mechanism: endpoint.mechanism,
    resolution: endpoint.resolution,
    interpretation: endpoint.interpretation,
  }));

it("does not mark a proven XMLHttpRequest open call as a candidate", () => {
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual([
    {
      kind: "network",
      value: "/api/items",
      mechanism: "call:xhr.open",
      resolution: undefined,
      interpretation: undefined,
    },
  ]);
});

it("marks an open call on an unproven receiver as a candidate", () => {
  expect(
    endpoints(
      `const client = createClient(); client.open("GET", "/api/items");`,
    ),
  ).toEqual([
    {
      kind: "network",
      value: "/api/items",
      mechanism: "call:client.open",
      resolution: undefined,
      interpretation: "candidate",
    },
  ]);
});

it("resolves a BrowserWindow loadURL target with no candidate interpretation", () => {
  expect(
    endpoints(`
      const { BrowserWindow } = require("electron");
      const win = new BrowserWindow();
      win.loadURL("https://app.example.test");
    `),
  ).toEqual([
    {
      kind: "network",
      value: "https://app.example.test",
      mechanism: "call:win.loadURL",
      resolution: undefined,
      interpretation: undefined,
    },
  ]);
});

it("does not record a BrowserWindow loadFile call as a network endpoint", () => {
  expect(
    endpoints(`
      const { BrowserWindow } = require("electron");
      const win = new BrowserWindow();
      win.loadFile("./window.html");
    `),
  ).toEqual([]);
});

it("marks a loadURL call on an unproven receiver as a candidate", () => {
  expect(
    endpoints(
      `const loader = createLoader(); loader.loadURL("https://plain.example.test");`,
    ),
  ).toEqual([
    {
      kind: "network",
      value: "https://plain.example.test",
      mechanism: "call:loader.loadURL",
      resolution: undefined,
      interpretation: "candidate",
    },
  ]);
});

it("resolves a BrowserWindow loadURL target bound to an unchanged literal", () => {
  expect(
    endpoints(`
      const { BrowserWindow } = require("electron");
      const win = new BrowserWindow();
      const target = "https://dyn.example.test";
      win.loadURL(target);
    `),
  ).toEqual([
    {
      kind: "network",
      value: "https://dyn.example.test",
      mechanism: "call:win.loadURL",
      resolution: undefined,
      interpretation: undefined,
    },
  ]);
});

it("keeps a fetch target partial when a nested function may reassign it", () => {
  expect(
    endpoints(`
      let endpoint = "https://first.example.test";
      function poke() { endpoint = "https://second.example.test"; }
      fetch(endpoint);
    `),
  ).toEqual([
    {
      kind: "network",
      value: "endpoint",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("keeps a member target partial when the member is written through an alias", () => {
  expect(
    endpoints(`
      const config = { url: "https://api.example.test" };
      const alias = config;
      alias.url = "https://evil.example.test";
      fetch(config.url);
    `),
  ).toEqual([
    {
      kind: "network",
      value: "config.url",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("does not resolve a fetch target from a var declaration after the call", () => {
  expect(
    endpoints(`
      fetch(endpoint);
      var endpoint = "https://late.example.test";
    `),
  ).toEqual([
    {
      kind: "network",
      value: "endpoint",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("keeps a fetch target partial when its only initializer is conditional", () => {
  expect(
    endpoints(`
      if (flag) { var endpoint = "https://cond.example.test"; }
      fetch(endpoint);
    `),
  ).toEqual([
    {
      kind: "network",
      value: "endpoint",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("does not resolve a fetch target initialized inside a block", () => {
  expect(
    endpoints(`
      { const endpoint = "https://api.example.test"; fetch(endpoint); }
    `),
  ).toEqual([
    {
      kind: "network",
      value: "endpoint",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("does not resolve a fetch target initialized inside a try block", () => {
  expect(
    endpoints(`
      try { const endpoint = "https://api.example.test"; fetch(endpoint); } catch {}
    `),
  ).toEqual([
    {
      kind: "network",
      value: "endpoint",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("keeps a URL object partial when URL.prototype.toString is overwritten", () => {
  expect(
    endpoints(`
      URL.prototype.toString = () => "x";
      const socket = new URL("https://api.example.test/socket");
      fetch(socket);
    `),
  ).toEqual([
    {
      kind: "network",
      value: "socket",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("keeps a URL object partial when Object.prototype.valueOf is overwritten", () => {
  expect(
    endpoints(`
      Object.prototype.valueOf = () => "x";
      const socket = new URL("https://api.example.test/socket");
      fetch(socket);
    `),
  ).toEqual([
    {
      kind: "network",
      value: "socket",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("keeps a URL object with three constructor arguments partial", () => {
  expect(
    endpoints(`
      const socket = new URL("/socket", "https://api.example.test", "extra");
      fetch(socket);
    `),
  ).toEqual([
    {
      kind: "network",
      value: "socket",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("keeps a URL object partial when its base is not a literal, even for an absolute input", () => {
  expect(
    endpoints(`
      const socket = new URL("https://api.example.test/x", dynamicBase);
      fetch(socket);
    `),
  ).toEqual([
    {
      kind: "network",
      value: "socket",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("keeps a cyclic alias chain partial", () => {
  expect(
    endpoints(`
      const a = b;
      const b = a;
      fetch(a);
    `),
  ).toEqual([
    {
      kind: "network",
      value: "a",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
  expect(
    endpoints(`
      const a = a;
      fetch(a);
    `),
  ).toEqual([
    {
      kind: "network",
      value: "a",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("keeps an aliased URL object partial when the source binding is rebound", () => {
  expect(
    endpoints(`
      let first = new URL("https://api.example.test");
      const second = first;
      first = new URL("https://evil.example.test");
      fetch(second);
    `),
  ).toEqual([
    {
      kind: "network",
      value: "second",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("keeps an aliased URL object partial when the source object is mutated", () => {
  expect(
    endpoints(`
      const first = new URL("https://api.example.test");
      const second = first;
      first.hostname = "evil.example.test";
      fetch(second);
    `),
  ).toEqual([
    {
      kind: "network",
      value: "second",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("keeps a non-toString method result on a URL object partial", () => {
  expect(
    endpoints(`
      const socket = new URL("wss://api.example.test/socket");
      new WebSocket(socket.clone());
    `),
  ).toEqual([
    {
      kind: "network",
      value: "socket.clone()",
      mechanism: "call:WebSocket",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("keeps a toString call carrying an argument partial", () => {
  expect(
    endpoints(`
      const socket = new URL("wss://api.example.test/socket");
      new WebSocket(socket.toString(10));
    `),
  ).toEqual([
    {
      kind: "network",
      value: "socket.toString(10)",
      mechanism: "call:WebSocket",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("keeps a URL object partial when its literal input is not a valid URL", () => {
  expect(
    endpoints(`
      const socket = new URL("http://");
      fetch(socket);
    `),
  ).toEqual([
    {
      kind: "network",
      value: "socket",
      mechanism: "call:fetch",
      resolution: "partial",
      interpretation: undefined,
    },
  ]);
});

it("resolves a URL object passed to fetch through its toString", () => {
  expect(
    endpoints(`
      const socket = new URL("https://api.example.test/socket");
      fetch(socket.toString());
    `),
  ).toEqual([
    {
      kind: "network",
      value: "https://api.example.test/socket",
      mechanism: "call:fetch",
      resolution: undefined,
      interpretation: undefined,
    },
  ]);
});
