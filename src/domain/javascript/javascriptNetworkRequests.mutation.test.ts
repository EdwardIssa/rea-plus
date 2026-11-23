import { expect, it } from "vitest";
import * as t from "@babel/types";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";
import { createXhrOpenRequestQuery } from "./javascriptNetworkRequests.js";
import { indexJavaScriptBindingsWithReceiversSteps } from "./javascriptSemanticAnalysis.js";
import { completeSemanticSteps } from "./javascriptSemanticTraversal.js";
import { parseJavaScriptSource } from "./javascriptSourceParser.js";

// Scenario tests for the XMLHttpRequest recognition in
// javascriptNetworkRequests.ts (isXhrOpenRequest and
// createXhrOpenRequestQuery), driven through the public static-analysis
// entry plus the exported query itself. The Stryker pilot lane held no
// XMLHttpRequest fixture at all, so the recognizer's second half was
// unmeasured: the prototype-pollution guard matrix, the changed-reference
// guard, the receiver-chain walk, and the tri-state return. Each fixture
// below is shaped so one guard is load-bearing: a proven open call keeps
// no candidate interpretation, and every fixture that breaks one proof
// step keeps the candidate interpretation instead. The pollution matrix
// is exercised one owner/member combination at a time so each path
// segment of the guard is independently load-bearing.

const endpoints = (source: string) =>
  analyzeJavaScriptStaticSource(source).endpoints.map((endpoint) => ({
    kind: endpoint.kind,
    value: endpoint.value,
    mechanism: endpoint.mechanism,
    resolution: endpoint.resolution,
    interpretation: endpoint.interpretation,
  }));

const provenOpen = (mechanism: string) => [
  {
    kind: "network",
    value: "/api/items",
    mechanism,
    resolution: undefined,
    interpretation: undefined,
  },
];

const candidateOpen = (mechanism: string) => [
  {
    kind: "network",
    value: "/api/items",
    mechanism,
    resolution: undefined,
    interpretation: "candidate",
  },
];

it("proves an open call reached through a two-binding receiver chain", () => {
  expect(
    endpoints(
      `const a = new XMLHttpRequest(); const b = a; b.open("GET", "/api/items");`,
    ),
  ).toEqual(provenOpen("call:b.open"));
});

it("proves an open call reached through a three-binding receiver chain", () => {
  expect(
    endpoints(
      `const a = new XMLHttpRequest(); const b = a; const c = b; c.open("GET", "/api/items");`,
    ),
  ).toEqual(provenOpen("call:c.open"));
});

it("proves an optional open call on a constructed receiver", () => {
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); xhr.open?.("GET", "/api/items");`,
    ),
  ).toEqual(provenOpen("call:xhr.open"));
});

it("proves a computed open call on a constructed receiver", () => {
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); xhr["open"]("GET", "/api/items");`,
    ),
  ).toEqual(provenOpen("call:xhr.open"));
});

it("proves an open call on a receiver built through the window namespace", () => {
  expect(
    endpoints(
      `const xhr = new window.XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(provenOpen("call:xhr.open"));
});

it("keeps an open call proven when an unrelated call runs first", () => {
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); unknownFn(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(provenOpen("call:xhr.open"));
});

it("keeps an open call proven when its open member is written after the call", () => {
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items"); xhr.open = function () {};`,
    ),
  ).toEqual(provenOpen("call:xhr.open"));
});

it("keeps an open call proven when another object's open member is written", () => {
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); const other = {}; other.open = function () {}; xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(provenOpen("call:xhr.open"));
});

it("keeps an open call proven when an unrelated method member is replaced first", () => {
  // The changed-reference guard watches the open and __proto__ paths
  // only; a write to any other member of the receiver must not disturb
  // the proof (an empty-path query would count it, which is what keeps
  // the guard's two path arguments load-bearing).
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); xhr.send = function () {}; xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(provenOpen("call:xhr.open"));
});

it("keeps an open call proven when an unrelated data member is written first", () => {
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); xhr.response = "x"; xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(provenOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the receiver is another constructor", () => {
  expect(
    endpoints(
      `class Other {}; const x = new Other(); x.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:x.open"));
});

it("keeps an open call a candidate when the receiver is a plain function call result", () => {
  expect(
    endpoints(`const xhr = XMLHttpRequest(); xhr.open("GET", "/api/items");`),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the constructor name is shadowed", () => {
  expect(
    endpoints(
      `class XMLHttpRequest {}; const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the receiver is undeclared", () => {
  expect(endpoints(`xhr.open("GET", "/api/items");`)).toEqual(
    candidateOpen("call:xhr.open"),
  );
});

it("keeps an open call a candidate when the receiver is a parameter", () => {
  expect(
    endpoints(`function f(xhr) { xhr.open("GET", "/api/items"); }`),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the receiver binding is reassigned", () => {
  expect(
    endpoints(
      `let xhr = new XMLHttpRequest(); xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the receiver is assignment-initialized", () => {
  expect(
    endpoints(
      `let xhr; xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the receiver is declared after the call", () => {
  expect(
    endpoints(`xhr.open("GET", "/api/items"); var xhr = new XMLHttpRequest();`),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the receiver comes from a member projection", () => {
  expect(
    endpoints(
      `const holder = { xhr: new XMLHttpRequest() }; const xhr = holder.xhr; xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the receiver is a member of a proven request", () => {
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); const alias = xhr.response; alias.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:alias.open"));
});

it("keeps an open call a candidate when the receiver is destructured", () => {
  expect(
    endpoints(
      `const { xhr } = { xhr: new XMLHttpRequest() }; xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the receiver is a destructured member of a proven request", () => {
  // The destructured binding's initializer is the request itself plus a
  // member projection; only the projection check keeps the walk from
  // treating the request as the receiver.
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); const { response: alias } = xhr; alias.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:alias.open"));
});

it("keeps an open call a candidate when the receiver is destructured from an aliased object", () => {
  expect(
    endpoints(
      `const pair = { req: new XMLHttpRequest() }; const { req: alias } = pair; alias.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:alias.open"));
});

it("keeps an open call a candidate through a two-binding cycle", () => {
  expect(
    endpoints(`const a = b; const b = a; a.open("GET", "/api/items");`),
  ).toEqual(candidateOpen("call:a.open"));
});

it("keeps an open call a candidate through a self-referential binding", () => {
  expect(endpoints(`const a = a; a.open("GET", "/api/items");`)).toEqual(
    candidateOpen("call:a.open"),
  );
});

it("keeps an open call a candidate when XMLHttpRequest.prototype.open is written", () => {
  expect(
    endpoints(
      `XMLHttpRequest.prototype.open = function () {}; const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when XMLHttpRequest.prototype.__proto__ is written", () => {
  expect(
    endpoints(
      `XMLHttpRequest.prototype.__proto__ = {}; const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when Object.prototype.open is written", () => {
  expect(
    endpoints(
      `Object.prototype.open = function () {}; const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when Object.prototype.__proto__ is written", () => {
  expect(
    endpoints(
      `Object.prototype.__proto__ = null; const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the prototype write uses a computed key", () => {
  expect(
    endpoints(
      `XMLHttpRequest.prototype["open"] = function () {}; const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the prototype write goes through an alias", () => {
  expect(
    endpoints(
      `const p = XMLHttpRequest.prototype; p.open = function () {}; const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the prototype write is spelled through globalThis", () => {
  expect(
    endpoints(
      `globalThis.XMLHttpRequest.prototype.open = function () {}; const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the prototype write follows the call", () => {
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items"); XMLHttpRequest.prototype.open = function () {};`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the request prototype object escapes", () => {
  expect(
    endpoints(
      `pollute(XMLHttpRequest.prototype); const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the request constructor escapes", () => {
  expect(
    endpoints(
      `pollute(XMLHttpRequest); const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the Object prototype object escapes", () => {
  expect(
    endpoints(
      `pollute(Object.prototype); const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the receiver's open member is replaced first", () => {
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); xhr.open = function () {}; xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the receiver's open member is replaced through an alias", () => {
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); const a = xhr; a.open = function () {}; xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps an open call a candidate when the receiver's __proto__ member is written first", () => {
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); xhr.__proto__ = {}; xhr.open("GET", "/api/items");`,
    ),
  ).toEqual(candidateOpen("call:xhr.open"));
});

it("keeps a get call on a proven receiver a candidate", () => {
  expect(
    endpoints(`const xhr = new XMLHttpRequest(); xhr.get("/api/items");`),
  ).toEqual([
    {
      kind: "network",
      value: "/api/items",
      mechanism: "call:xhr.get",
      resolution: undefined,
      interpretation: "candidate",
    },
  ]);
});

it("keeps a delete call on a proven receiver a candidate", () => {
  expect(
    endpoints(`const xhr = new XMLHttpRequest(); xhr.delete("/api/items");`),
  ).toEqual([
    {
      kind: "network",
      value: "/api/items",
      mechanism: "call:xhr.delete",
      resolution: undefined,
      interpretation: "candidate",
    },
  ]);
});

it("keeps a loadURL call on a proven receiver a candidate", () => {
  expect(
    endpoints(
      `const xhr = new XMLHttpRequest(); xhr.loadURL("https://app.example.test");`,
    ),
  ).toEqual([
    {
      kind: "network",
      value: "https://app.example.test",
      mechanism: "call:xhr.loadURL",
      resolution: undefined,
      interpretation: "candidate",
    },
  ]);
});

// The exported query is the recognizer's unit surface: the analysis entry
// only ever hands it call-shaped candidates, so its non-call rejection and
// its two-phase proof are pinned here against a real binding index.
const queryFor = (source: string) => {
  const parsed = parseJavaScriptSource(source);
  if (parsed === null) throw new Error("Expected the fixture to parse");
  const index = completeSemanticSteps(
    indexJavaScriptBindingsWithReceiversSteps(parsed.program),
  );
  return {
    program: parsed.program,
    query: createXhrOpenRequestQuery(index),
  };
};

const statementExpression = (program: t.Program, statement: number): t.Node => {
  const node = program.body[statement];
  if (node === undefined || !t.isExpressionStatement(node))
    throw new Error("Expected an expression statement");
  return node.expression;
};

it("answers the query true for a proven open call and false for other nodes", () => {
  const { program, query } = queryFor(
    `const xhr = new XMLHttpRequest(); xhr.open("GET", "/api/items");`,
  );
  expect(query(statementExpression(program, 1))).toBe(true);
  const declaration = program.body[0];
  if (
    declaration === undefined ||
    !t.isVariableDeclaration(declaration) ||
    declaration.declarations[0] === undefined
  )
    throw new Error("Expected a variable declaration");
  // The construction itself and the receiver name are not open calls.
  expect(query(declaration.declarations[0].init as t.Node)).toBe(false);
  expect(query(declaration.declarations[0].id)).toBe(false);
});

it("answers the query false for an open call on an unproven receiver", () => {
  const { program, query } = queryFor(
    `const client = createClient(); client.open("GET", "/api/items");`,
  );
  expect(query(statementExpression(program, 1))).toBe(false);
});

it("answers the query false when the receiver's open member changed first", () => {
  const { program, query } = queryFor(
    `const xhr = new XMLHttpRequest(); xhr.open = function () {}; xhr.open("GET", "/api/items");`,
  );
  expect(query(statementExpression(program, 2))).toBe(false);
});

it("answers the query false for a non-open call on a proven receiver", () => {
  const { program, query } = queryFor(
    `const xhr = new XMLHttpRequest(); xhr.get("/api/items");`,
  );
  expect(query(statementExpression(program, 1))).toBe(false);
});
