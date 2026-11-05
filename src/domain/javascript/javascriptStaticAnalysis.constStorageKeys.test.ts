import { expect, it } from "vitest";
import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

it.each([
  'const n = "mila_guest_token"; localStorage.getItem(n);',
  'const n = "mila_guest_token"; localStorage.setItem(n, "v"); localStorage.removeItem(n);',
  "const n = 'mila_guest_token'; sessionStorage.getItem(n);",
])("propagates a const-bound storage key: %s", (source) => {
  const storage = analyzeJavaScriptStaticSource(source).storage;
  expect(storage.length).toBeGreaterThan(0);
  for (const entry of storage)
    expect(entry).toMatchObject({ name: "mila_guest_token" });
});

it("keeps literal storage keys unchanged", () => {
  expect(
    analyzeJavaScriptStaticSource('localStorage.getItem("plain");').storage,
  ).toMatchObject([{ kind: "local-storage", name: "plain" }]);
});

it.each([
  // A reassigned binding has no single stable value.
  'let n = "k"; n = "k2"; localStorage.getItem(n);',
  // Two declarations with initializers are not a stable initializer.
  'var n = "k"; var n = "k2"; localStorage.getItem(n);',
  // A non-string const is not a key value.
  "const n = 42; localStorage.getItem(n);",
  // An unbound or dynamic key stays unknown.
  "localStorage.getItem(someKey);",
  "localStorage.getItem(prefix + '_key');",
])("leaves unproven storage keys unknown: %s", (source) => {
  const storage = analyzeJavaScriptStaticSource(source).storage;
  expect(storage.length).toBeGreaterThan(0);
  for (const entry of storage) expect(entry.name).toBeNull();
});
