import { describe, expect, it } from "vitest";

import {
  parseJvmHeapBytes,
  resolveGhidraWorkerRssCap,
} from "./GhidraWorkerSupervisor.js";

describe("parseJvmHeapBytes", () => {
  it("parses JVM heap units exactly", () => {
    expect(parseJvmHeapBytes("2G")).toBe(2 * 1024 * 1024 * 1024);
    expect(parseJvmHeapBytes("512M")).toBe(512 * 1024 * 1024);
    expect(parseJvmHeapBytes("1024K")).toBe(1024 * 1024);
    expect(parseJvmHeapBytes("1073741824")).toBe(1073741824);
    expect(parseJvmHeapBytes("2g")).toBe(2 * 1024 * 1024 * 1024);
  });

  it("refuses values it cannot read exactly", () => {
    expect(parseJvmHeapBytes("lots")).toBeUndefined();
    expect(parseJvmHeapBytes("")).toBeUndefined();
    expect(parseJvmHeapBytes("-2G")).toBeUndefined();
    expect(parseJvmHeapBytes("0")).toBeUndefined();
  });
});

describe("resolveGhidraWorkerRssCap", () => {
  it("keeps the 3 GiB default above the default 2G heap", () => {
    expect(resolveGhidraWorkerRssCap({ configuredMaxHeap: "2G" })).toBe(
      3 * 1024 * 1024 * 1024,
    );
  });

  it("raises a cap that would sit at or below the heap", () => {
    expect(
      resolveGhidraWorkerRssCap({
        configuredMaxHeap: "2G",
        requestedCapBytes: 1024 * 1024 * 1024,
      }),
    ).toBe(2 * 1024 * 1024 * 1024 + 512 * 1024 * 1024);
    expect(resolveGhidraWorkerRssCap({ configuredMaxHeap: "4G" })).toBe(
      4 * 1024 * 1024 * 1024 + 512 * 1024 * 1024,
    );
  });

  it("honors the requested cap when no heap is configured", () => {
    expect(resolveGhidraWorkerRssCap({ requestedCapBytes: 1234 })).toBe(1234);
  });
});
