import { describe, expect, it } from "vitest";

import type { JsonValue } from "../jsonValue.js";
import { fileDynamicObservations, soBasename } from "./dynamicObservation.js";

const send = (payload: Record<string, unknown>): JsonValue =>
  ({ type: "send", payload }) as JsonValue;

describe("soBasename", () => {
  it("derives .so basenames and refuses other shapes", () => {
    expect(soBasename("./libplug3.so")).toBe("libplug3.so");
    expect(soBasename("/usr/lib/libc.so.6")).toBe("libc.so.6");
    expect(soBasename("libfoo.so.1.2")).toBe("libfoo.so.1.2");
    expect(soBasename("./lib%s%s.so")).toBe("lib%s%s.so");
    expect(soBasename("/bin/ls")).toBeNull();
    expect(soBasename("readme.txt")).toBeNull();
  });
});

describe("fileDynamicObservations", () => {
  it("files argument captures as string rows under their channels, deduplicated", () => {
    const filing = fileDynamicObservations([
      send({ t: "puts", text: "hello" }),
      send({ t: "puts", text: "hello" }),
      send({ t: "fputs", text: "hello" }),
      send({ t: "printf_fmt", text: "value=%d" }),
    ]);
    expect(filing.strings).toEqual([
      { value: "hello", channel: "puts" },
      { value: "hello", channel: "fputs" },
      { value: "value=%d", channel: "printf_fmt" },
    ]);
  });

  it("never files fixture attribution lines as content strings", () => {
    const filing = fileDynamicObservations([
      send({ t: "puts", text: "MARK:main" }),
      send({ t: "puts", text: "real" }),
    ]);
    expect(filing.strings).toEqual([{ value: "real", channel: "puts" }]);
  });

  it("files a dlopen path as a module row only and a dlsym name as a symbol row only", () => {
    const filing = fileDynamicObservations([
      send({ t: "dlopen", path: "./libplug3.so", ok: true }),
      send({ t: "dlopen", path: "./missing.so", ok: false }),
      send({ t: "dlsym", name: "plug_greet", ok: true }),
      send({ t: "dlsym", name: "absent_fn", ok: false }),
    ]);
    expect(filing.modules).toEqual([
      { path: "./libplug3.so", basename: "libplug3.so", ok: true },
      { path: "./missing.so", basename: "missing.so", ok: false },
    ]);
    expect(filing.symbols).toEqual([
      { name: "plug_greet", ok: true },
      { name: "absent_fn", ok: false },
    ]);
    // One kind per observation: neither appears as a string row.
    expect(filing.strings).toEqual([]);
  });

  it("assembles write streams once as output, split by fd, ignoring other fds", () => {
    const bytes = (text: string): number[] => [...Buffer.from(text, "utf8")];
    const filing = fileDynamicObservations([
      send({ t: "write", fd: 1, data: bytes("alp") }),
      send({ t: "write", fd: 2, data: bytes("err!") }),
      send({ t: "write", fd: 1, data: bytes("ha\n") }),
      send({ t: "write", fd: 7, data: bytes("ignored") }),
    ]);
    expect(filing.output.stdout).toBe("alpha\n");
    expect(filing.output.stderr).toBe("err!");
    // Stream text is never re-filed as string rows.
    expect(filing.strings).toEqual([]);
  });

  it("drops malformed write payloads instead of inventing bytes", () => {
    const filing = fileDynamicObservations([
      send({ t: "write", fd: 1, data: [65, 999, 66] }),
      send({ t: "write", fd: 1, data: "not-an-array" }),
    ]);
    expect(filing.output.stdout).toBe("");
  });

  it("captures pack_ready and the exit code, and ignores non-send messages", () => {
    const filing = fileDynamicObservations([
      { type: "log", payload: { t: "puts", text: "not-a-send" } } as JsonValue,
      send({
        t: "pack_ready",
        version: "1.1.0",
        hooked: ["puts", "write"],
        missing: ["dlopen"],
      }),
      send({ t: "exit", code: 3 }),
    ]);
    expect(filing.packVersion).toBe("1.1.0");
    expect(filing.packReady).toEqual({
      hooked: ["puts", "write"],
      missing: ["dlopen"],
    });
    expect(filing.output.exit_code).toBe(3);
    expect(filing.strings).toEqual([]);
  });
});
