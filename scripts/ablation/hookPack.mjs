/**
 * Pre-registered Frida hook pack for the dynamic-execution ablation
 * (spec section 2). Versioned; the version is recorded in every run record.
 * No target-specific hooks. Hooks: puts/fputs argument capture, printf-family
 * format capture, write() stream capture on fd 1/2 (the rendered output the
 * stdio hooks feed), dlopen/dlsym observation, exit/_exit observation.
 * Frida 17 API: Module.getGlobalExportByName (getExportByName was removed).
 */
export const HOOK_PACK_VERSION = "1.1.0";

export const HOOK_PACK_SOURCE = `
"use strict";
const PACK_VERSION = "${HOOK_PACK_VERSION}";
const hooked = [];
const missing = [];
function resolveExport(name) {
  try {
    if (typeof Module.getGlobalExportByName === "function")
      return Module.getGlobalExportByName(name);
  } catch (e) { /* fall through */ }
  try {
    if (typeof Module.findGlobalExportByName === "function")
      return Module.findGlobalExportByName(name);
  } catch (e) { /* fall through */ }
  return null;
}
function readText(pointer) {
  if (pointer === null || pointer.isNull()) return null;
  try {
    const value = pointer.readUtf8String();
    return value === null || value === undefined ? null : String(value);
  } catch (e) {
    return null;
  }
}
function attach(name, callbacks) {
  const address = resolveExport(name);
  if (address === null) { missing.push(name); return; }
  try {
    Interceptor.attach(address, callbacks);
    hooked.push(name);
  } catch (e) {
    missing.push(name + " (attach failed)");
  }
}
attach("puts", {
  onEnter(args) {
    const text = readText(args[0]);
    if (text !== null) send({ t: "puts", text });
  },
});
attach("fputs", {
  onEnter(args) {
    const text = readText(args[0]);
    if (text !== null) send({ t: "fputs", text });
  },
});
attach("printf", {
  onEnter(args) {
    const format = readText(args[0]);
    if (format !== null) send({ t: "printf_fmt", text: format });
  },
});
attach("fprintf", {
  onEnter(args) {
    const format = readText(args[1]);
    if (format !== null) send({ t: "printf_fmt", text: format });
  },
});
attach("write", {
  onEnter(args) {
    const fd = args[0].toInt32();
    if (fd !== 1 && fd !== 2) return;
    const count = args[2].toInt32();
    if (count <= 0 || count > 1048576) return;
    try {
      const bytes = args[1].readByteArray(count);
      if (bytes !== null) {
        send({ t: "write", fd, data: Array.from(new Uint8Array(bytes)) });
        // The exit-time stdio flush is the last message out of a dying
        // process; without a drain delay the agent channel teardown races
        // it and the stream tail is lost (~70% of sessions in gate runs).
        // Hold the calling thread briefly so the queued message delivers.
        const until = Date.now() + 150;
        while (Date.now() < until) { /* drain delay */ }
      }
    } catch (e) { /* unreadable buffer: the stream claim is lost, not invented */ }
  },
});
attach("dlopen", {
  onEnter(args) {
    this.path = readText(args[0]);
  },
  onLeave(retval) {
    if (this.path !== null && this.path !== undefined)
      send({ t: "dlopen", path: this.path, ok: !retval.isNull() });
  },
});
attach("dlsym", {
  onEnter(args) {
    this.name = readText(args[1]);
  },
  onLeave(retval) {
    if (this.name !== null && this.name !== undefined)
      send({ t: "dlsym", name: this.name, ok: !retval.isNull() });
  },
});
attach("exit", {
  onEnter(args) {
    send({ t: "exit", code: args[0].toInt32() });
  },
});
attach("_exit", {
  onEnter(args) {
    send({ t: "exit", code: args[0].toInt32() });
  },
});
send({ t: "pack_ready", version: PACK_VERSION, hooked, missing });
`;
