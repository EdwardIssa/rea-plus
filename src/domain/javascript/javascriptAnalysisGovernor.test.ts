import { expect, it } from "vitest";
import { JavaScriptAnalysisGovernor } from "./javascriptAnalysisGovernor.js";

const calm = { limited: false, timedOut: false, slow: false };
const limited = { limited: true, timedOut: false, slow: false };

it("runs every module's semantic phase when nothing trips", () => {
  const governor = new JavaScriptAnalysisGovernor();
  for (let i = 0; i < 12; i++) {
    const decision = governor.observeStatic(`m${String(i)}`, calm);
    expect(decision.runSemantic).toBe(true);
    governor.observeSemantic(`m${String(i)}`, false);
  }
  expect(governor.fileMode()).toBe("nominal");
  expect(governor.degradations()).toEqual([]);
  expect(governor.limitations()).toEqual([]);
});

it("tolerates a single spike without degrading", () => {
  const governor = new JavaScriptAnalysisGovernor();
  const first = governor.observeStatic("m1", limited);
  expect(first.runSemantic).toBe(true);
  governor.observeSemantic("m1", false);
  const second = governor.observeStatic("m2", calm);
  expect(second.runSemantic).toBe(true);
  governor.observeSemantic("m2", false);
  expect(governor.fileMode()).toBe("nominal");
});

it("degrades after sustained tripping in the window", () => {
  const governor = new JavaScriptAnalysisGovernor();
  governor.observeStatic("m1", limited);
  governor.observeSemantic("m1", false);
  const decision = governor.observeStatic("m2", limited);
  expect(decision.runSemantic).toBe(false);
  expect(decision.mode).toBe("degraded");
  expect(decision.reason).toContain("static resource limit");
  governor.settleDegraded("m2");
  expect(governor.degradations()).toMatchObject([{ moduleKey: "m2" }]);
  expect(governor.fileMode()).toBe("degraded");
});

it("counts structural/semantic disagreement as a trip", () => {
  const governor = new JavaScriptAnalysisGovernor();
  governor.observeStatic("m1", calm);
  governor.observeSemantic("m1", true);
  const decision = governor.observeStatic("m2", limited);
  expect(decision.runSemantic).toBe(false);
  governor.settleDegraded("m2");
});

it("never degrades the prelude", () => {
  const governor = new JavaScriptAnalysisGovernor();
  governor.observeStatic("m1", limited);
  governor.observeSemantic("m1", false);
  const decision = governor.observeStatic(null, limited);
  expect(decision.runSemantic).toBe(true);
  expect(decision.mode).toBe("nominal");
});

it("halts stickily once most settled modules degraded", () => {
  const governor = new JavaScriptAnalysisGovernor();
  // Eight settled modules, five degraded: the halt engages.
  for (let i = 0; i < 8; i++) {
    const key = `m${String(i)}`;
    const decision = governor.observeStatic(key, limited);
    if (decision.runSemantic) governor.observeSemantic(key, false);
    else governor.settleDegraded(key);
  }
  expect(governor.fileMode()).toBe("halt");
  const halted = governor.observeStatic("m9", calm);
  expect(halted.runSemantic).toBe(false);
  expect(halted.mode).toBe("halt");
  governor.settleDegraded("m9");
  expect(governor.haltedModules()).toBe(1);
  expect(governor.limitations().join(" ")).toContain("halted");
});
