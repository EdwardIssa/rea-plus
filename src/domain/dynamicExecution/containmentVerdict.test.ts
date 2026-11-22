import { describe, expect, it } from "vitest";

import {
  composeContainmentVerdict,
  containmentAccountingTruncated,
} from "./containmentVerdict.js";
import type { DynamicDescendantAccounting } from "./dynamicObservation.js";

const accounting = (
  overrides: Partial<DynamicDescendantAccounting> = {},
): DynamicDescendantAccounting => ({
  subreaper_armed: true,
  observed: [],
  observed_count: 0,
  remaining: [],
  remaining_count: 0,
  ...overrides,
});

describe("composeContainmentVerdict", () => {
  it("reports unverified with a null breach when no accounting exists", () => {
    expect(
      composeContainmentVerdict({
        accounting: null,
        aliveAccounted: [],
        sweepSurvivors: [],
      }),
    ).toEqual({
      verified: false,
      source: "unavailable",
      survivors_after: [],
      breach: null,
      reaped_descendants: [],
    });
  });

  it("reports unverified when the worker could not prove the subreaper role", () => {
    expect(
      composeContainmentVerdict({
        accounting: accounting({
          subreaper_armed: false,
          observed: [{ pid: 41, exe: "/bin/sleep" }],
          observed_count: 1,
        }),
        aliveAccounted: [],
        sweepSurvivors: [],
      }),
    ).toEqual({
      verified: false,
      source: "unavailable",
      survivors_after: [],
      breach: null,
      reaped_descendants: [],
    });
  });

  it("never lets a sweep result manufacture a clean verdict without accounting", () => {
    const verdict = composeContainmentVerdict({
      accounting: null,
      aliveAccounted: [],
      sweepSurvivors: ["/bin/sleep"],
    });
    expect(verdict.verified).toBe(false);
    expect(verdict.breach).toBeNull();
    expect(verdict.survivors_after).toEqual([]);
  });

  it("verdicts a clean run from armed accounting with no descendants", () => {
    expect(
      composeContainmentVerdict({
        accounting: accounting(),
        aliveAccounted: [],
        sweepSurvivors: [],
      }),
    ).toEqual({
      verified: true,
      source: "subreaper_accounting",
      survivors_after: [],
      breach: false,
      reaped_descendants: [],
    });
  });

  it("names a reaped different-image escapee from the accounting", () => {
    expect(
      composeContainmentVerdict({
        accounting: accounting({
          observed: [{ pid: 41, exe: "/usr/bin/sleep" }],
          observed_count: 1,
          remaining: [{ pid: 41, exe: "/usr/bin/sleep" }],
          remaining_count: 1,
        }),
        aliveAccounted: [],
        sweepSurvivors: [],
      }),
    ).toEqual({
      verified: true,
      source: "subreaper_accounting",
      survivors_after: [],
      breach: false,
      reaped_descendants: ["/usr/bin/sleep"],
    });
  });

  it("reports a breach naming an accounted descendant still alive post-settle", () => {
    const verdict = composeContainmentVerdict({
      accounting: accounting({
        observed: [{ pid: 41, exe: "/usr/bin/sleep" }],
        observed_count: 1,
        remaining: [{ pid: 41, exe: "/usr/bin/sleep" }],
        remaining_count: 1,
      }),
      aliveAccounted: [{ pid: 41, exe: "/usr/bin/sleep" }],
      sweepSurvivors: [],
    });
    expect(verdict.breach).toBe(true);
    expect(verdict.survivors_after).toEqual(["/usr/bin/sleep"]);
    expect(verdict.reaped_descendants).toEqual([]);
  });

  it("lets the sweep add a survivor the accounting missed, never clear one", () => {
    const verdict = composeContainmentVerdict({
      accounting: accounting({
        observed: [{ pid: 41, exe: "/usr/bin/sleep" }],
        observed_count: 1,
        remaining: [{ pid: 41, exe: "/usr/bin/sleep" }],
        remaining_count: 1,
      }),
      aliveAccounted: [{ pid: 41, exe: "/usr/bin/sleep" }],
      sweepSurvivors: ["/tmp/target"],
    });
    expect(verdict.breach).toBe(true);
    expect(verdict.survivors_after).toEqual(["/tmp/target", "/usr/bin/sleep"]);
    expect(verdict.reaped_descendants).toEqual([]);
  });

  it("dedupes and sorts the reaped set across observed and remaining", () => {
    const verdict = composeContainmentVerdict({
      accounting: accounting({
        observed: [
          { pid: 9, exe: "/bin/zeta" },
          { pid: 7, exe: "/bin/alpha" },
        ],
        observed_count: 2,
        remaining: [{ pid: 7, exe: "/bin/alpha" }],
        remaining_count: 1,
      }),
      aliveAccounted: [],
      sweepSurvivors: [],
    });
    expect(verdict.reaped_descendants).toEqual(["/bin/alpha", "/bin/zeta"]);
  });
});

describe("containmentAccountingTruncated", () => {
  it("is false when the stored lists carry the full totals", () => {
    expect(
      containmentAccountingTruncated(
        accounting({
          observed: [{ pid: 1, exe: "/bin/a" }],
          observed_count: 1,
        }),
      ),
    ).toBe(false);
  });

  it("is true when either count exceeds its stored list", () => {
    expect(
      containmentAccountingTruncated(accounting({ observed_count: 5000 })),
    ).toBe(true);
    expect(
      containmentAccountingTruncated(accounting({ remaining_count: 5000 })),
    ).toBe(true);
  });
});
