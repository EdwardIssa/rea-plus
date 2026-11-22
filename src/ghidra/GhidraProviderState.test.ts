import { describe, expect, it } from "vitest";

import {
  ghidraProviderState,
  ghidraProviderStateForInspection,
} from "./GhidraProviderState.js";
import type { GhidraInstallationInspection } from "./GhidraInstallation.js";

describe("ghidraProviderState", () => {
  it("reports absent whenever the installation is unavailable", () => {
    for (const activity of ["none", "starting", "analyzing", "settled"] as const)
      expect(ghidraProviderState({ installationAvailable: false, activity })).toBe(
        "absent",
      );
  });

  it("reports loading while a worker is starting or analyzing", () => {
    expect(
      ghidraProviderState({ installationAvailable: true, activity: "starting" }),
    ).toBe("loading");
    expect(
      ghidraProviderState({ installationAvailable: true, activity: "analyzing" }),
    ).toBe("loading");
  });

  it("reports ready when the engine is installed and no job is in flight", () => {
    expect(
      ghidraProviderState({ installationAvailable: true, activity: "none" }),
    ).toBe("ready");
    expect(
      ghidraProviderState({ installationAvailable: true, activity: "settled" }),
    ).toBe("ready");
  });

  it("drives the absent to loading to ready transition from one inspection", () => {
    const inspection = { status: "available" } as GhidraInstallationInspection;
    const missing = { status: "unavailable" } as GhidraInstallationInspection;
    expect(ghidraProviderStateForInspection(missing, "none")).toBe("absent");
    expect(ghidraProviderStateForInspection(inspection, "starting")).toBe(
      "loading",
    );
    expect(ghidraProviderStateForInspection(inspection, "settled")).toBe(
      "ready",
    );
  });
});
