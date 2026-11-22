import { describe, expect, it } from "vitest";

import { fridaProviderState } from "./FridaProviderState.js";

describe("fridaProviderState", () => {
  it("projects absent whenever the binding cannot load", () => {
    expect(
      fridaProviderState({ bindingAvailable: false, runInFlight: false }),
    ).toBe("absent");
    expect(
      fridaProviderState({ bindingAvailable: false, runInFlight: true }),
    ).toBe("absent");
  });

  it("projects loading while a run is in flight", () => {
    expect(
      fridaProviderState({ bindingAvailable: true, runInFlight: true }),
    ).toBe("loading");
  });

  it("projects ready when the binding loads and no run is in flight", () => {
    expect(
      fridaProviderState({ bindingAvailable: true, runInFlight: false }),
    ).toBe("ready");
  });
});
