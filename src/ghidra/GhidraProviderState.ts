import type { GhidraInstallationInspection } from "./GhidraInstallation.js";

/**
 * Observable Ghidra provider state, replacing the flat available/unavailable
 * split at surfaces that report engine readiness. `absent` means no verified
 * installation is configured; `loading` means a worker session is starting or
 * analyzing; `ready` means the engine is installed and able to serve a job.
 */
export type GhidraProviderState = "absent" | "loading" | "ready";

/** What the worker is doing when the state is projected. */
export type GhidraWorkerActivity =
  | "none"
  | "starting"
  | "analyzing"
  | "settled";

/**
 * Project the three provider states from installation availability and live
 * worker activity. An unavailable installation is always `absent`, whatever
 * the worker last did; a starting or analyzing worker is `loading`; anything
 * else with a verified installation is `ready`.
 */
export const ghidraProviderState = (input: {
  readonly installationAvailable: boolean;
  readonly activity: GhidraWorkerActivity;
}): GhidraProviderState => {
  if (!input.installationAvailable) return "absent";
  if (input.activity === "starting" || input.activity === "analyzing")
    return "loading";
  return "ready";
};

/** Project the state from a completed installation inspection. */
export const ghidraProviderStateForInspection = (
  inspection: GhidraInstallationInspection,
  activity: GhidraWorkerActivity,
): GhidraProviderState =>
  ghidraProviderState({
    installationAvailable: inspection.status === "available",
    activity,
  });
