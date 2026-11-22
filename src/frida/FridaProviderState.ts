/**
 * Observable Frida provider state for dynamic execution, mirroring the
 * Ghidra three-state projection (src/ghidra/GhidraProviderState.ts).
 * `absent` means the lazy binding load failed; `loading` means a run is in
 * flight; `ready` means the binding loads and no run is in flight. Frida
 * has no installation to inspect, so availability is a load outcome.
 */
export type FridaProviderState = "absent" | "loading" | "ready";

/**
 * Project the three provider states from binding availability and run
 * activity. A binding that cannot load is always `absent`, whatever ran
 * before; a run in flight is `loading`; anything else with a loadable
 * binding is `ready`.
 */
export const fridaProviderState = (input: {
  readonly bindingAvailable: boolean;
  readonly runInFlight: boolean;
}): FridaProviderState => {
  if (!input.bindingAvailable) return "absent";
  if (input.runInFlight) return "loading";
  return "ready";
};
