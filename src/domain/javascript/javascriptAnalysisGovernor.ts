/**
 * Analysis governor for partitioned bundle analysis, modeled on the
 * disagreement-and-degradation pattern: per-module signals feed a small
 * state machine that can degrade individual modules to structural-only
 * analysis and, when degradation is widespread, halt semantic expansion for
 * the rest of the file. Thresholds require sustained tripping (a window of
 * recent modules), never a single spike, and halting is sticky so a file
 * cannot oscillate between modes.
 */

export type JavaScriptGovernorMode = "nominal" | "degraded" | "halt";

/** Signals observed from one module's static (structural) phase. */
export interface JavaScriptGovernorStaticSignals {
  /** The static phase recorded a resource limit for this module. */
  readonly limited: boolean;
  /** The static phase exhausted its per-module time budget. */
  readonly timedOut: boolean;
  /** The static phase consumed most of its per-module time budget. */
  readonly slow: boolean;
}

/** The governor's decision for one module's semantic phase. */
export interface JavaScriptGovernorDecision {
  readonly mode: JavaScriptGovernorMode;
  readonly runSemantic: boolean;
  /** Why the module degraded, when it did. */
  readonly reason: string | null;
}

/** One module the governor degraded, with the signals that caused it. */
export interface JavaScriptGovernorDegradation {
  readonly moduleKey: string | null;
  readonly reason: string;
}

/** Recent modules considered when judging whether tripping is sustained. */
export const GOVERNOR_WINDOW_SIZE = 10;
/** Tripping modules inside the window required before degradation starts. */
export const GOVERNOR_SUSTAINED_TRIPS = 2;
/** Modules that must settle before a file-level halt can engage. */
export const GOVERNOR_HALT_MIN_SETTLED = 8;
/** Degraded share of settled modules at which a file-level halt engages. */
export const GOVERNOR_HALT_DEGRADED_SHARE = 0.5;

interface ModuleRecord {
  readonly moduleKey: string | null;
  trips: number;
  degraded: boolean;
}

const signalReasons = (
  signals: JavaScriptGovernorStaticSignals,
  disagreement: boolean,
): string[] => [
  ...(signals.limited ? ["static resource limit"] : []),
  ...(signals.timedOut ? ["static time budget exhausted"] : []),
  ...(signals.slow && !signals.timedOut
    ? ["static phase near its time budget"]
    : []),
  ...(disagreement ? ["structural/semantic disagreement"] : []),
];

/** Per-file governor state; one instance serves one partitioned source. */
export class JavaScriptAnalysisGovernor {
  readonly #window: ModuleRecord[] = [];
  readonly #degradations: JavaScriptGovernorDegradation[] = [];
  #settled = 0;
  #degraded = 0;
  #halted = false;
  #haltedModules = 0;

  /**
   * Decide whether this module's semantic phase runs, from its static
   * signals and the recent window. The prelude (moduleKey null) always runs:
   * it carries the bundle runtime and is exempt from degradation.
   */
  observeStatic(
    moduleKey: string | null,
    signals: JavaScriptGovernorStaticSignals,
  ): JavaScriptGovernorDecision {
    if (moduleKey === null)
      return { mode: "nominal", runSemantic: true, reason: null };
    const trips =
      (signals.limited ? 1 : 0) +
      (signals.timedOut ? 1 : 0) +
      (signals.slow ? 1 : 0);
    const record: ModuleRecord = { moduleKey, trips, degraded: false };
    this.#window.push(record);
    if (this.#window.length > GOVERNOR_WINDOW_SIZE) this.#window.shift();
    if (this.#halted) {
      record.degraded = true;
      this.#haltedModules += 1;
      return {
        mode: "halt",
        runSemantic: false,
        reason:
          "semantic analysis halted for this file after sustained module degradation",
      };
    }
    const windowTrips = this.#window.reduce(
      (total, entry) => total + (entry.trips > 0 ? 1 : 0),
      0,
    );
    if (trips > 0 && windowTrips >= GOVERNOR_SUSTAINED_TRIPS) {
      record.degraded = true;
      this.#degraded += 1;
      const reason = `governor degradation: ${signalReasons(signals, false).join(", ")}`;
      this.#degradations.push({ moduleKey, reason });
      return { mode: "degraded", runSemantic: false, reason };
    }
    return { mode: "nominal", runSemantic: true, reason: null };
  }

  /**
   * Record a module's semantic outcome. Disagreement between the structural
   * and semantic views of the same module counts as a trip for the window,
   * then the module settles and the file-level halt is re-evaluated.
   */
  observeSemantic(moduleKey: string | null, disagreement: boolean): void {
    if (moduleKey !== null && disagreement) {
      const record = this.#window.findLast(
        (entry) => entry.moduleKey === moduleKey,
      );
      if (record !== undefined && record.trips === 0) record.trips = 1;
    }
    this.#settle();
  }

  /** Settle a module that was degraded before its semantic phase. */
  settleDegraded(moduleKey: string | null): void {
    void moduleKey;
    this.#settle();
  }

  #settle(): void {
    this.#settled += 1;
    if (
      !this.#halted &&
      this.#settled >= GOVERNOR_HALT_MIN_SETTLED &&
      this.#degraded / this.#settled >= GOVERNOR_HALT_DEGRADED_SHARE
    )
      this.#halted = true;
  }

  /** The file's current mode: halt is sticky, degraded is cumulative. */
  fileMode(): JavaScriptGovernorMode {
    if (this.#halted) return "halt";
    return this.#degraded > 0 ? "degraded" : "nominal";
  }

  /** Every module degraded so far, in decision order. */
  degradations(): readonly JavaScriptGovernorDegradation[] {
    return this.#degradations;
  }

  /** Modules whose semantic phase was skipped under an engaged halt. */
  haltedModules(): number {
    return this.#haltedModules;
  }

  /** Analyst-facing summary labels for the file's Evidence. */
  limitations(): readonly string[] {
    if (this.#degradations.length === 0 && !this.#halted) return [];
    const labels: string[] = [];
    if (this.#degradations.length > 0)
      labels.push(
        `Governor degraded ${String(this.#degradations.length)} module(s) to structural-only analysis (sustained per-module signal tripping).`,
      );
    if (this.#halted)
      labels.push(
        `Governor halted semantic analysis for this file; ${String(this.#haltedModules)} further module(s) are structural only.`,
      );
    return labels;
  }
}
