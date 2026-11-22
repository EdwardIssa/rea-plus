import { createEvidence, type Evidence } from "../../../src/domain/evidence.js";

/** The subject digest every authored runtime record in the boundary suites shares. */
export const RUNTIME_FIXTURE_SUBJECT_SHA = "ab".repeat(32);

const HOOKED = ["puts", "fputs", "printf", "fprintf", "write", "exit"];

export interface RuntimeRecordOptions {
  readonly argv?: readonly string[];
  readonly envSet?: Readonly<Record<string, string>>;
  readonly filed?: readonly string[];
  readonly logTexts?: readonly string[];
  readonly pid?: number;
  readonly limitations?: readonly string[];
  /** Subject digest override, for records that must join a real artifact's group. */
  readonly subjectSha?: string;
}

/**
 * Author one authenticated execute_dynamically Evidence record in memory:
 * the filed rows and the preserved raw hook log agree unless logTexts
 * overrides the log, exactly as a real run's record would carry them.
 */
export const runtimeEvidenceRecord = (
  options: RuntimeRecordOptions,
): Evidence => {
  const filed = (options.filed ?? []).map((value) => ({
    value,
    channel: "puts",
  }));
  const texts = options.logTexts ?? options.filed ?? [];
  return createEvidence(
    {
      path: "/fixtures/target",
      sha256: options.subjectSha ?? RUNTIME_FIXTURE_SUBJECT_SHA,
      format: "elf",
    },
    { id: "frida", name: "Frida", version: "17.23.2" },
    {
      operation: "execute_dynamically",
      parameters: {
        target_path: "/fixtures/target",
        argv: options.argv ?? [],
        env_set: options.envSet ?? {},
        session_timeout_ms: 30000,
        deadline_ms: 75000,
        rss_cap_bytes: 3221225472,
        evidence_path: "/tmp/e.json",
      },
      result: {
        strings: filed,
        modules: [],
        symbols: [],
        output: { stdout: "", stderr: "", exit_code: 0 },
        execution: {
          hook_pack_version: "1.1.0",
          frida_version: "17.23.2",
          target_pid: options.pid ?? 4242,
          resume_observed: true,
          pack_ready: { hooked: HOOKED, missing: [] },
          supervisor: {
            reason: "exited",
            peak_rss_bytes: 1000,
            wall_ms: 40 + (options.pid ?? 0),
          },
          budgets: {
            session_timeout_ms: 30000,
            deadline_ms: 75000,
            rss_cap_bytes: 3221225472,
          },
          containment: {
            verified: true,
            source: "subreaper_accounting",
            survivors_after: [],
            breach: false,
            reaped_descendants: [],
          },
        },
      },
      rawResult: [
        {
          type: "send",
          payload: {
            t: "pack_ready",
            version: "1.1.0",
            hooked: HOOKED,
            missing: [],
          },
        },
        ...texts.map((text) => ({
          type: "send",
          payload: { t: "puts", text },
        })),
      ],
      confidence: "observed",
      authority: "controlled-replay",
      limitations: options.limitations ?? [],
      evidenceLinks: [],
    },
  );
};
