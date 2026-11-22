/**
 * JVM heap policy for supervised Ghidra workers. The generic supervisor
 * lives in `src/process/WorkerSupervisor.ts`; only the heap-derived RSS cap
 * policy stays here, where heap semantics belong.
 */

/** Default worker tree RSS cap: the default -Xmx2G heap plus native headroom. */
export const GHIDRA_WORKER_DEFAULT_RSS_CAP_BYTES = 3 * 1024 * 1024 * 1024;

/** Native headroom kept above the configured JVM heap when deriving the cap. */
const HEAP_HEADROOM_BYTES = 512 * 1024 * 1024;

/**
 * Parse a JVM heap value (`2G`, `512M`, `1024K`, or a plain byte count) into
 * bytes. Returns undefined for values that cannot be read exactly, so callers
 * keep the configured cap instead of guessing.
 */
export const parseJvmHeapBytes = (value: string): number | undefined => {
  const match = /^(\d+(?:\.\d+)?)([KMG])?$/iu.exec(value.trim());
  if (match === null) return undefined;
  const amount = Number(match[1]);
  if (!Number.isFinite(amount) || amount <= 0) return undefined;
  const unit = (match[2] ?? "").toUpperCase();
  const multiplier =
    unit === "G"
      ? 1024 * 1024 * 1024
      : unit === "M"
        ? 1024 * 1024
        : unit === "K"
          ? 1024
          : 1;
  return Math.floor(amount * multiplier);
};

/**
 * Resolve the RSS cap for one worker. The cap always stays above the
 * configured JVM heap by the native headroom: a requested cap that would sit
 * at or below the heap is raised, never silently enforced against the heap.
 */
export const resolveGhidraWorkerRssCap = (input: {
  readonly configuredMaxHeap?: string;
  readonly requestedCapBytes?: number;
}): number => {
  const requested =
    input.requestedCapBytes ?? GHIDRA_WORKER_DEFAULT_RSS_CAP_BYTES;
  const heapBytes =
    input.configuredMaxHeap === undefined
      ? undefined
      : parseJvmHeapBytes(input.configuredMaxHeap);
  if (heapBytes === undefined) return requested;
  return Math.max(requested, heapBytes + HEAP_HEADROOM_BYTES);
};
