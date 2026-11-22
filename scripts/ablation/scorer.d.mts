export interface ClaimSet {
  items: Set<string>;
  outputs: Map<string, string>;
}

export interface TruthFile {
  strings: string[];
  loaded_modules: string[];
  resolved_symbols: string[];
  executed_functions: Record<string, string[]>;
  call_edges: Record<string, [string, string][]>;
  outputs: Record<string, string>;
  function_markers: Record<string, string>;
}

export interface ScoreRow {
  truth: number;
  claimed: number;
  recovered: number;
  missed: number;
  false_claims: number;
  success: number;
  fp_rate: number | null;
}

export declare const truthItems: (truth: TruthFile) => Set<string>;
export declare const truthOutputStimuli: (truth: TruthFile) => string[];
export declare const scoreClaims: (
  truth: TruthFile,
  claims: ClaimSet,
) => ScoreRow;
export declare const median: (values: number[]) => number;

export interface TargetScoreRow {
  target_id: string;
  class: string;
  static: ScoreRow;
  dynamic: ScoreRow;
  static_wall_ms: number;
  dynamic_wall_ms: number;
  static_peak_rss_bytes: number;
  dynamic_peak_rss_bytes: number;
}

export interface AggregateRow {
  static: ScoreRow;
  dynamic: ScoreRow;
  static_wall_ms: number;
  dynamic_wall_ms: number;
  static_peak_rss_bytes: number;
  dynamic_peak_rss_bytes: number;
  targets: number;
}

export interface BenchmarkAggregate {
  classes: Record<string, AggregateRow>;
  overall: AggregateRow;
}

export declare const aggregateBenchmark: (
  perTarget: TargetScoreRow[],
) => BenchmarkAggregate;

export interface DecisionInputs {
  gain_points: number;
  dynamic_fp_rate: number | null;
  wall_ratio: number;
  class_gains_points: Record<string, number>;
  classes_with_gain_at_least_25: number;
  containment_ok: boolean;
}

export declare const applyDecisionRule: (
  aggregate: BenchmarkAggregate,
  containmentOk: boolean,
) => { verdict: string; inputs: DecisionInputs; reasons: string[] };
