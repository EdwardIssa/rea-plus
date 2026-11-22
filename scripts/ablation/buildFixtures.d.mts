export declare const FIXTURES_ROOT: string;

export interface Stimulus {
  stimulus_id: string;
  argv: string[];
  env: Record<string, string>;
  stdin: string | null;
  timeout_ms: number;
}

export interface ManifestTarget {
  target_id: string;
  class: string;
  containment: boolean;
  binary: string;
  binary_path: string;
  sha256: string;
  plugins: { name: string; sha256: string }[];
  stimuli: Stimulus[];
  truth_path: string;
}

export interface Manifest {
  version: number;
  generated_by: string;
  targets: ManifestTarget[];
}

export declare const buildFixtures: () => Manifest;
export declare const loadManifest: () => Manifest;
export declare const verifyManifest: (manifest: Manifest) => string[];
