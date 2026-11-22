import type { ClaimSet } from "./scorer.mjs";

export declare const stringItem: (value: string) => string;
export declare const moduleItem: (value: string) => string;
export declare const symbolItem: (value: string) => string;
export declare const functionItem: (name: string, stimulus: string) => string;
export declare const edgeItem: (
  caller: string,
  callee: string,
  stimulus: string,
) => string;

export declare const isPrintableAscii: (value: string) => boolean;
export declare const isContentString: (
  value: string,
  excludedNames: Set<string>,
) => boolean;
export declare const soBasename: (path: string) => string | null;

export interface StaticFacts {
  stringFacts: string[];
  procedureNames: Set<string>;
  symbolNames: Set<string>;
  sectionNames: Set<string>;
  dtNeeded: string[];
  interpBasename: string | null;
  commentStrings?: Set<string>;
  importsDlsym: boolean;
}

export declare const staticClaims: (facts: StaticFacts) => ClaimSet;

export interface Observation {
  texts: string[];
  stdout: string;
  dlopen: { path: string; ok: boolean }[];
  dlsym: { name: string; ok: boolean }[];
}

export declare const dynamicClaims: (
  base: ClaimSet,
  observation: Observation,
  context: { candidateEdges: [string, string][] },
  stimulusId: string,
) => ClaimSet;

export declare const candidateEdges: (
  staticGraph: {
    directEdges: [string, string][];
    xrefEdges: [string, string][];
  },
  observation: { dlsym: { name: string; ok: boolean }[] },
) => [string, string][];
