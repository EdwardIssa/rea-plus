export interface ElfMetadata {
  dtNeeded: string[];
  symbolNames: Set<string>;
  sectionNames: string[];
  interp: string | null;
  commentStrings: Set<string>;
}

export declare const readElfMetadata: (binaryPath: string) => ElfMetadata;
export declare const readDtNeeded: (binaryPath: string) => string[];
