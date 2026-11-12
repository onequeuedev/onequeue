/**
 * The redacted SARIF subset that is uploaded. It is still valid SARIF 2.1.0,
 * but only these fields can exist; they are built from scratch, never copied.
 */

export type ScannerName = 'trivy' | 'semgrep' | 'gitleaks';

export type Level = 'none' | 'note' | 'warning' | 'error';

export interface RedactedRule {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  helpUri?: string;
  properties?: { 'security-severity'?: string };
}

export interface RedactedLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region?: { startLine: number; endLine: number };
  };
}

export interface RedactedResult {
  ruleId: string;
  level: Level;
  message: { text: string };
  locations?: RedactedLocation[];
  properties?: { fixedVersion?: string };
}

export interface RedactedRun {
  tool: {
    driver: {
      name: string;
      version?: string;
      rules: RedactedRule[];
    };
  };
  results: RedactedResult[];
}

export interface RedactionOutput {
  runs: RedactedRun[];
  /** Number of results kept. */
  findings: number;
  /** Number of results dropped (e.g. Trivy secret results). */
  dropped: number;
}
