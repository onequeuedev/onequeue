import type { ScannerName } from '../redact/types.ts';

export interface CommandResult {
  exitCode: number | null;
  /** Last few KB of stderr. Untrusted: print only via Logger.untrusted. */
  stderrTail: string;
  /** Set when the process could not be started or was killed. */
  spawnError?: string;
}

export interface RunCommandOptions {
  cwd: string;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
}

export type RunCommand = (cmd: string, args: string[], opts: RunCommandOptions) => Promise<CommandResult>;

export interface ScanContext {
  workspace: string;
  /** Private temp dir (0700) for raw SARIF. Deleted after the run. */
  outDir: string;
  env: NodeJS.ProcessEnv;
  runCommand: RunCommand;
  timeoutMs: number;
  semgrepConfigs: string[];
  gitleaksHistory: boolean;
}

export interface ScannerDefinition {
  name: ScannerName;
  /** Exit codes that mean "ran successfully" (findings or not). */
  okExitCodes: number[];
  command(ctx: ScanContext, sarifPath: string): { cmd: string; args: string[]; env?: NodeJS.ProcessEnv };
  /** Version baked into the image, if known. */
  imageVersion(env: NodeJS.ProcessEnv): string | undefined;
}

export interface ScanOutcome {
  name: ScannerName;
  ok: boolean;
  /** Parsed raw SARIF (unredacted). Only held in memory. */
  sarif?: unknown;
  version?: string;
  error?: string;
  durationMs: number;
}
