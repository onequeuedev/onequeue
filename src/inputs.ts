import { isAbsolute, normalize, sep } from 'node:path';
import { validateApiUrl } from './lib/client.ts';
import type { Mode, OnTimeout } from './lib/gate.ts';
import type { ScannerName } from './lib/redact/types.ts';
import { SCANNER_NAMES } from './lib/scanners/definitions.ts';

export type FailOn = 'critical' | 'high' | 'none';

export interface Inputs {
  apiKey: string;
  apiUrl: string;
  scanners: ScannerName[];
  mode: Mode;
  failOn: FailOn;
  gateTimeoutSec: number;
  onTimeout: OnTimeout;
  semgrepConfigs: string[];
  gitleaksHistory: boolean;
  /** Write the envelope to outputFile instead of uploading; never fail the build. */
  dryRun: boolean;
  /** Dry-run output path, relative to the workspace (validated: no absolute paths, no ..). */
  outputFile: string;
}

export interface ParsedInputs {
  inputs: Inputs;
  /** Problems found. In gate mode these are fatal; in upload mode they are warnings. */
  problems: string[];
  /** Set when the input is unusable in any mode (e.g. unknown mode). */
  fatal?: string;
}

/**
 * Default OneQueue API base URL. This is the only place the default is set:
 * action.yml leaves api-url empty so this constant applies. Moving to a custom
 * domain later is a one-line change here.
 */
export const DEFAULT_API_URL = 'https://n3m2eiznc2.execute-api.us-east-1.amazonaws.com';

export const DEFAULT_OUTPUT_FILE = 'onequeue-payload.json';

/** Docker actions receive inputs as INPUT_<NAME> with the hyphen kept. */
export function getInput(env: NodeJS.ProcessEnv, name: string): string {
  return (env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] ?? '').trim();
}

function parseDryRun(env: NodeJS.ProcessEnv, problems: string[]): boolean {
  const raw = getInput(env, 'dry-run').toLowerCase() || 'false';
  if (raw === 'true') return true;
  if (raw !== 'false') problems.push(`Invalid input dry-run="${raw.slice(0, 32)}". Expected true or false.`);
  return false;
}

/**
 * output-file must be a path inside the workspace. This is a Docker action, so
 * only the workspace is shared with later steps; absolute runner paths and ".."
 * would point somewhere else inside the container.
 */
function parseOutputFile(env: NodeJS.ProcessEnv, problems: string[]): string {
  const raw = getInput(env, 'output-file');
  if (!raw) return DEFAULT_OUTPUT_FILE;
  const norm = normalize(raw);
  if (isAbsolute(raw) || norm === '..' || norm.startsWith(`..${sep}`) || norm === '.' || norm.endsWith(sep) || raw.includes('\0')) {
    problems.push(
      `Invalid input output-file="${raw.slice(0, 64)}". Use a file path relative to the workspace, without "..". Using ${DEFAULT_OUTPUT_FILE}.`,
    );
    return DEFAULT_OUTPUT_FILE;
  }
  return norm;
}

export function parseInputs(env: NodeJS.ProcessEnv): ParsedInputs {
  const problems: string[] = [];
  const dryRun = parseDryRun(env, problems);
  const outputFile = parseOutputFile(env, problems);

  const modeRaw = getInput(env, 'mode').toLowerCase() || 'upload';
  if (modeRaw !== 'upload' && modeRaw !== 'gate') {
    return {
      inputs: { ...defaults(env), dryRun, outputFile },
      problems,
      fatal: `Invalid input mode="${modeRaw.slice(0, 32)}". Expected "upload" or "gate".`,
    };
  }
  const mode: Mode = modeRaw;

  const apiUrl = getInput(env, 'api-url') || DEFAULT_API_URL;
  try {
    validateApiUrl(apiUrl);
  } catch (e) {
    problems.push(`Invalid input api-url: ${(e as Error).message}.`);
  }

  const scannersRaw = getInput(env, 'scanners') || 'trivy,semgrep,gitleaks';
  const scanners: ScannerName[] = [];
  for (const s of scannersRaw.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean)) {
    if ((SCANNER_NAMES as readonly string[]).includes(s)) {
      if (!scanners.includes(s as ScannerName)) scanners.push(s as ScannerName);
    } else {
      problems.push(`Unknown scanner "${s.slice(0, 32)}" in input scanners. Valid: ${SCANNER_NAMES.join(', ')}.`);
    }
  }
  if (scanners.length === 0) problems.push('Input scanners enables no scanner.');

  const failOnRaw = getInput(env, 'fail-on').toLowerCase() || 'critical';
  let failOn: FailOn = 'critical';
  if (failOnRaw === 'critical' || failOnRaw === 'high' || failOnRaw === 'none') failOn = failOnRaw;
  else problems.push(`Invalid input fail-on="${failOnRaw.slice(0, 32)}". Expected critical, high or none.`);

  const timeoutRaw = getInput(env, 'gate-timeout') || '30';
  let gateTimeoutSec = 30;
  if (/^\d+$/.test(timeoutRaw) && Number(timeoutRaw) >= 1 && Number(timeoutRaw) <= 3600) gateTimeoutSec = Number(timeoutRaw);
  else problems.push(`Invalid input gate-timeout="${timeoutRaw.slice(0, 32)}". Expected whole seconds between 1 and 3600.`);

  const onTimeoutRaw = getInput(env, 'on-timeout').toLowerCase() || 'pass';
  let onTimeout: OnTimeout = 'pass';
  if (onTimeoutRaw === 'pass' || onTimeoutRaw === 'fail') onTimeout = onTimeoutRaw;
  else problems.push(`Invalid input on-timeout="${onTimeoutRaw.slice(0, 32)}". Expected pass or fail.`);

  const semgrepRaw = getInput(env, 'semgrep-config') || 'p/default';
  const semgrepConfigs = semgrepRaw.split(',').map((s) => s.trim()).filter(Boolean);
  if (semgrepConfigs.some((c) => c.startsWith('-'))) problems.push('Input semgrep-config must not start with "-".');

  const historyRaw = getInput(env, 'gitleaks-history').toLowerCase() || 'false';
  let gitleaksHistory = false;
  if (historyRaw === 'true') gitleaksHistory = true;
  else if (historyRaw !== 'false') problems.push(`Invalid input gitleaks-history="${historyRaw.slice(0, 32)}". Expected true or false.`);

  return {
    inputs: {
      apiKey: getInput(env, 'api-key'),
      apiUrl,
      scanners,
      mode,
      failOn,
      gateTimeoutSec,
      onTimeout,
      semgrepConfigs: semgrepConfigs.filter((c) => !c.startsWith('-')),
      gitleaksHistory,
      dryRun,
      outputFile,
    },
    problems,
  };
}

function defaults(env: NodeJS.ProcessEnv): Inputs {
  return {
    apiKey: getInput(env, 'api-key'),
    apiUrl: DEFAULT_API_URL,
    scanners: [...SCANNER_NAMES],
    mode: 'upload',
    failOn: 'critical',
    gateTimeoutSec: 30,
    onTimeout: 'pass',
    semgrepConfigs: ['p/default'],
    gitleaksHistory: false,
    dryRun: false,
    outputFile: DEFAULT_OUTPUT_FILE,
  };
}
