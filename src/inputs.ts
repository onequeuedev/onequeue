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
}

export interface ParsedInputs {
  inputs: Inputs;
  /** Problems found. In gate mode these are fatal; in upload mode they are warnings. */
  problems: string[];
  /** Set when the input is unusable in any mode (e.g. unknown mode). */
  fatal?: string;
}

export const DEFAULT_API_URL = 'https://api.onequeue.dev';

/** Docker actions receive inputs as INPUT_<NAME> with the hyphen kept. */
export function getInput(env: NodeJS.ProcessEnv, name: string): string {
  return (env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] ?? '').trim();
}

export function parseInputs(env: NodeJS.ProcessEnv): ParsedInputs {
  const problems: string[] = [];

  const modeRaw = getInput(env, 'mode').toLowerCase() || 'upload';
  if (modeRaw !== 'upload' && modeRaw !== 'gate') {
    return {
      inputs: defaults(env),
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
  };
}
