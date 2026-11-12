import type { ScannerName } from '../redact/types.ts';
import type { ScannerDefinition } from './types.ts';

export const trivy: ScannerDefinition = {
  name: 'trivy',
  okExitCodes: [0],
  command: (ctx, sarifPath) => ({
    cmd: 'trivy',
    args: [
      'fs',
      // Secret scanning is Gitleaks' job; Trivy secret results contain "Match:" lines.
      '--scanners',
      'vuln,misconfig',
      '--format',
      'sarif',
      '--output',
      sarifPath,
      '--quiet',
      '--skip-dirs',
      '.git',
      '--exit-code',
      '0',
      '--disable-telemetry',
      ctx.workspace,
    ],
    env: { TRIVY_DISABLE_TELEMETRY: 'true' },
  }),
  imageVersion: (env) => env.ONEQUEUE_TRIVY_VERSION,
};

export const semgrep: ScannerDefinition = {
  name: 'semgrep',
  // 0 = ok; Semgrep only uses 1 with --error, which we do not pass.
  okExitCodes: [0, 1],
  command: (ctx, sarifPath) => ({
    cmd: 'semgrep',
    args: [
      'scan',
      ...ctx.semgrepConfigs.flatMap((c) => ['--config', c]),
      '--metrics=off',
      '--disable-version-check',
      '--sarif',
      '--output',
      sarifPath,
      '--quiet',
      ctx.workspace,
    ],
    env: { SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0' },
  }),
  imageVersion: (env) => env.ONEQUEUE_SEMGREP_VERSION,
};

export const gitleaks: ScannerDefinition = {
  name: 'gitleaks',
  okExitCodes: [0],
  command: (ctx, sarifPath) => ({
    cmd: 'gitleaks',
    args: [
      ctx.gitleaksHistory ? 'git' : 'dir',
      ctx.workspace,
      '--report-format',
      'sarif',
      '--report-path',
      sarifPath,
      // Findings are read from the report; a non-zero exit would look like a crash.
      '--exit-code',
      '0',
      '--no-banner',
      '--log-level',
      'error',
    ],
    // The workspace is owned by the runner user, not the container's root.
    env: { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'safe.directory', GIT_CONFIG_VALUE_0: '*' },
  }),
  imageVersion: (env) => env.ONEQUEUE_GITLEAKS_VERSION,
};

export const SCANNERS: Record<ScannerName, ScannerDefinition> = { trivy, semgrep, gitleaks };
export const SCANNER_NAMES: readonly ScannerName[] = ['trivy', 'semgrep', 'gitleaks'];
