import { appendFileSync } from 'node:fs';
import type { ScannerReport } from './lib/metadata.ts';
import type { ScannerName } from './lib/redact/types.ts';

export interface SummaryData {
  mode: string;
  scanners: Partial<Record<ScannerName, ScannerReport>>;
  findingsUploaded: number | null;
  uploadId: string | null;
  uploadNote: string;
  gateResult: string;
}

const esc = (s: string) => s.replace(/[|\\`*_<>[\]]/g, (c) => `\\${c}`).replace(/\r?\n/g, ' ');

export function renderSummary(d: SummaryData): string {
  const rows = (Object.entries(d.scanners) as [ScannerName, ScannerReport][])
    .map(([name, r]) => `| ${name} | ${esc(r.version ?? 'unknown')} | ${r.status} | ${r.status === 'ok' ? r.findings : '-'} |`)
    .join('\n');
  return [
    '## OneQueue Scan',
    '',
    '| Scanner | Version | Status | Findings |',
    '| --- | --- | --- | --- |',
    rows || '| (none) | | | |',
    '',
    `- **Mode:** ${esc(d.mode)}`,
    `- **Findings uploaded:** ${d.findingsUploaded ?? 'none (upload skipped or failed)'}`,
    `- **Upload ID:** ${d.uploadId ? `\`${d.uploadId.replace(/`/g, '')}\`` : 'none'}${d.uploadNote ? ` (${esc(d.uploadNote)})` : ''}`,
    `- **Gate result:** ${esc(d.gateResult)}`,
    '',
    '_Only redacted findings are uploaded. Source code never leaves the runner._',
    '',
  ].join('\n');
}

export function writeSummary(env: NodeJS.ProcessEnv, d: SummaryData): void {
  const path = env.GITHUB_STEP_SUMMARY;
  if (!path) return;
  appendFileSync(path, renderSummary(d));
}

export function setOutputs(env: NodeJS.ProcessEnv, outputs: Record<string, string>): void {
  const path = env.GITHUB_OUTPUT;
  if (!path) return;
  // Values are short, single-line and validated, so the simple form is safe.
  const lines = Object.entries(outputs).map(([k, v]) => `${k}=${v.replace(/[\r\n]/g, ' ')}`);
  appendFileSync(path, `${lines.join('\n')}\n`);
}
