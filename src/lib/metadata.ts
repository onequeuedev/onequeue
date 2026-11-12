/**
 * Run metadata sent with an upload. Read from GITHUB_* variables and the
 * pull_request number from the event file. Nothing else from the event payload
 * or the environment is sent.
 */
import { readFileSync } from 'node:fs';
import type { ScannerName } from './redact/types.ts';

export interface PullRequestInfo {
  number: number;
  headSha?: string;
  headRef?: string;
  baseRef?: string;
}

export interface ScannerReport {
  version?: string;
  status: 'ok' | 'failed' | 'skipped';
  findings: number;
}

export interface UploadMetadata {
  repository: string;
  sha: string;
  ref: string;
  eventName: string;
  pullRequest: PullRequestInfo | null;
  runId: string;
  runAttempt: string;
  runUrl: string;
  actionVersion: string;
  scanners: Partial<Record<ScannerName, ScannerReport>>;
}

const SHA = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const clean = (v: string | undefined, max = 256): string => (v ?? '').replace(/[\u0000-\u001F\u007F]/g, '').slice(0, max);

export function readPullRequest(env: NodeJS.ProcessEnv): PullRequestInfo | null {
  const path = env.GITHUB_EVENT_PATH;
  if (!path) return null;
  let event: any;
  try {
    event = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
  const pr = event?.pull_request;
  const number = pr?.number ?? (typeof event?.number === 'number' && pr ? event.number : undefined);
  if (typeof number !== 'number' || !Number.isInteger(number) || number <= 0) return null;
  const info: PullRequestInfo = { number };
  if (typeof pr?.head?.sha === 'string' && SHA.test(pr.head.sha)) info.headSha = pr.head.sha;
  if (typeof pr?.head?.ref === 'string') info.headRef = clean(pr.head.ref);
  if (typeof pr?.base?.ref === 'string') info.baseRef = clean(pr.base.ref);
  return info;
}

export function buildMetadata(
  env: NodeJS.ProcessEnv,
  actionVersion: string,
  scanners: UploadMetadata['scanners'],
): UploadMetadata {
  const repository = clean(env.GITHUB_REPOSITORY);
  const runId = clean(env.GITHUB_RUN_ID, 32);
  const server = clean(env.GITHUB_SERVER_URL) || 'https://github.com';
  return {
    repository,
    sha: SHA.test(env.GITHUB_SHA ?? '') ? env.GITHUB_SHA! : '',
    ref: clean(env.GITHUB_REF),
    eventName: clean(env.GITHUB_EVENT_NAME, 64),
    pullRequest: readPullRequest(env),
    runId,
    runAttempt: clean(env.GITHUB_RUN_ATTEMPT, 16),
    runUrl: repository && runId ? `${server}/${repository}/actions/runs/${runId}` : '',
    actionVersion,
    scanners,
  };
}
