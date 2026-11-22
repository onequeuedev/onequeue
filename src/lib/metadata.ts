/**
 * Run metadata sent with an upload. Read from GITHUB_* variables and the
 * pull_request number from the event file. Nothing else from the event payload
 * or the environment is sent.
 */
import { readFileSync } from 'node:fs';
import { scrubText } from './redact/scrub.ts';
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

/** Something this run did not cover, in words and names only: a scanner that failed or was off, a base image that was not scanned. */
export interface CoverageGap {
  type: 'scanner_failed' | 'scanner_skipped' | 'base_image_not_scanned';
  /** The scanner's name, or the image reference. */
  detail: string;
  /** A short plain reason ("exited with code 2", "not enabled in the scanners input"). */
  reason?: string;
}

export interface UploadMetadata {
  repository: string;
  sha: string;
  ref: string;
  eventName: string;
  /** The repository's default branch, from the GitHub event (absent when the event does not carry it). */
  defaultBranch?: string;
  pullRequest: PullRequestInfo | null;
  runId: string;
  runAttempt: string;
  runUrl: string;
  actionVersion: string;
  scanners: Partial<Record<ScannerName, ScannerReport>>;
  coverage: CoverageGap[];
}

const BRANCH = /^[A-Za-z0-9._\/-]{1,255}$/;
const SHA = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const clean = (v: string | undefined, max = 256): string => (v ?? '').replace(/[\u0000-\u001F\u007F]/g, '').slice(0, max);

/** The default branch named by the event payload (push, schedule and pull_request events all carry `repository.default_branch`). */
export function readDefaultBranch(env: NodeJS.ProcessEnv): string | undefined {
  const path = env.GITHUB_EVENT_PATH;
  if (!path) return undefined;
  try {
    const b = JSON.parse(readFileSync(path, 'utf8'))?.repository?.default_branch;
    return typeof b === 'string' && BRANCH.test(b) && !b.includes('..') ? b : undefined;
  } catch {
    return undefined;
  }
}

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
  if (typeof pr?.head?.ref === 'string') info.headRef = scrubText(clean(pr.head.ref), { maxLen: 256 });
  if (typeof pr?.base?.ref === 'string') info.baseRef = scrubText(clean(pr.base.ref), { maxLen: 256 });
  return info;
}

export function buildMetadata(
  env: NodeJS.ProcessEnv,
  actionVersion: string,
  scanners: UploadMetadata['scanners'],
  coverage: CoverageGap[] = [],
): UploadMetadata {
  const repository = clean(env.GITHUB_REPOSITORY);
  const runId = clean(env.GITHUB_RUN_ID, 32);
  const server = clean(env.GITHUB_SERVER_URL) || 'https://github.com';
  return {
    repository,
    sha: SHA.test(env.GITHUB_SHA ?? '') ? env.GITHUB_SHA! : '',
    ref: clean(env.GITHUB_REF),
    eventName: clean(env.GITHUB_EVENT_NAME, 64),
    ...(readDefaultBranch(env) ? { defaultBranch: readDefaultBranch(env)! } : {}),
    pullRequest: readPullRequest(env),
    runId,
    runAttempt: clean(env.GITHUB_RUN_ATTEMPT, 16),
    runUrl: repository && runId ? `${server}/${repository}/actions/runs/${runId}` : '',
    actionVersion,
    scanners,
    coverage: coverage.slice(0, 40).map((c) => ({ type: c.type, detail: scrubText(clean(c.detail, 200), { maxLen: 200, entropy: false }), ...(c.reason ? { reason: scrubText(clean(c.reason, 200), { maxLen: 200 }) } : {}) })),
  };
}
