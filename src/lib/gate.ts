/**
 * Pure decision logic: given what happened, should the step fail?
 */
import type { PollResult } from './client.ts';

export type Mode = 'upload' | 'gate';
export type OnTimeout = 'pass' | 'fail';

export type ServerOutcome =
  | { kind: 'skipped'; reason: string }
  | { kind: 'upload-failed'; message: string }
  | { kind: 'uploaded' }
  | PollResult;

export interface GateInput {
  mode: Mode;
  onTimeout: OnTimeout;
  /** Gitleaks findings, or undefined if Gitleaks did not run successfully. */
  gitleaksFindings: number | undefined;
  server: ServerOutcome;
}

export interface GateDecision {
  exitCode: 0 | 1;
  /** One-word result for the summary and the `verdict` output. */
  result: 'pass' | 'fail' | 'warn' | 'n/a';
  messages: { level: 'notice' | 'warning' | 'error'; text: string }[];
}

export function decide(input: GateInput): GateDecision {
  const messages: GateDecision['messages'] = [];
  const leaks = input.gitleaksFindings ?? 0;

  if (input.mode === 'upload') {
    if (leaks > 0) {
      messages.push({ level: 'warning', text: `Gitleaks found ${leaks} secret(s). Upload mode does not fail the build.` });
    }
    return { exitCode: 0, result: leaks > 0 ? 'warn' : 'n/a', messages };
  }

  let fail = false;
  let warn = false;

  // Local hard rule, independent of the server.
  if (leaks > 0) {
    fail = true;
    messages.push({ level: 'error', text: `OneQueue gate failed: Gitleaks found ${leaks} secret(s) in the workspace. Remove them and rotate the credentials.` });
  }

  const s = input.server;
  const timeoutPolicy = (why: string) => {
    if (input.onTimeout === 'fail') {
      fail = true;
      messages.push({ level: 'error', text: `OneQueue gate failed: ${why} (on-timeout: fail).` });
    } else {
      warn = true;
      messages.push({ level: 'warning', text: `OneQueue gate passed without a server verdict: ${why} (on-timeout: pass).` });
    }
  };

  switch (s.kind) {
    case 'skipped':
      warn = true;
      messages.push({ level: 'warning', text: `Server verdict skipped: ${s.reason}` });
      break;
    case 'upload-failed':
      timeoutPolicy(`upload failed (${s.message})`);
      break;
    case 'uploaded':
      // Gate mode always polls; treat a missing verdict like a timeout.
      timeoutPolicy('no verdict was requested');
      break;
    case 'timeout':
      timeoutPolicy('no verdict before gate-timeout');
      break;
    case 'error':
      timeoutPolicy(`verdict unavailable (${s.message})`);
      break;
    case 'verdict':
      if (s.verdict.status === 'fail') {
        fail = true;
        messages.push({
          level: 'error',
          text: `OneQueue gate failed: ${s.verdict.reason ?? 'the server verdict is fail'}${s.verdict.detailsUrl ? ` (${s.verdict.detailsUrl})` : ''}`,
        });
      } else {
        messages.push({ level: 'notice', text: `OneQueue verdict: pass${s.verdict.reason ? ` (${s.verdict.reason})` : ''}` });
      }
      break;
  }

  return { exitCode: fail ? 1 : 0, result: fail ? 'fail' : warn ? 'warn' : 'pass', messages };
}
