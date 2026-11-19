import { describe, expect, it } from 'vitest';
import { decide, type GateInput } from '../src/lib/gate.ts';

// Defaults: an api-key is present, so the server verdict decides about secrets.
const base: GateInput = { mode: 'gate', onTimeout: 'pass', gitleaksFindings: 0, secretRule: 'server', localFindings: 0, server: { kind: 'uploaded' } };
const pass = { kind: 'verdict', verdict: { status: 'pass' } } as const;
const fail = { kind: 'verdict', verdict: { status: 'fail', reason: 'too many criticals' } } as const;
const noKey = { kind: 'skipped', reason: 'no key' } as const;

describe('decide', () => {
  it.each([
    ['upload mode never fails', { mode: 'upload', server: { kind: 'upload-failed', message: 'x' }, gitleaksFindings: 5 }, 0],
    ['verdict pass', { server: pass }, 0],
    ['verdict fail', { server: fail }, 1],
    ['timeout + pass', { server: { kind: 'timeout' } }, 0],
    ['timeout + fail', { server: { kind: 'timeout' }, onTimeout: 'fail' }, 1],
    ['verdict error + fail', { server: { kind: 'error', message: '404' }, onTimeout: 'fail' }, 1],
    ['upload failed + pass', { server: { kind: 'upload-failed', message: '500' } }, 0],
    ['skipped (no key), clean', { server: noKey, secretRule: 'workspace' }, 0],
    ['gitleaks did not run', { server: pass, gitleaksFindings: undefined }, 0],
  ] as [string, Partial<GateInput>, number][])('%s', (_name, patch, code) => {
    expect(decide({ ...base, ...patch }).exitCode).toBe(code);
  });

  it('includes the server reason in the failure message', () => {
    expect(decide({ ...base, server: fail }).messages[0]!.text).toContain('too many criticals');
  });
});

describe('secrets with an api-key: the server verdict decides', () => {
  const withLeaks = { ...base, gitleaksFindings: 2 };
  it('a pass verdict passes even though Gitleaks found secrets (baseline, triage and policy allowed them)', () => {
    const d = decide({ ...withLeaks, server: pass });
    expect(d.exitCode).toBe(0);
    expect(d.result).toBe('pass');
    expect(d.messages.some((m) => m.level === 'notice' && /allows them/.test(m.text))).toBe(true);
    expect(d.messages.some((m) => m.level === 'error')).toBe(false);
  });
  it('a fail verdict (for example a new secret) fails with the server reason', () => {
    const d = decide({ ...withLeaks, server: { kind: 'verdict', verdict: { status: 'fail', reason: '1 new secret' } } });
    expect(d.exitCode).toBe(1);
    expect(d.messages[0]!.text).toContain('1 new secret');
  });
  it('without a verdict, on-timeout decides, and the unchecked secrets are called out', () => {
    const pending = decide({ ...withLeaks, server: { kind: 'timeout' } });
    expect(pending.exitCode).toBe(0);
    expect(pending.messages.some((m) => m.level === 'warning' && /could not be checked/.test(m.text))).toBe(true);
    expect(decide({ ...withLeaks, server: { kind: 'timeout' }, onTimeout: 'fail' }).exitCode).toBe(1);
  });
});

describe('secrets without an api-key (fork pull requests)', () => {
  const local = { ...base, server: noKey };
  it('only secrets on lines changed by the PR fail the build', () => {
    const d = decide({ ...local, secretRule: 'changed-lines', gitleaksFindings: 3, localFindings: 1 });
    expect(d.exitCode).toBe(1);
    expect(d.messages.find((m) => m.level === 'error')!.text).toContain('1 secret(s) in lines changed by this pull request');
    expect(d.messages.some((m) => m.level === 'warning' && /2 secret\(s\) outside the lines changed/.test(m.text))).toBe(true);
  });
  it('secrets elsewhere in the workspace only warn', () => {
    const d = decide({ ...local, secretRule: 'changed-lines', gitleaksFindings: 2, localFindings: 0 });
    expect(d.exitCode).toBe(0);
    expect(d.messages.some((m) => m.level === 'error')).toBe(false);
    expect(d.messages.some((m) => m.level === 'warning' && /outside the lines changed/.test(m.text))).toBe(true);
  });
  it('without a diff, every secret in the workspace fails the build', () => {
    const d = decide({ ...local, secretRule: 'workspace', gitleaksFindings: 2, localFindings: 2 });
    expect(d.exitCode).toBe(1);
    expect(d.messages[0]!.text).toContain('2 secret(s) in the workspace');
  });
  it('a clean scan passes', () => {
    expect(decide({ ...local, secretRule: 'changed-lines' }).exitCode).toBe(0);
    expect(decide({ ...local, secretRule: 'workspace' }).exitCode).toBe(0);
  });
});
