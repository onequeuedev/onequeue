import { describe, expect, it } from 'vitest';
import { decide, type GateInput } from '../src/lib/gate.ts';

const base: GateInput = { mode: 'gate', onTimeout: 'pass', gitleaksFindings: 0, server: { kind: 'uploaded' } };
const pass = { kind: 'verdict', verdict: { status: 'pass' } } as const;
const fail = { kind: 'verdict', verdict: { status: 'fail', reason: 'too many criticals' } } as const;

describe('decide', () => {
  it.each([
    ['upload mode never fails', { mode: 'upload', server: { kind: 'upload-failed', message: 'x' }, gitleaksFindings: 5 }, 0],
    ['verdict pass', { server: pass }, 0],
    ['verdict fail', { server: fail }, 1],
    ['timeout + pass', { server: { kind: 'timeout' } }, 0],
    ['timeout + fail', { server: { kind: 'timeout' }, onTimeout: 'fail' }, 1],
    ['verdict error + fail', { server: { kind: 'error', message: '404' }, onTimeout: 'fail' }, 1],
    ['upload failed + pass', { server: { kind: 'upload-failed', message: '500' } }, 0],
    ['skipped (no key), clean', { server: { kind: 'skipped', reason: 'no key' } }, 0],
    ['gitleaks overrides pass', { server: pass, gitleaksFindings: 1 }, 1],
    ['gitleaks with no key', { server: { kind: 'skipped', reason: 'no key' }, gitleaksFindings: 1 }, 1],
    ['gitleaks did not run', { server: pass, gitleaksFindings: undefined }, 0],
  ] as [string, Partial<GateInput>, number][])('%s', (_name, patch, code) => {
    expect(decide({ ...base, ...patch }).exitCode).toBe(code);
  });

  it('includes the server reason in the failure message', () => {
    expect(decide({ ...base, server: fail }).messages[0]!.text).toContain('too many criticals');
  });
});
