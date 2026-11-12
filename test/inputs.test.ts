import { describe, expect, it } from 'vitest';
import { getInput, parseInputs } from '../src/inputs.ts';

const env = (inputs: Record<string, string>) =>
  Object.fromEntries(Object.entries(inputs).map(([k, v]) => [`INPUT_${k.toUpperCase()}`, v]));

describe('parseInputs', () => {
  it('reads Docker-style INPUT_ names with hyphens and applies defaults', () => {
    const { inputs, problems, fatal } = parseInputs(env({ 'api-key': '  k  ' }));
    expect(fatal).toBeUndefined();
    expect(problems).toEqual([]);
    expect(inputs).toEqual({
      apiKey: 'k',
      apiUrl: 'https://api.onequeue.dev',
      scanners: ['trivy', 'semgrep', 'gitleaks'],
      mode: 'upload',
      failOn: 'critical',
      gateTimeoutSec: 30,
      onTimeout: 'pass',
      semgrepConfigs: ['p/default'],
      gitleaksHistory: false,
    });
    expect(getInput({ 'INPUT_API-KEY': 'x' }, 'api-key')).toBe('x');
  });

  it('parses every input', () => {
    const { inputs, problems } = parseInputs(
      env({
        'api-key': 'k',
        'api-url': 'https://eu.api.example.com',
        scanners: 'Gitleaks, trivy,gitleaks',
        mode: 'GATE',
        'fail-on': 'high',
        'gate-timeout': '90',
        'on-timeout': 'fail',
        'semgrep-config': 'p/ci, rules/',
        'gitleaks-history': 'true',
      }),
    );
    expect(problems).toEqual([]);
    expect(inputs).toMatchObject({
      apiUrl: 'https://eu.api.example.com',
      scanners: ['gitleaks', 'trivy'],
      mode: 'gate',
      failOn: 'high',
      gateTimeoutSec: 90,
      onTimeout: 'fail',
      semgrepConfigs: ['p/ci', 'rules/'],
      gitleaksHistory: true,
    });
  });

  it.each([
    ['fail-on', 'medium'],
    ['gate-timeout', '0'],
    ['gate-timeout', '1.5'],
    ['gate-timeout', '9999'],
    ['on-timeout', 'maybe'],
    ['gitleaks-history', 'yes'],
    ['scanners', 'snyk'],
    ['semgrep-config', '--dangerous'],
    ['api-url', 'http://api.example.com'],
  ])('reports a problem for %s=%s', (name, value) => {
    expect(parseInputs(env({ [name]: value })).problems.length).toBeGreaterThanOrEqual(1);
  });

  it('treats an unknown mode as fatal', () => {
    expect(parseInputs(env({ mode: 'block' })).fatal).toMatch(/Invalid input mode/);
  });

  it('accepts an empty api-key (forked pull requests)', () => {
    const r = parseInputs(env({ 'api-key': '' }));
    expect(r.inputs.apiKey).toBe('');
    expect(r.problems).toEqual([]);
  });
});
