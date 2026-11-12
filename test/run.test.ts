import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run, type RunDeps } from '../src/run.ts';
import { assertNoLeak, FAKE_TOKEN, fakeRunner, fixtureText, makeHostile, PLAIN_SECRET, type RecordedCall } from './helpers.ts';
import { SCENARIOS, startMockServer, type MockConfig, type MockServer } from './mock-server.ts';

// Built at runtime so secret scanners do not flag this public repository.
const KEY = ['oq', 'live', 'supersecretkey', '0123456789'].join('_');
const SHA = 'a'.repeat(40);

let server: MockServer | undefined;
let dir: string;
let lines: string[];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'oq-test-'));
  lines = [];
});
afterEach(async () => {
  await server?.close();
  server = undefined;
});

const ws = () => join(dir, 'ws');
const cleanGitleaks = () => JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'gitleaks', rules: [] } }, results: [] }] });

function baseEnv(inputs: Record<string, string>, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const event = join(dir, 'event.json');
  writeFileSync(event, JSON.stringify({ pull_request: { number: 42, head: { sha: 'b'.repeat(40), ref: 'feat' }, base: { ref: 'main' } } }));
  writeFileSync(join(dir, 'summary.md'), '');
  writeFileSync(join(dir, 'output.txt'), '');
  const env: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: ws(),
    GITHUB_REPOSITORY: 'acme/app',
    GITHUB_SHA: SHA,
    GITHUB_REF: 'refs/pull/42/merge',
    GITHUB_EVENT_NAME: 'pull_request',
    GITHUB_EVENT_PATH: event,
    GITHUB_RUN_ID: '987',
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_STEP_SUMMARY: join(dir, 'summary.md'),
    GITHUB_OUTPUT: join(dir, 'output.txt'),
    RUNNER_TEMP: dir,
    ONEQUEUE_ACTION_VERSION: '1.0.0-test',
    ONEQUEUE_TRIVY_VERSION: '0.76.1',
    AWS_SECRET_ACCESS_KEY: PLAIN_SECRET, // must never be uploaded
    ...extra,
  };
  for (const [k, v] of Object.entries(inputs)) env[`INPUT_${k.toUpperCase()}`] = v;
  return env;
}

interface Opts {
  scenario?: MockConfig;
  inputs?: Record<string, string>;
  scans?: Partial<Record<string, string>>;
  calls?: RecordedCall[];
}

async function go(o: Opts = {}): Promise<number> {
  server = await startMockServer({ ...(o.scenario ?? SCENARIOS.accepted), apiKey: KEY });
  let t = 0;
  const deps: RunDeps = {
    env: baseEnv({ 'api-key': KEY, 'api-url': server.url, ...o.inputs }),
    write: (l) => lines.push(l),
    runCommand: fakeRunner(
      o.scans ?? { trivy: fixtureText('trivy', ws()), semgrep: fixtureText('semgrep', ws()), gitleaks: cleanGitleaks() },
      o.calls,
    ),
    sleep: async (ms) => {
      t += ms;
    },
    now: () => t,
    backoffMs: 1,
  };
  return run(deps);
}

const out = () => lines.join('\n');
const summary = () => readFileSync(join(dir, 'summary.md'), 'utf8');
const outputs = () => readFileSync(join(dir, 'output.txt'), 'utf8');
const uploads = () => server!.requests.filter((r) => r.method === 'POST');

describe('upload mode', () => {
  it('uploads redacted findings with metadata and exits 0', async () => {
    expect(await go()).toBe(0);
    expect(uploads()).toHaveLength(1);
    const body = uploads()[0]!.json;
    expect(body.schemaVersion).toBe(1);
    expect(body.mode).toBe('upload');
    expect(body.failOn).toBe('critical');
    expect(body.metadata).toEqual({
      repository: 'acme/app',
      sha: SHA,
      ref: 'refs/pull/42/merge',
      eventName: 'pull_request',
      pullRequest: { number: 42, headSha: 'b'.repeat(40), headRef: 'feat', baseRef: 'main' },
      runId: '987',
      runAttempt: '1',
      runUrl: 'https://github.com/acme/app/actions/runs/987',
      actionVersion: '1.0.0-test',
      scanners: {
        trivy: { status: 'ok', findings: 2, version: '0.76.1' },
        semgrep: { status: 'ok', findings: 1, version: '1.182.1' },
        gitleaks: { status: 'ok', findings: 0 },
      },
    });
    expect(body.sarif.version).toBe('2.1.0');
    expect(body.sarif.runs).toHaveLength(3);
    // No server polling in upload mode
    expect(server!.requests.filter((r) => r.method === 'GET')).toHaveLength(0);
    expect(summary()).toContain('upl_test123');
    expect(summary()).toContain('**Findings uploaded:** 3');
    expect(outputs()).toContain('upload-id=upl_test123');
  });

  it('sends the envelope as raw gzip bytes with Content-Type application/gzip', async () => {
    expect(await go()).toBe(0);
    const req = uploads()[0]!;
    expect(req.headers['content-type']).toBe('application/gzip');
    expect(req.headers['content-encoding']).toBeUndefined();
    expect([...req.raw.subarray(0, 2)]).toEqual([0x1f, 0x8b]);
    expect(req.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(req.headers['idempotency-key']).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('uses one Idempotency-Key per run, reused on every retry', async () => {
    expect(await go({ scenario: SCENARIOS.error500 })).toBe(0);
    expect(uploads()).toHaveLength(4);
    expect(new Set(uploads().map((r) => r.headers['idempotency-key'])).size).toBe(1);
  });

  it('never sends planted secrets, environment variables or source code', async () => {
    const hostile = (t: 'trivy' | 'semgrep' | 'gitleaks') => JSON.stringify(makeHostile(JSON.parse(fixtureText(t, ws())), PLAIN_SECRET));
    expect(await go({ scans: { trivy: hostile('trivy'), semgrep: hostile('semgrep'), gitleaks: hostile('gitleaks') } })).toBe(0);
    expect(uploads()).toHaveLength(1);
    assertNoLeak(uploads()[0]!.body, [FAKE_TOKEN, PLAIN_SECRET, KEY]);
  });

  it('never fails the build when the upload returns 500 (after retries)', async () => {
    expect(await go({ scenario: SCENARIOS.error500 })).toBe(0);
    expect(uploads()).toHaveLength(4);
    expect(out()).toMatch(/::warning::OneQueue upload failed: HTTP 500/);
  });

  it('never fails the build when the API is unreachable', async () => {
    server = await startMockServer(SCENARIOS.accepted);
    const url = server.url;
    await server.close();
    server = undefined;
    const code = await run({
      env: baseEnv({ 'api-key': KEY, 'api-url': url }),
      write: (l) => lines.push(l),
      runCommand: fakeRunner({ trivy: fixtureText('trivy', ws()), semgrep: 'crash', gitleaks: cleanGitleaks() }),
      sleep: async () => {},
      backoffMs: 1,
    });
    expect(code).toBe(0);
    expect(out()).toMatch(/OneQueue upload failed: network error/);
  });

  it('warns but passes when Gitleaks finds secrets', async () => {
    const code = await go({ scans: { trivy: 'nosarif', semgrep: 'nosarif', gitleaks: fixtureText('gitleaks', ws()) } });
    expect(code).toBe(0);
    expect(out()).toMatch(/::warning::Gitleaks found 2 secret\(s\)/);
  });

  it('continues when a scanner crashes and reports it', async () => {
    const code = await go({ scans: { trivy: 'crash', semgrep: fixtureText('semgrep', ws()), gitleaks: 'badjson' } });
    expect(code).toBe(0);
    expect(out()).toMatch(/::warning::trivy failed \(exited with code 2\)\. Continuing/);
    expect(out()).toMatch(/::warning::gitleaks failed \(no valid SARIF output/);
    const body = uploads()[0]!.json;
    expect(body.metadata.scanners.trivy.status).toBe('failed');
    expect(body.metadata.scanners.semgrep.status).toBe('ok');
    expect(body.sarif.runs).toHaveLength(1);
  });

  it('neutralises workflow commands in scanner stderr', async () => {
    await go({ scans: { trivy: 'crash', semgrep: 'nosarif', gitleaks: 'nosarif' } });
    const i = lines.findIndex((l) => l.startsWith('::stop-commands::'));
    const j = lines.findIndex((l) => l.includes('::set-output'));
    const token = lines[i]!.split('::')[2];
    const k = lines.indexOf(`::${token}::`);
    expect(i).toBeGreaterThan(-1);
    expect(j).toBeGreaterThan(i);
    expect(k).toBeGreaterThan(j);
  });

  it('exits 0 even if every scanner fails to start', async () => {
    expect(await go({ scans: {} })).toBe(0);
  });

  it('runs only the enabled scanners', async () => {
    const calls: RecordedCall[] = [];
    await go({ inputs: { scanners: 'semgrep, gitleaks' }, calls });
    expect(calls.map((c) => c.cmd)).toEqual(['semgrep', 'gitleaks']);
  });

  it('passes semgrep-config, metrics off, and gitleaks dir mode by default', async () => {
    const calls: RecordedCall[] = [];
    await go({ inputs: { 'semgrep-config': 'p/owasp-top-ten, .semgrep/rules.yml' }, calls });
    const sg = calls.find((c) => c.cmd === 'semgrep')!;
    expect(sg.args).toEqual(expect.arrayContaining(['--config', 'p/owasp-top-ten', '.semgrep/rules.yml', '--metrics=off']));
    expect(sg.env.SEMGREP_SEND_METRICS).toBe('off');
    const gl = calls.find((c) => c.cmd === 'gitleaks')!;
    expect(gl.args[0]).toBe('dir');
    const tv = calls.find((c) => c.cmd === 'trivy')!;
    expect(tv.args).toEqual(expect.arrayContaining(['--scanners', 'vuln,misconfig']));
  });

  it('uses gitleaks git mode when gitleaks-history is true, and strips author data', async () => {
    const calls: RecordedCall[] = [];
    await go({ inputs: { 'gitleaks-history': 'true' }, calls, scans: { trivy: 'nosarif', semgrep: 'nosarif', gitleaks: fixtureText('gitleaks', ws()) } });
    expect(calls.find((c) => c.cmd === 'gitleaks')!.args[0]).toBe('git');
    const body = uploads()[0]!.body;
    expect(body).not.toMatch(/jane|Jane Dev|commitMessage|4b825dc6|2026-10-01T12/);
  });

  it('cleans up the raw SARIF temp dir', async () => {
    await go();
    expect(readdirSync(dir).filter((f) => f.startsWith('onequeue-'))).toEqual([]);
  });
});

describe('api key handling', () => {
  it('masks the key and never prints it', async () => {
    await go({ scenario: SCENARIOS.error500 });
    expect(lines[0]).toBe(`::add-mask::${KEY}`);
    expect(lines.slice(1).join('\n')).not.toContain(KEY);
  });

  it('empty key (fork PR), upload mode: warns, skips upload, runs only gitleaks, exits 0', async () => {
    const calls: RecordedCall[] = [];
    server = await startMockServer(SCENARIOS.accepted);
    const code = await run({
      env: baseEnv({ 'api-key': '', 'api-url': server.url }),
      write: (l) => lines.push(l),
      runCommand: fakeRunner({ gitleaks: fixtureText('gitleaks', ws()) }, calls),
    });
    expect(code).toBe(0);
    expect(server.requests).toHaveLength(0);
    expect(calls.map((c) => c.cmd)).toEqual(['gitleaks']);
    expect(out()).toMatch(/::warning::OneQueue api-key is empty/);
    expect(out()).not.toContain('::add-mask::');
    expect(summary()).toContain('skipped: no api-key');
  });

  it('empty key, gate mode, clean: exits 0', async () => {
    const code = await run({
      env: baseEnv({ 'api-key': '', mode: 'gate' }),
      write: (l) => lines.push(l),
      runCommand: fakeRunner({ gitleaks: cleanGitleaks() }),
    });
    expect(code).toBe(0);
  });

  it('empty key, gate mode, Gitleaks finding: local hard rule fails the build', async () => {
    const code = await run({
      env: baseEnv({ 'api-key': '', mode: 'gate' }),
      write: (l) => lines.push(l),
      runCommand: fakeRunner({ gitleaks: fixtureText('gitleaks', ws()) }),
    });
    expect(code).toBe(1);
    expect(out()).toMatch(/::error::OneQueue gate failed: Gitleaks found 2 secret/);
    expect(out()).not.toContain(FAKE_TOKEN);
  });
});

describe('gate mode', () => {
  const gate = (extra: Record<string, string> = {}) => ({ mode: 'gate', ...extra });

  it('verdict pass -> exit 0', async () => {
    expect(await go({ scenario: SCENARIOS.pass, inputs: gate() })).toBe(0);
    expect(summary()).toContain('**Gate result:** pass');
    expect(outputs()).toContain('verdict=pass');
  });

  it('verdict fail -> exit 1 with a clear message', async () => {
    expect(await go({ scenario: SCENARIOS.fail, inputs: gate() })).toBe(1);
    expect(out()).toMatch(/::error::OneQueue gate failed: 2 critical findings exceed fail-on=critical \(https:\/\/app\.example\.com/);
  });

  it('sends fail-on to the server', async () => {
    await go({ scenario: SCENARIOS.pass, inputs: gate({ 'fail-on': 'high' }) });
    expect(uploads()[0]!.json.failOn).toBe('high');
    expect(uploads()[0]!.json.mode).toBe('gate');
  });

  it('timeout + on-timeout=pass -> exit 0 with warning', async () => {
    expect(await go({ scenario: SCENARIOS.timeout, inputs: gate({ 'gate-timeout': '6' }) })).toBe(0);
    expect(out()).toMatch(/::warning::OneQueue gate passed without a server verdict: no verdict before gate-timeout/);
    expect(server!.requests.filter((r) => r.method === 'GET')).toHaveLength(3);
  });

  it('timeout + on-timeout=fail -> exit 1', async () => {
    expect(await go({ scenario: SCENARIOS.timeout, inputs: gate({ 'gate-timeout': '4', 'on-timeout': 'fail' }) })).toBe(1);
    expect(out()).toMatch(/::error::OneQueue gate failed: no verdict before gate-timeout \(on-timeout: fail\)/);
  });

  it('upload 500 follows on-timeout (pass)', async () => {
    expect(await go({ scenario: SCENARIOS.error500, inputs: gate() })).toBe(0);
  });

  it('upload 500 follows on-timeout (fail)', async () => {
    expect(await go({ scenario: SCENARIOS.error500, inputs: gate({ 'on-timeout': 'fail' }) })).toBe(1);
  });

  it('Gitleaks finding fails the build even when the server says pass', async () => {
    const scans = { trivy: fixtureText('trivy', ws()), semgrep: fixtureText('semgrep', ws()), gitleaks: fixtureText('gitleaks', ws()) };
    expect(await go({ scenario: SCENARIOS.pass, inputs: gate({ 'fail-on': 'none' }), scans })).toBe(1);
    expect(out()).toMatch(/Gitleaks found 2 secret/);
    assertNoLeak(uploads()[0]!.body);
    assertNoLeak(out());
  });

  it('invalid inputs fail fast in gate mode', async () => {
    expect(await go({ inputs: gate({ 'fail-on': 'medium' }) })).toBe(1);
    expect(uploads()).toHaveLength(0);
  });
});

describe('inputs', () => {
  it('invalid inputs only warn in upload mode', async () => {
    expect(await go({ inputs: { 'fail-on': 'medium', scanners: 'trivy,nope' } })).toBe(0);
    expect(out()).toMatch(/::warning::Unknown scanner "nope"/);
    expect(uploads()).toHaveLength(1);
  });

  it('unknown mode is a configuration error', async () => {
    expect(await go({ inputs: { mode: 'block' } })).toBe(1);
  });

  it('refuses plain http to a non-local API (key would travel in clear text)', async () => {
    expect(await go({ inputs: { 'api-url': 'http://api.example.com', mode: 'gate' } })).toBe(1);
  });
});
