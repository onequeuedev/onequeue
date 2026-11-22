import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { findBaseImages, parseBaseImages } from '../src/lib/baseimages.ts';
import { readDefaultBranch } from '../src/lib/metadata.ts';
import { redactSarif } from '../src/lib/redact/allowlist.ts';
import { run, type RunDeps } from '../src/run.ts';
import { DEFAULT_API_URL } from '../src/inputs.ts';
import { fakeRunner, fixtureText, FAKE_TOKEN } from './helpers.ts';
import { SCENARIOS, startMockServer, type MockConfig, type MockServer } from './mock-server.ts';

const KEY = ['oq', 'live', 'supersecretkey', '0123456789'].join('_');
const SHA = 'a'.repeat(40);
let dir: string;
let server: MockServer | undefined;
let lines: string[];
const ws = () => join(dir, 'ws');
const clean = () => JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'gitleaks', rules: [] } }, results: [] }] });

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'oq-rel-'));
  mkdirSync(ws(), { recursive: true });
  lines = [];
});
afterEach(async () => {
  await server?.close();
  server = undefined;
});

function env(inputs: Record<string, string>, event: object, eventName = 'pull_request', ref = 'refs/pull/42/merge'): NodeJS.ProcessEnv {
  writeFileSync(join(dir, 'event.json'), JSON.stringify(event));
  writeFileSync(join(dir, 'summary.md'), '');
  writeFileSync(join(dir, 'output.txt'), '');
  const e: NodeJS.ProcessEnv = { GITHUB_WORKSPACE: ws(), GITHUB_REPOSITORY: 'acme/app', GITHUB_SHA: SHA, GITHUB_REF: ref, GITHUB_EVENT_NAME: eventName, GITHUB_EVENT_PATH: join(dir, 'event.json'), GITHUB_RUN_ID: '987', GITHUB_RUN_ATTEMPT: '1', GITHUB_SERVER_URL: 'https://github.com', GITHUB_STEP_SUMMARY: join(dir, 'summary.md'), GITHUB_OUTPUT: join(dir, 'output.txt'), RUNNER_TEMP: dir, ONEQUEUE_ACTION_VERSION: '1.1.0-test' };
  for (const [k, v] of Object.entries(inputs)) e[`INPUT_${k.toUpperCase()}`] = v;
  return e;
}
const PR = { repository: { default_branch: 'main' }, pull_request: { number: 42, head: { sha: 'b'.repeat(40), ref: 'feat' }, base: { ref: 'main', sha: 'c'.repeat(40) } } };

async function go(inputs: Record<string, string>, scenario: MockConfig, opts: { event?: object; eventName?: string; ref?: string; scans?: Record<string, string>; deps?: Partial<RunDeps> } = {}): Promise<number> {
  server = await startMockServer({ ...scenario, apiKey: KEY });
  let t = 0;
  return run({
    env: env({ 'api-key': KEY, 'api-url': server.url, ...inputs }, opts.event ?? PR, opts.eventName, opts.ref),
    write: (l) => lines.push(l),
    runCommand: fakeRunner(opts.scans ?? { trivy: fixtureText('trivy', ws()), semgrep: fixtureText('semgrep', ws()), gitleaks: clean() }),
    sleep: async (ms) => void (t += ms),
    now: () => t,
    backoffMs: 1,
    ...opts.deps,
  });
}
const out = () => lines.join('\n');
const uploads = () => server!.requests.filter((r) => r.method === 'POST');
const payment = { status: 402, body: { error: { code: 'payment_required', message: 'Uploads are paused for this company.' } } };

describe('402 payment required is a warning', () => {
  const scenario: MockConfig = { upload: [payment], verdict: [payment] };
  it('upload mode: warns, exits 0, sends one request and does not retry', async () => {
    expect(await go({}, scenario)).toBe(0);
    expect(uploads()).toHaveLength(1);
    expect(out()).toMatch(/::warning::OneQueue upload skipped: HTTP 402/);
    expect(out()).not.toMatch(/::error::/);
  });
  it('gate mode with on-timeout fail still does not fail the build for it', async () => {
    expect(await go({ mode: 'gate', 'on-timeout': 'fail' }, scenario)).toBe(0);
    expect(readFileSync(join(dir, 'output.txt'), 'utf8')).toContain('verdict=warn');
    expect(readFileSync(join(dir, 'summary.md'), 'utf8')).toMatch(/uploads paused \(HTTP 402\)/);
  });
});

describe('no verdict: secrets fall back to the local rule', () => {
  const noVerdict: MockConfig = { upload: [payment], verdict: [payment] };
  const diff = (file: string, line: number) => `diff --git a/${file} b/${file}\n--- a/${file}\n+++ b/${file}\n@@ -0,0 +${line},1 @@\n+x\n`;
  const leak = (path: string, line: number) => JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'gitleaks', rules: [{ id: 'generic-api-key' }] } }, results: [{ ruleId: 'generic-api-key', level: 'error', message: { text: 'x' }, locations: [{ physicalLocation: { artifactLocation: { uri: path }, region: { startLine: line, endLine: line } } }] }] }] });

  it('a secret on a line the pull request added fails the build', async () => {
    const code = await go({ mode: 'gate' }, noVerdict, { scans: { trivy: clean(), semgrep: clean(), gitleaks: leak('src/a.ts', 3) }, deps: { gitDiff: async () => diff('src/a.ts', 3) } });
    expect(code).toBe(1);
    expect(out()).toMatch(/::error::OneQueue gate failed: Gitleaks found 1 secret\(s\) in lines changed by this pull request/);
  });
  it('an older secret elsewhere only warns', async () => {
    const code = await go({ mode: 'gate' }, noVerdict, { scans: { trivy: clean(), semgrep: clean(), gitleaks: leak('src/old.ts', 9) }, deps: { gitDiff: async () => diff('src/a.ts', 3) } });
    expect(code).toBe(0);
    expect(out()).toMatch(/::warning::Gitleaks also found 1 secret\(s\) outside the lines changed/);
  });
  it('when the diff cannot be read it only warns that the secret could not be checked', async () => {
    const code = await go({ mode: 'gate' }, noVerdict, { scans: { trivy: clean(), semgrep: clean(), gitleaks: leak('src/a.ts', 3) }, deps: { gitDiff: async () => { throw new Error('no base'); } } });
    expect(code).toBe(0);
    expect(out()).toMatch(/could not be checked against the baseline/);
  });
  it('with a verdict the server still decides alone (no local rule)', async () => {
    const code = await go({ mode: 'gate' }, SCENARIOS.pass, { scans: { trivy: clean(), semgrep: clean(), gitleaks: leak('src/a.ts', 3) }, deps: { gitDiff: async () => diff('src/a.ts', 3) } });
    expect(code).toBe(0);
  });
});

describe('metadata: defaultBranch, schedule events and coverage gaps', () => {
  it('sends the default branch from the event, also for a schedule run', async () => {
    const event = { repository: { default_branch: 'trunk' }, schedule: '0 3 * * *' };
    expect(await go({}, SCENARIOS.accepted, { event, eventName: 'schedule', ref: 'refs/heads/trunk' })).toBe(0);
    const md = uploads()[0]!.json.metadata;
    expect(md).toMatchObject({ eventName: 'schedule', ref: 'refs/heads/trunk', defaultBranch: 'trunk', pullRequest: null });
    expect(uploads()[0]!.json.mode).toBe('upload');
  });
  it('a schedule run in gate mode is still uploaded with its event name', async () => {
    expect(await go({ mode: 'gate' }, SCENARIOS.pass, { event: { repository: { default_branch: 'main' } }, eventName: 'schedule', ref: 'refs/heads/main' })).toBe(0);
    expect(uploads()[0]!.json.metadata.eventName).toBe('schedule');
  });
  it('leaves defaultBranch out when the event does not carry it, or it is not a branch name', () => {
    for (const [i, ev] of [{}, { repository: {} }, { repository: { default_branch: 'a b; rm -rf /' } }, { repository: { default_branch: '../x' } }].entries()) {
      writeFileSync(join(dir, `e${i}.json`), JSON.stringify(ev));
      expect(readDefaultBranch({ GITHUB_EVENT_PATH: join(dir, `e${i}.json`) })).toBeUndefined();
    }
    expect(readDefaultBranch({})).toBeUndefined();
  });
  it('reports scanners that failed or are off, and the base images it did not scan', async () => {
    const scans = { trivy: '', semgrep: fixtureText('semgrep', ws()), gitleaks: clean() };
    await go({ scanners: 'trivy,semgrep,gitleaks' }, SCENARIOS.accepted, { scans: { semgrep: scans.semgrep, gitleaks: scans.gitleaks }, deps: { findBaseImages: async () => ['node:24-bookworm-slim', 'ghcr.io/acme/base:1.2'] } });
    const cov = uploads()[0]!.json.metadata.coverage as { type: string; detail: string; reason?: string }[];
    expect(cov.find((c) => c.type === 'scanner_failed' && c.detail === 'trivy')).toBeTruthy();
    expect(cov.filter((c) => c.type === 'base_image_not_scanned').map((c) => c.detail)).toEqual(['node:24-bookworm-slim', 'ghcr.io/acme/base:1.2']);
  });
  it('a scanner left out of the scanners input is a gap with its reason', async () => {
    await go({ scanners: 'gitleaks' }, SCENARIOS.accepted, { scans: { gitleaks: clean() }, deps: { findBaseImages: async () => [] } });
    const cov = uploads()[0]!.json.metadata.coverage;
    expect(cov).toEqual([
      { type: 'scanner_skipped', detail: 'trivy', reason: 'not enabled in the scanners input' },
      { type: 'scanner_skipped', detail: 'semgrep', reason: 'not enabled in the scanners input' },
    ]);
  });
});

describe('base images', () => {
  it('reads FROM lines: no scratch, no earlier stages, no build arguments, flags and continuations handled', () => {
    const text = ['# comment', 'FROM --platform=$BUILDPLATFORM node:24-slim@sha256:' + 'a'.repeat(64) + ' AS build', 'FROM build AS test', 'FROM scratch', 'FROM $BASE', 'FROM \\', '  python:3.12-slim', 'RUN echo FROM nothing'].join('\n');
    expect(parseBaseImages(text)).toEqual(['node:24-slim@sha256:' + 'a'.repeat(64), 'python:3.12-slim']);
  });
  it('finds Dockerfiles in the workspace, skips node_modules, and dedupes', async () => {
    mkdirSync(join(ws(), 'svc', 'api'), { recursive: true });
    mkdirSync(join(ws(), 'node_modules', 'x'), { recursive: true });
    writeFileSync(join(ws(), 'Dockerfile'), 'FROM node:24-slim\n');
    writeFileSync(join(ws(), 'svc', 'api', 'Dockerfile.prod'), 'FROM node:24-slim\nFROM alpine:3.20\n');
    writeFileSync(join(ws(), 'svc', 'app.dockerfile'), 'FROM debian:12\n');
    writeFileSync(join(ws(), 'node_modules', 'x', 'Dockerfile'), 'FROM evil:1\n');
    expect(await findBaseImages(ws())).toEqual(['alpine:3.20', 'debian:12', 'node:24-slim']);
  });
  it('nothing to find in a workspace without Dockerfiles', async () => {
    expect(await findBaseImages(ws())).toEqual([]);
  });
});

describe('redaction: every kept string is scrubbed', () => {
  const sarif = (rule: object, result: object) => ({ version: '2.1.0', runs: [{ tool: { driver: { name: 'Semgrep', rules: [rule] } }, results: [result] }] });
  it('a rule id that the scrubber would change is not kept (the result is dropped)', () => {
    const r = redactSarif('semgrep', sarif({ id: `rule.${FAKE_TOKEN}` }, { ruleId: `rule.${FAKE_TOKEN}`, message: { text: 'matched code here' } }), { workspace: ws() });
    expect(r.findings).toBe(0);
    expect(JSON.stringify(r.runs)).not.toContain(FAKE_TOKEN);
  });
  it('documentation links lose their query string and fragment', () => {
    const r = redactSarif('semgrep', sarif({ id: 'r.ok', helpUri: 'https://docs.example.com/rules/r.ok?token=abc#frag', fullDescription: { text: 'Static description.' } }, { ruleId: 'r.ok', message: { text: 'user code: secret_value_here' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'a.py' }, region: { startLine: 1 } } }] }), { workspace: ws() });
    const rule = r.runs[0]!.tool.driver.rules[0]!;
    expect(rule.helpUri).toBe('https://docs.example.com/rules/r.ok');
    expect(r.runs[0]!.results[0]!.message.text).toBe('Static description.'); // never result.message
    expect(JSON.stringify(r.runs)).not.toContain('secret_value_here');
  });
  it('the Semgrep command always turns metrics off', async () => {
    const calls: string[][] = [];
    await go({ scanners: 'semgrep' }, SCENARIOS.accepted, { deps: { runCommand: async (cmd, args) => { calls.push([cmd, ...args]); return { exitCode: 0, stderrTail: '' }; } } });
    expect(calls.find((c) => c[0] === 'semgrep')).toContain('--metrics=off');
  });
  it('a hostile branch name is scrubbed in the upload metadata', async () => {
    const hostile = { repository: { default_branch: 'main' }, pull_request: { number: 1, head: { sha: 'b'.repeat(40), ref: `feat/${FAKE_TOKEN}` }, base: { ref: 'main' } } };
    await go({}, SCENARIOS.accepted, { event: hostile });
    expect(JSON.stringify(uploads()[0]!.json)).not.toContain(FAKE_TOKEN);
  });
});

describe('default API address', () => {
  it('is the OneQueue API on the main domain', () => {
    expect(DEFAULT_API_URL).toBe('https://api.onequeue.dev');
  });
});

describe('gitleaks paths', () => {
  it('scans "." from the workspace so fingerprints (and .gitleaksignore entries) are repository-relative', async () => {
    const calls: { args: string[]; cwd: string }[] = [];
    await go({ scanners: 'gitleaks' }, SCENARIOS.accepted, { deps: { runCommand: async (cmd, args, o) => { if (cmd === 'gitleaks') calls.push({ args, cwd: o.cwd }); return { exitCode: 0, stderrTail: '' }; } } });
    expect(calls[0]!.args.slice(0, 2)).toEqual(['dir', '.']);
    expect(calls[0]!.cwd).toBe(ws());
  });
});
