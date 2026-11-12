import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { RunCommand } from '../src/lib/scanners/types.ts';

/**
 * Planted fake secrets. Built at runtime so this repository never contains
 * a literal secret-shaped string (keeps secret scanners and push protection quiet).
 * FAKE_TOKEN matches a known token pattern; PLAIN_SECRET matches no pattern, so
 * only the allowlist (not the scrubber) can keep it out of the payload.
 */
export const FAKE_TOKEN = ['gh', 'p_', 'T3stOnly', 'Xk9mQ2vL8pR4sN7wZ1yB5cD0eF6g'].join('');
export const PLAIN_SECRET = ['plain', 'cobalt', 'giraffe', 'seventy'].join('-');

export const FIXTURE_DIR = new URL('./fixtures/sarif/', import.meta.url).pathname;

export function fixtureText(name: 'trivy' | 'semgrep' | 'gitleaks', workspace: string): string {
  return readFileSync(join(FIXTURE_DIR, `${name}.sarif`), 'utf8')
    .replaceAll('__FAKE_TOKEN__', FAKE_TOKEN)
    .replaceAll('__PLAIN_SECRET__', PLAIN_SECRET)
    .replaceAll('__WORKSPACE__', workspace);
}

export function fixture(name: 'trivy' | 'semgrep' | 'gitleaks', workspace: string): any {
  return JSON.parse(fixtureText(name, workspace));
}

/** Every encoding a leak could take in the payload. */
export function leakForms(secret: string): string[] {
  return [secret, JSON.stringify(secret).slice(1, -1), encodeURIComponent(secret), Buffer.from(secret).toString('base64')];
}

export function assertNoLeak(payload: string, secrets = [FAKE_TOKEN, PLAIN_SECRET]): void {
  for (const s of secrets) {
    for (const form of leakForms(s)) {
      if (payload.includes(form)) throw new Error(`payload leaks planted secret (form: ${form === s ? 'raw' : 'encoded'})`);
    }
  }
}

/**
 * Deep-inject the secret into fields the redactor must drop: snippets,
 * context regions, artifact contents, invocations/env, fingerprints,
 * code flows, related locations, fixes, attachments, and property bags at
 * every level.
 */
export function makeHostile(sarif: any, secret: string): any {
  const s = structuredClone(sarif);
  s.properties = { leak: secret };
  s.inlineExternalProperties = [{ properties: { leak: secret } }];
  for (const run of s.runs) {
    run.properties = { ...run.properties, leak: secret };
    run.artifacts = [{ location: { uri: 'x.py' }, contents: { text: secret, binary: Buffer.from(secret).toString('base64') }, hashes: { sha256: secret } }];
    run.invocations = [{ commandLine: `tool --token ${secret}`, environmentVariables: { SECRET: secret }, machine: secret, account: secret, workingDirectory: { uri: `file:///home/${secret}` } }];
    run.originalUriBaseIds = { SRC: { uri: `file:///${secret}/` } };
    run.versionControlProvenance = [{ repositoryUri: `https://x:${secret}@github.com/o/r`, revisionId: secret }];
    run.webRequests = [{ headers: { Authorization: secret } }];
    run.threadFlowLocations = [{ location: { message: { text: secret } } }];
    run.graphs = [{ description: { text: secret } }];
    run.tool.driver.properties = { leak: secret };
    run.tool.driver.notifications = [{ id: 'n', shortDescription: { text: secret } }];
    run.tool.extensions = [{ name: secret }];
    for (const rule of run.tool.driver.rules ?? []) {
      rule.properties = { ...rule.properties, leak: secret };
      rule.help = { text: secret, markdown: secret };
      rule.messageStrings = { default: { text: secret } };
    }
    for (const r of run.results ?? []) {
      r.properties = { ...r.properties, Secret: secret, Match: secret, leak: secret };
      r.fingerprints = { ...r.fingerprints, primary: secret };
      r.partialFingerprints = { ...r.partialFingerprints, commitMessage: secret, author: secret, email: secret };
      r.attachments = [{ description: { text: secret }, artifactLocation: { uri: secret } }];
      r.relatedLocations = [{ physicalLocation: { artifactLocation: { uri: 'other.py' }, region: { snippet: { text: secret } } } }];
      r.codeFlows = [{ threadFlows: [{ locations: [{ location: { message: { text: secret } } }] }] }];
      r.stacks = [{ message: { text: secret } }];
      r.fixes = [{ description: { text: secret } }];
      r.webRequest = { body: { text: secret } };
      r.analysisTarget = { uri: secret };
      r.hostedViewerUri = secret;
      r.provenance = { conversionSources: [{ region: { snippet: { text: secret } } }] };
      for (const loc of r.locations ?? []) {
        loc.message = { text: secret };
        loc.properties = { leak: secret };
        const p = loc.physicalLocation;
        if (!p) continue;
        p.address = { name: secret };
        p.properties = { leak: secret };
        p.artifactLocation.properties = { leak: secret };
        p.artifactLocation.description = { text: secret };
        p.region = { ...p.region, snippet: { text: secret }, message: { text: secret }, properties: { leak: secret } };
        p.contextRegion = { startLine: 1, snippet: { text: secret } };
      }
    }
  }
  return s;
}

export interface FakeScan {
  /** SARIF text to write, or a failure kind. */
  output: string | 'crash' | 'nosarif' | 'badjson' | 'spawn-error';
}

export interface RecordedCall {
  cmd: string;
  args: string[];
  env: NodeJS.ProcessEnv;
}

/** Fake RunCommand: writes the configured SARIF to the path the scanner was asked to write. */
export function fakeRunner(outputs: Partial<Record<string, FakeScan['output']>>, calls: RecordedCall[] = []): RunCommand {
  return async (cmd, args, opts) => {
    calls.push({ cmd, args, env: opts.env });
    const out = outputs[cmd];
    if (out === undefined || out === 'spawn-error') return { exitCode: null, stderrTail: '', spawnError: `spawn ${cmd} ENOENT` };
    if (out === 'crash') return { exitCode: 2, stderrTail: `fatal: ${cmd} panicked\n::set-output name=x::pwned` };
    if (out === 'nosarif') return { exitCode: 0, stderrTail: '' };
    const flag = cmd === 'gitleaks' ? '--report-path' : '--output';
    const path = args[args.indexOf(flag) + 1]!;
    writeFileSync(path, out === 'badjson' ? '{not json' : out);
    return { exitCode: 0, stderrTail: '' };
  };
}
