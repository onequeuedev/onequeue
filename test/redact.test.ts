import { gunzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { OneQueueClient } from '../src/lib/client.ts';
import { redactSarif } from '../src/lib/redact/allowlist.ts';
import { normalizePath } from '../src/lib/redact/paths.ts';
import { REDACTED, scrubText } from '../src/lib/redact/scrub.ts';
import { collectGitleaksSecrets, containsSecret } from '../src/lib/redact/tripwire.ts';
import type { ScannerName } from '../src/lib/redact/types.ts';
import { assertNoLeak, FAKE_TOKEN, fixture, makeHostile, PLAIN_SECRET } from './helpers.ts';

const WS = '/github/workspace';
// Built at runtime so secret scanners do not flag this public repository.
const FAKE_AWS_ID = ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join('');
const TOOLS: ScannerName[] = ['trivy', 'semgrep', 'gitleaks'];

/** What actually goes over the wire: gzip(JSON(envelope)), decoded again. */
function wire(runs: unknown): string {
  return gunzipSync(OneQueueClient.encode({ schemaVersion: 1, sarif: { version: '2.1.0', runs } })).toString('utf8');
}

describe('planted secrets never reach the upload payload', () => {
  for (const tool of TOOLS) {
    it(`${tool}: realistic SARIF`, () => {
      const out = redactSarif(tool, fixture(tool, WS), { workspace: WS });
      expect(out.findings).toBeGreaterThan(0);
      assertNoLeak(wire(out.runs));
    });

    it(`${tool}: hostile SARIF with the secret in every droppable field`, () => {
      for (const secret of [FAKE_TOKEN, PLAIN_SECRET]) {
        const out = redactSarif(tool, makeHostile(fixture(tool, WS), secret), { workspace: WS });
        expect(out.findings).toBeGreaterThan(0);
        assertNoLeak(wire(out.runs), [secret]);
      }
    });
  }

  it('drops snippets, contextRegion, artifact contents, invocations and fingerprints structurally', () => {
    const payload = wire(TOOLS.flatMap((t) => redactSarif(t, makeHostile(fixture(t, WS), 'x'), { workspace: WS }).runs));
    for (const key of [
      'snippet',
      'contextRegion',
      'artifactContent',
      'artifacts',
      'invocations',
      'environmentVariables',
      'fingerprints',
      'partialFingerprints',
      'codeFlows',
      'relatedLocations',
      'fixes',
      'attachments',
      'originalUriBaseIds',
      'commitSha',
      'author',
      'email',
      'commitMessage',
      'Secret',
      'Match',
      'help"',
      'fullDescription',
    ]) {
      expect(payload, key).not.toContain(`"${key.replace('"', '')}"`);
    }
  });
});

describe('kept fields', () => {
  it('trivy: rule, severity, path, lines, fixed version; drops Trivy secret results', () => {
    const out = redactSarif('trivy', fixture('trivy', WS), { workspace: WS });
    expect(out.findings).toBe(2);
    expect(out.dropped).toBe(1);
    const run = out.runs[0]!;
    expect(run.tool.driver).toMatchObject({ name: 'Trivy', version: '0.76.1' });
    const [vuln, misconfig] = run.results;
    expect(vuln).toEqual({
      ruleId: 'CVE-2021-23337',
      level: 'error',
      message: {
        text: 'Package: lodash\nInstalled Version: 4.17.20\nVulnerability: CVE-2021-23337\nSeverity: HIGH\nFixed Version: 4.17.21\nLink: [CVE-2021-23337](https://avd.aquasec.com/nvd/cve-2021-23337)',
      },
      locations: [{ physicalLocation: { artifactLocation: { uri: 'package-lock.json' }, region: { startLine: 1, endLine: 1 } } }],
      properties: { fixedVersion: '4.17.21' },
    });
    // file:// URI inside the workspace becomes repo-relative
    expect(misconfig!.locations![0]!.physicalLocation.artifactLocation.uri).toBe('Dockerfile');
    expect(misconfig!.message.text).toContain('Message: Specify at least 1 USER command');
    expect(run.tool.driver.rules).toEqual([
      {
        id: 'CVE-2021-23337',
        name: 'LanguageSpecificPackageVulnerability',
        shortDescription: { text: 'nodejs-lodash: command injection via template' },
        helpUri: 'https://avd.aquasec.com/nvd/cve-2021-23337',
        properties: { 'security-severity': '7.2' },
      },
      {
        id: 'DS-0002',
        name: 'Misconfiguration',
        shortDescription: { text: "Image user should not be 'root'" },
        helpUri: 'https://avd.aquasec.com/misconfig/ds-0002',
        properties: { 'security-severity': '7.0' },
      },
    ]);
  });

  it('semgrep: message comes from the static rule description, never result.message', () => {
    const out = redactSarif('semgrep', fixture('semgrep', WS), { workspace: WS });
    const r = out.runs[0]!.results[0]!;
    expect(out.runs[0]!.tool.driver).toMatchObject({ name: 'Semgrep OSS', version: '1.182.1' });
    expect(r.message.text).toBe('Detected possible formatted SQL query. Use parameterized queries instead.');
    expect(r.level).toBe('warning');
    expect(r.locations![0]!.physicalLocation).toEqual({ artifactLocation: { uri: 'app/db.py' }, region: { startLine: 10, endLine: 12 } });
  });

  it('gitleaks: synthesized message, level error, no author/commit data', () => {
    const out = redactSarif('gitleaks', fixture('gitleaks', WS), { workspace: WS });
    expect(out.findings).toBe(2);
    expect(out.runs[0]!.results[0]).toEqual({
      ruleId: 'github-pat',
      level: 'error',
      message: { text: 'github-pat: secret detected' },
      locations: [{ physicalLocation: { artifactLocation: { uri: 'config/settings.py' }, region: { startLine: 3, endLine: 3 } } }],
    });
    expect(JSON.stringify(out)).not.toMatch(/jane|Jane Dev|4b825dc6/);
  });

  it('keeps a finding but omits its location when the path is outside the workspace', () => {
    const s = fixture('semgrep', WS);
    s.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri = 'file:///etc/passwd';
    const r = redactSarif('semgrep', s, { workspace: WS }).runs[0]!.results[0]!;
    expect(r.locations).toBeUndefined();
  });

  it('survives garbage input without throwing', () => {
    for (const junk of [null, 1, 'x', [], {}, { runs: 'x' }, { runs: [null, 1, { results: [null, { ruleId: 5 }] }] }]) {
      expect(() => redactSarif('trivy', junk, { workspace: WS })).not.toThrow();
    }
  });
});

describe('property test: random extra fields holding the secret are always dropped', () => {
  // Small deterministic PRNG (mulberry32) so failures are reproducible.
  const prng = (seed: number) => () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const KEYS = ['text', 'snippet', 'value', 'data', 'secret', 'Match', 'properties', 'contents', 'env', 'x', 'markdown', 'uriBaseId'];

  function junk(rand: () => number, secret: string, depth: number): unknown {
    if (depth <= 0 || rand() < 0.3) return rand() < 0.5 ? secret : `${secret}::${Math.floor(rand() * 100)}`;
    if (rand() < 0.3) return [junk(rand, secret, depth - 1), junk(rand, secret, depth - 1)];
    const o: Record<string, unknown> = {};
    const n = 1 + Math.floor(rand() * 3);
    for (let i = 0; i < n; i++) o[KEYS[Math.floor(rand() * KEYS.length)]!] = junk(rand, secret, depth - 1);
    return o;
  }

  function sprinkle(node: any, rand: () => number, secret: string, depth = 0): void {
    if (!node || typeof node !== 'object' || depth > 12) return;
    for (const v of Object.values(node)) sprinkle(v, rand, secret, depth + 1);
    if (!Array.isArray(node) && rand() < 0.6) node[`k${Math.floor(rand() * 1e6)}`] = junk(rand, secret, 3);
  }

  for (const tool of TOOLS) {
    it(`${tool}: 200 random mutations`, () => {
      for (let seed = 1; seed <= 200; seed++) {
        const rand = prng(seed * 7919);
        const s = fixture(tool, WS);
        sprinkle(s, rand, PLAIN_SECRET);
        const out = redactSarif(tool, s, { workspace: WS });
        try {
          assertNoLeak(wire(out.runs), [PLAIN_SECRET]);
        } catch (e) {
          throw new Error(`seed ${seed}: ${(e as Error).message}`);
        }
      }
    });
  }
});

describe('scrubText', () => {
  it.each([
    [`token ${FAKE_TOKEN} here`, FAKE_TOKEN],
    [`key ${FAKE_AWS_ID} end`, FAKE_AWS_ID],
    ['password = "hunter22"', 'hunter22'],
    ['api_key: s3cr3tvalue', 's3cr3tvalue'],
    ['-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----', 'MIIabc'],
    ['https://user:pa55word@example.com/x', 'pa55word'],
    ['blob Zx8Kq2Lm9Pw4Rt7Yv1Bn6Cs3Dg5Fh0Jk', 'Zx8Kq2Lm9Pw4Rt7Yv1Bn6Cs3Dg5Fh0Jk'],
  ])('redacts %s', (input, secret) => {
    const out = scrubText(input);
    expect(out).not.toContain(secret);
    expect(out).toContain(REDACTED);
  });

  it('keeps ordinary prose, CVE ids, URLs and versions', () => {
    const text = 'Package: lodash CVE-2021-23337 https://avd.aquasec.com/nvd/cve-2021-23337 fixed in 4.17.21';
    expect(scrubText(text)).toBe(text);
    expect(scrubText('v0.0.0-20210921155107-089bfa567519', { entropy: false })).toBe('v0.0.0-20210921155107-089bfa567519');
  });

  it('caps length and strips control characters', () => {
    expect(scrubText('a'.repeat(5000)).length).toBe(1000);
    expect(scrubText('a\u0000b\u001bc')).toBe('abc');
  });
});

describe('normalizePath', () => {
  it.each([
    ['src/a.ts', 'src/a.ts'],
    ['./src/a.ts', 'src/a.ts'],
    ['file:///github/workspace/src/a%20b.ts', 'src/a b.ts'],
    ['/github/workspace/x.py', 'x.py'],
    ['src\\win\\path.cs', 'src/win/path.cs'],
  ])('%s -> %s', (input, expected) => {
    expect(normalizePath(input, WS)).toBe(expected);
  });

  it.each(['/etc/passwd', 'file:///root/.ssh/id_rsa', '../outside', 'a/../../b', 'https://evil/x', '', 42])('rejects %s', (input) => {
    expect(normalizePath(input, WS)).toBeUndefined();
  });
});

describe('tripwire', () => {
  it('collects secret values from raw gitleaks SARIF', () => {
    const secrets = collectGitleaksSecrets(fixture('gitleaks', WS));
    expect(secrets).toEqual(expect.arrayContaining([FAKE_TOKEN, PLAIN_SECRET]));
  });

  it('detects a secret in raw, JSON-escaped, URL-encoded and base64 form', () => {
    const s = 'abc"def/ghi+jkl';
    expect(containsSecret(`x${s}x`, [s])).toBe(true);
    expect(containsSecret(JSON.stringify({ a: s }), [s])).toBe(true);
    expect(containsSecret(encodeURIComponent(s), [s])).toBe(true);
    expect(containsSecret(Buffer.from(s).toString('base64'), [s])).toBe(true);
    expect(containsSecret('clean payload', [s])).toBe(false);
  });

  it('ignores very short values to avoid false positives', () => {
    expect(containsSecret('abc', ['abc'])).toBe(false);
  });
});
