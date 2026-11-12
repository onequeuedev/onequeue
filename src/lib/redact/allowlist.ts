/**
 * Allowlist redactor.
 *
 * Builds a new SARIF run from scratch and copies across ONLY the fields listed
 * in README "What is sent". Nothing from the input object is passed through by
 * reference, so unknown or future fields are dropped by construction.
 */
import { normalizePath } from './paths.ts';
import { scrubText } from './scrub.ts';
import type {
  Level,
  RedactedLocation,
  RedactedResult,
  RedactedRule,
  RedactedRun,
  RedactionOutput,
  ScannerName,
} from './types.ts';

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);
const get = (o: unknown, ...keys: string[]): unknown => {
  let cur: unknown = o;
  for (const k of keys) {
    if (!isObj(cur)) return undefined;
    cur = cur[k];
  }
  return cur;
};

const LEVELS: readonly Level[] = ['none', 'note', 'warning', 'error'];
const RULE_ID = /^[A-Za-z0-9_.:/@+-]{1,256}$/;
const VERSION = /^[A-Za-z0-9_.+:~-]{1,64}$/;
const TOOL_NAME = /^[A-Za-z0-9 _.-]{1,64}$/;
const FIXED_VERSION = /^[A-Za-z0-9_.+:~, <>=!^*-]{1,200}$/;
const SEVERITY = /^(?:10(?:\.0+)?|\d(?:\.\d+)?)$/;

const CANONICAL_TOOL: Record<ScannerName, string> = {
  trivy: 'Trivy',
  semgrep: 'Semgrep',
  gitleaks: 'gitleaks',
};

export interface RedactOptions {
  /** Absolute workspace path, used to make file paths repo-relative. */
  workspace: string;
}

function safeRuleId(v: unknown): string | undefined {
  const s = str(v);
  return s && RULE_ID.test(s) ? s : undefined;
}

function safeHttpsUrl(v: unknown): string | undefined {
  const s = str(v);
  if (!s || s.length > 2048) return undefined;
  try {
    const u = new URL(s);
    if (u.protocol !== 'https:' || u.username || u.password) return undefined;
    return u.toString();
  } catch {
    return undefined;
  }
}

function lineNumber(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isInteger(v) && v > 0 && v < 10_000_000 ? v : undefined;
}

function buildLocation(raw: unknown, workspace: string): RedactedLocation | undefined {
  const phys = get(raw, 'physicalLocation');
  const uri = normalizePath(get(phys, 'artifactLocation', 'uri'), workspace);
  if (!uri) return undefined;
  const loc: RedactedLocation = { physicalLocation: { artifactLocation: { uri } } };
  const start = lineNumber(get(phys, 'region', 'startLine'));
  if (start !== undefined) {
    const end = lineNumber(get(phys, 'region', 'endLine'));
    loc.physicalLocation.region = { startLine: start, endLine: end !== undefined && end >= start ? end : start };
  }
  return loc;
}

/** Trivy messages are "Key: value" lines. Keep only known keys. */
const TRIVY_KEYS = new Set([
  'Package',
  'Installed Version',
  'Fixed Version',
  'Vulnerability',
  'Severity',
  'Artifact',
  'Type',
  'Message',
  'Link',
]);
// Values that are package coordinates, not prose: skip entropy scrubbing.
const TRIVY_STRUCTURED = new Set(['Package', 'Installed Version', 'Fixed Version', 'Vulnerability', 'Severity', 'Type']);

function parseTrivyMessage(text: string): { message: string; fixedVersion?: string } {
  const kept: string[] = [];
  let fixedVersion: string | undefined;
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    // Trivy prints "Vulnerability CVE-2021-1234" (no colon); everything else is "Key: value".
    const m = /^Vulnerability\s+([^\s:]+)$/.exec(t) ?? /^([A-Za-z][A-Za-z ]*?):\s*(.*)$/.exec(t);
    if (!m) continue;
    const key = m.length === 2 ? 'Vulnerability' : m[1]!.trim();
    const value = (m.length === 2 ? m[1]! : m[2]!).trim();
    if (!TRIVY_KEYS.has(key)) continue;
    const clean = scrubText(value, { maxLen: 300, entropy: !TRIVY_STRUCTURED.has(key) });
    if (key === 'Fixed Version' && FIXED_VERSION.test(clean)) fixedVersion = clean;
    kept.push(`${key}: ${clean}`);
  }
  return { message: kept.join('\n'), fixedVersion };
}

function isTrivySecretRule(rule: unknown): boolean {
  const tags = arr(get(rule, 'properties', 'tags')).map((t) => String(t).toLowerCase());
  return tags.includes('secret');
}

export function redactSarif(scanner: ScannerName, sarif: unknown, opts: RedactOptions): RedactionOutput {
  const runs: RedactedRun[] = [];
  let findings = 0;
  let dropped = 0;

  for (const rawRun of arr(get(sarif, 'runs'))) {
    const driver = get(rawRun, 'tool', 'driver');
    const rawRules = arr(get(driver, 'rules'));
    const rulesById = new Map<string, unknown>();
    for (const r of rawRules) {
      const id = safeRuleId(get(r, 'id'));
      if (id && !rulesById.has(id)) rulesById.set(id, r);
    }

    const name = str(get(driver, 'name'));
    const version = str(get(driver, 'version')) ?? str(get(driver, 'semanticVersion'));
    const run: RedactedRun = {
      tool: {
        driver: {
          name: name && TOOL_NAME.test(name) ? name : CANONICAL_TOOL[scanner],
          ...(version && VERSION.test(version) ? { version } : {}),
          rules: [],
        },
      },
      results: [],
    };
    const usedRules = new Map<string, RedactedRule>();

    for (const rawResult of arr(get(rawRun, 'results'))) {
      let rawRule: unknown;
      let ruleId = safeRuleId(get(rawResult, 'ruleId')) ?? safeRuleId(get(rawResult, 'rule', 'id'));
      const idx = get(rawResult, 'ruleIndex');
      if (typeof idx === 'number' && Number.isInteger(idx) && idx >= 0 && idx < rawRules.length) {
        rawRule = rawRules[idx];
        ruleId ??= safeRuleId(get(rawRule, 'id'));
      }
      if (!ruleId) {
        dropped++;
        continue;
      }
      rawRule ??= rulesById.get(ruleId);

      if (scanner === 'trivy' && isTrivySecretRule(rawRule)) {
        // Gitleaks owns secrets; Trivy secret results carry "Match:" lines.
        dropped++;
        continue;
      }

      const result: RedactedResult = { ruleId, level: 'warning', message: { text: '' } };

      // Level
      const lvl = str(get(rawResult, 'level')) ?? str(get(rawRule, 'defaultConfiguration', 'level'));
      result.level = LEVELS.includes(lvl as Level) ? (lvl as Level) : 'warning';

      // Message: per-scanner rules
      const rawMsg = str(get(rawResult, 'message', 'text')) ?? '';
      if (scanner === 'gitleaks') {
        result.level = 'error';
        result.message.text = `${ruleId}: secret detected`;
      } else if (scanner === 'semgrep') {
        // Never use result.message: Semgrep interpolates matched code into it.
        const tmpl = str(get(rawRule, 'fullDescription', 'text')) ?? str(get(rawRule, 'shortDescription', 'text'));
        result.message.text = tmpl ? scrubText(tmpl) : `Semgrep finding: ${ruleId}`;
      } else {
        const parsed = parseTrivyMessage(rawMsg);
        result.message.text = parsed.message || `Trivy finding: ${ruleId}`;
        if (parsed.fixedVersion) result.properties = { fixedVersion: parsed.fixedVersion };
      }

      // Location: first valid one only
      for (const rawLoc of arr(get(rawResult, 'locations'))) {
        const loc = buildLocation(rawLoc, opts.workspace);
        if (loc) {
          result.locations = [loc];
          break;
        }
      }

      run.results.push(result);
      findings++;

      if (!usedRules.has(ruleId)) {
        const rule: RedactedRule = { id: ruleId };
        const rName = str(get(rawRule, 'name'));
        if (rName) rule.name = scrubText(rName, { maxLen: 256 });
        const short = str(get(rawRule, 'shortDescription', 'text'));
        if (short && scanner !== 'gitleaks') rule.shortDescription = { text: scrubText(short, { maxLen: 512 }) };
        const helpUri = safeHttpsUrl(get(rawRule, 'helpUri'));
        if (helpUri) rule.helpUri = helpUri;
        const sev = get(rawRule, 'properties', 'security-severity');
        const sevStr = typeof sev === 'number' ? String(sev) : str(sev);
        if (sevStr && SEVERITY.test(sevStr)) rule.properties = { 'security-severity': sevStr };
        usedRules.set(ruleId, rule);
      }
    }

    run.tool.driver.rules = [...usedRules.values()];
    runs.push(run);
  }

  return { runs, findings, dropped };
}
