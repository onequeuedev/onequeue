/**
 * Free-text scrubbing. Applied to every string the redactor keeps
 * (rule names, messages, paths). This is a second line of defence: the
 * allowlist in allowlist.ts already drops every field that is expected to
 * contain code or secrets.
 */

export const REDACTED = '[REDACTED]';

const PATTERNS: RegExp[] = [
  // PEM private keys (whole block, or an unterminated header to end of text)
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g,
  // AWS access key ids
  /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  // GitHub tokens
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
  // Slack tokens
  /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g,
  // Stripe / OpenAI / Anthropic style keys
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  // Google API keys
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  // JWTs
  /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
  // Credentials embedded in URLs: scheme://user:pass@host
  /(?<=[a-z][a-z0-9+.-]*:\/\/)[^\s/:@]+:[^\s/@]+(?=@)/gi,
];

// key = value / key: value where the key looks like a credential name.
const ASSIGNMENT =
  /((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential|client[_-]?secret)[A-Za-z0-9_-]*["']?\s*[:=]\s*)(["']?)([^\s"',;]{4,})/gi;

// Long opaque tokens. Redacted only when they look random (high entropy).
const LONG_TOKEN = /[A-Za-z0-9+/_=-]{24,}/g;

export function shannonEntropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksRandom(token: string): boolean {
  if (shannonEntropy(token) < 3.5) return false;
  // Require a mix of character classes; plain words and kebab-case ids are kept.
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((r) => r.test(token)).length;
  return classes >= 2 && /[0-9]/.test(token);
}

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

export interface ScrubOptions {
  maxLen?: number;
  /**
   * Redact long high-entropy tokens. On for prose (messages, rule names);
   * off for structured values such as paths and package versions, where
   * long mixed tokens (e.g. Go pseudo-versions) are expected.
   */
  entropy?: boolean;
}

/** Scrub secrets from text and cap its length. */
export function scrubText(input: string, opts: ScrubOptions = {}): string {
  const maxLen = opts.maxLen ?? 1000;
  let s = input.replace(CONTROL, '');
  for (const re of PATTERNS) s = s.replace(re, REDACTED);
  s = s.replace(ASSIGNMENT, (_m, key: string, quote: string) => `${key}${quote}${REDACTED}`);
  if (opts.entropy !== false) s = s.replace(LONG_TOKEN, (tok) => (looksRandom(tok) ? REDACTED : tok));
  if (s.length > maxLen) s = `${s.slice(0, maxLen - 1)}…`;
  return s;
}
