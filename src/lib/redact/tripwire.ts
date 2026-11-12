/**
 * Last check before upload. Gitleaks' raw (unredacted) SARIF tells us the
 * exact secret values present on this runner. We keep them in memory only and
 * refuse to upload any payload that contains one of them, in any common
 * encoding. This guards against bugs in the redactor.
 */

const MIN_SECRET_LEN = 6;

/** Extract secret values from raw Gitleaks SARIF. Never log the result. */
export function collectGitleaksSecrets(rawSarif: unknown): string[] {
  const out = new Set<string>();
  const runs = (rawSarif as { runs?: unknown })?.runs;
  if (!Array.isArray(runs)) return [];
  for (const run of runs) {
    const results = (run as { results?: unknown })?.results;
    if (!Array.isArray(results)) continue;
    for (const res of results) {
      const r = res as Record<string, any>;
      const candidates: unknown[] = [];
      for (const loc of Array.isArray(r?.locations) ? r.locations : []) {
        candidates.push(loc?.physicalLocation?.region?.snippet?.text);
      }
      candidates.push(r?.properties?.Secret, r?.properties?.Match, r?.properties?.secret, r?.properties?.match);
      for (const c of candidates) {
        if (typeof c !== 'string') continue;
        const v = c.trim();
        if (v.length >= MIN_SECRET_LEN) out.add(v);
      }
    }
  }
  return [...out];
}

function encodings(secret: string): string[] {
  return [
    secret,
    JSON.stringify(secret).slice(1, -1),
    encodeURIComponent(secret),
    Buffer.from(secret, 'utf8').toString('base64'),
  ];
}

/** Returns true if `payload` contains any of `secrets`. */
export function containsSecret(payload: string, secrets: readonly string[]): boolean {
  for (const s of secrets) {
    for (const enc of encodings(s)) {
      if (enc.length >= MIN_SECRET_LEN && payload.includes(enc)) return true;
    }
  }
  return false;
}
