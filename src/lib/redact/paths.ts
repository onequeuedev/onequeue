import { scrubText } from './scrub.ts';

const MAX_PATH = 1024;

/**
 * Turn a SARIF artifactLocation.uri into a repo-relative POSIX path.
 * Returns undefined when the path is absolute outside the workspace, escapes
 * it with `..`, or is otherwise unusable. The caller then omits the location.
 */
export function normalizePath(uri: unknown, workspace: string): string | undefined {
  if (typeof uri !== 'string' || uri.length === 0 || uri.length > 4 * MAX_PATH) return undefined;

  let p = uri;
  if (/^file:/i.test(p)) {
    try {
      p = new URL(p).pathname;
    } catch {
      return undefined;
    }
  } else if (/^[a-z][a-z0-9+.-]*:/i.test(p)) {
    // Any other URI scheme (http:, git:, ...) is not a file in the workspace.
    return undefined;
  }

  try {
    p = decodeURIComponent(p);
  } catch {
    return undefined;
  }

  p = p.replace(/\\/g, '/');
  const ws = workspace.replace(/\\/g, '/').replace(/\/+$/, '');

  if (p.startsWith('/')) {
    if (ws && p.startsWith(`${ws}/`)) p = p.slice(ws.length + 1);
    else return undefined;
  }

  p = p.replace(/^\.\/+/, '');
  const parts = p.split('/').filter((seg) => seg !== '' && seg !== '.');
  if (parts.length === 0 || parts.some((seg) => seg === '..')) return undefined;

  const out = parts.join('/');
  if (out.length > MAX_PATH) return undefined;
  return scrubText(out, { entropy: false, maxLen: MAX_PATH });
}
