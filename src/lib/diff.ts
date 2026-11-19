/**
 * Which lines did a pull request change? Used only for the local secret rule when there is no api-key
 * (pull requests from forks): a Gitleaks finding counts only when it sits on a line the PR added or changed.
 *
 * The diff text can contain source code, so it stays in memory and only its headers are read; nothing from it is logged.
 */
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';

/** Repo-relative path -> inclusive [start, end] line ranges on the new side of the diff. */
export type ChangedLines = Map<string, [number, number][]>;

/** Runs `git diff` for the workspace and returns its text, or null when it cannot be produced. */
export type GitDiffFn = (workspace: string, baseSha: string, env: NodeJS.ProcessEnv) => Promise<string | null>;

const SHA = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;

/** The base commit of the pull request, from the event payload. */
export function readBaseSha(env: NodeJS.ProcessEnv): string | undefined {
  const path = env.GITHUB_EVENT_PATH;
  if (!path || !(env.GITHUB_EVENT_NAME ?? '').startsWith('pull_request')) return undefined;
  try {
    const sha = JSON.parse(readFileSync(path, 'utf8'))?.pull_request?.base?.sha;
    return typeof sha === 'string' && SHA.test(sha) ? sha : undefined;
  } catch {
    return undefined;
  }
}

const unquote = (p: string): string => {
  if (!p.startsWith('"') || !p.endsWith('"')) return p;
  return p.slice(1, -1).replace(/\\(["\\])/g, '$1').replace(/\\([0-7]{3})/g, (_m, o: string) => String.fromCharCode(parseInt(o, 8)));
};

/** Reads the `+++ b/<path>` and `@@ -a,b +c,d @@` headers of a `git diff --unified=0` text. */
export function parseChangedLines(diff: string): ChangedLines {
  const out: ChangedLines = new Map();
  let file: string | undefined;
  for (const line of diff.split('\n')) {
    if (line.startsWith('+++ ')) {
      const p = unquote(line.slice(4).trimEnd());
      file = p === '/dev/null' ? undefined : p.replace(/^b\//, '');
      if (file && !out.has(file)) out.set(file, []);
      continue;
    }
    const h = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (h && file) {
      const start = Number(h[1]);
      const count = h[2] === undefined ? 1 : Number(h[2]);
      if (count > 0) out.get(file)!.push([start, start + count - 1]);
    }
  }
  return out;
}

export interface Located {
  path: string | undefined;
  startLine: number | undefined;
  endLine: number | undefined;
}

/**
 * Is a finding inside the PR's changes? A finding without a usable location counts (fail closed).
 * With `fileOnly` (Gitleaks history mode, where a finding's line belongs to an older commit) any change to the file counts.
 */
export function inChangedLines(f: Located, changed: ChangedLines, fileOnly = false): boolean {
  if (!f.path) return true;
  const ranges = changed.get(f.path);
  if (!ranges) return false;
  if (fileOnly || f.startLine === undefined) return true;
  const end = f.endLine ?? f.startLine;
  return ranges.some(([a, b]) => f.startLine! <= b && end >= a);
}

function git(args: string[], cwd: string, env: NodeJS.ProcessEnv, collect: boolean): Promise<{ code: number | null; stdout: string }> {
  return new Promise((resolve) => {
    let stdout = '';
    let child;
    try {
      child = spawn('git', args, { cwd, env, stdio: ['ignore', collect ? 'pipe' : 'ignore', 'ignore'], shell: false });
    } catch {
      resolve({ code: null, stdout: '' });
      return;
    }
    const timer = setTimeout(() => child.kill('SIGKILL'), 120_000);
    child.stdout?.on('data', (b: Buffer) => {
      if (stdout.length < 64 * 1024 * 1024) stdout += b.toString('utf8');
    });
    child.on('error', () => {
      clearTimeout(timer);
      resolve({ code: null, stdout: '' });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout });
    });
  });
}

/**
 * Default GitDiffFn. With the default checkout of a pull request, HEAD is the merge of the PR into its base, so
 * `git diff <base sha> HEAD` is exactly the PR's changes. The base commit is fetched (depth 1) when it is missing, which
 * works for public repositories; if it still cannot be read, the caller falls back to the whole workspace.
 */
export const gitDiff: GitDiffFn = async (workspace, baseSha, env) => {
  const genv = { ...env, GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'safe.directory', GIT_CONFIG_VALUE_0: '*', GIT_TERMINAL_PROMPT: '0' };
  const diffArgs = ['-c', 'core.quotepath=off', 'diff', '--unified=0', '--no-color', '--no-ext-diff', '--no-renames', '--no-textconv', baseSha, 'HEAD', '--'];
  let r = await git(diffArgs, workspace, genv, true);
  if (r.code !== 0) {
    const fetched = await git(['fetch', '--no-tags', '--depth=1', '--no-recurse-submodules', 'origin', baseSha], workspace, genv, false);
    if (fetched.code !== 0) return null;
    r = await git(diffArgs, workspace, genv, true);
  }
  return r.code === 0 ? r.stdout : null;
};
