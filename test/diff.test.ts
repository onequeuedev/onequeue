import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { gitDiff, inChangedLines, parseChangedLines, readBaseSha } from '../src/lib/diff.ts';

const DIFF = [
  'diff --git a/config/settings.py b/config/settings.py',
  'index 111..222 100644',
  '--- a/config/settings.py',
  '+++ b/config/settings.py',
  '@@ -2 +2,2 @@ import os',
  '+x = 1',
  '+y = 2',
  '@@ -10,2 +11,0 @@',
  '-gone',
  '-gone too',
  'diff --git a/new.txt b/new.txt',
  'new file mode 100644',
  '--- /dev/null',
  '+++ b/new.txt',
  '@@ -0,0 +1,3 @@',
  '+a',
  'diff --git a/old.txt b/old.txt',
  '--- a/old.txt',
  '+++ /dev/null',
  '@@ -1,2 +0,0 @@',
  'diff --git a/with space.py b/with space.py',
  '--- a/with space.py',
  '+++ "b/with space.py"',
  '@@ -5 +5 @@',
].join('\n');

describe('parseChangedLines', () => {
  const changed = parseChangedLines(DIFF);
  it('reads the new-side ranges and ignores pure deletions', () => {
    expect(changed.get('config/settings.py')).toEqual([[2, 3]]);
    expect(changed.get('new.txt')).toEqual([[1, 3]]);
    expect(changed.has('old.txt')).toBe(false);
    expect(changed.get('with space.py')).toEqual([[5, 5]]);
  });
  it('matches findings by their lines', () => {
    expect(inChangedLines({ path: 'config/settings.py', startLine: 3, endLine: 3 }, changed)).toBe(true);
    expect(inChangedLines({ path: 'config/settings.py', startLine: 4, endLine: 4 }, changed)).toBe(false);
    expect(inChangedLines({ path: 'config/settings.py', startLine: 1, endLine: 2 }, changed)).toBe(true); // a multi-line finding touching a changed line
    expect(inChangedLines({ path: 'untouched.py', startLine: 1, endLine: 1 }, changed)).toBe(false);
  });
  it('a finding without a usable location counts (fail closed); history mode counts by file', () => {
    expect(inChangedLines({ path: undefined, startLine: undefined, endLine: undefined }, changed)).toBe(true);
    expect(inChangedLines({ path: 'config/settings.py', startLine: 99, endLine: 99 }, changed, true)).toBe(true);
    expect(inChangedLines({ path: 'untouched.py', startLine: 1, endLine: 1 }, changed, true)).toBe(false);
  });
});

describe('gitDiff with a real repository', () => {
  const git = (cwd: string, ...args: string[]) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', ...args], { cwd, encoding: 'utf8' }).trim();

  it('returns exactly the lines a pull request (a merge into its base) changed', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'oq-git-'));
    git(dir, 'init', '-q', '-b', 'main');
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src/app.py'), ['one', 'two', 'three', 'four', ''].join('\n'));
    writeFileSync(join(dir, 'keep.txt'), 'untouched\n');
    git(dir, 'add', '.');
    git(dir, 'commit', '-q', '-m', 'base');
    const base = git(dir, 'rev-parse', 'HEAD');
    git(dir, 'checkout', '-q', '-b', 'feature');
    writeFileSync(join(dir, 'src/app.py'), ['one', 'TWO', 'three', 'four', 'five', ''].join('\n'));
    writeFileSync(join(dir, 'new file.txt'), 'x\n');
    git(dir, 'add', '.');
    git(dir, 'commit', '-q', '-m', 'change');

    const text = await gitDiff(dir, base, {});
    expect(text).not.toBeNull();
    const changed = parseChangedLines(text!);
    expect(changed.get('src/app.py')).toEqual([[2, 2], [5, 5]]);
    expect(changed.get('new file.txt')).toEqual([[1, 1]]);
    expect(changed.has('keep.txt')).toBe(false);
  });

  it('returns null when the base commit cannot be read or fetched', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'oq-git-'));
    git(dir, 'init', '-q', '-b', 'main');
    writeFileSync(join(dir, 'a.txt'), 'a\n');
    git(dir, 'add', '.');
    git(dir, 'commit', '-q', '-m', 'one');
    expect(await gitDiff(dir, 'd'.repeat(40), {})).toBeNull(); // no such commit, no remote to fetch it from
    expect(await gitDiff(join(dir, 'missing-dir'), 'd'.repeat(40), {})).toBeNull();
  });
});

describe('readBaseSha', () => {
  const event = (pr: unknown) => {
    const dir = mkdtempSync(join(tmpdir(), 'oq-ev-'));
    const p = join(dir, 'event.json');
    writeFileSync(p, JSON.stringify(pr));
    return p;
  };
  it('reads the PR base sha, only for pull request events and only if it looks like a sha', () => {
    const ok = event({ pull_request: { base: { sha: 'a'.repeat(40) } } });
    expect(readBaseSha({ GITHUB_EVENT_PATH: ok, GITHUB_EVENT_NAME: 'pull_request' })).toBe('a'.repeat(40));
    expect(readBaseSha({ GITHUB_EVENT_PATH: ok, GITHUB_EVENT_NAME: 'push' })).toBeUndefined();
    expect(readBaseSha({ GITHUB_EVENT_PATH: event({ pull_request: { base: { sha: '--upload-pack=evil' } } }), GITHUB_EVENT_NAME: 'pull_request' })).toBeUndefined();
    expect(readBaseSha({ GITHUB_EVENT_NAME: 'pull_request' })).toBeUndefined();
  });
});
