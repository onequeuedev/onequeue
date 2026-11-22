import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';

const SCRIPT = resolve(__dirname, '../scripts/release-tag.sh');
const DIGEST = 'sha256:' + 'a'.repeat(64);
let repo: string;
let remote: string;
let env: NodeJS.ProcessEnv;

// Nothing here may depend on the machine's git setup: CI runners have no user identity, and a developer's global config may sign
// commits. HOME points at an empty directory, the global and system config are ignored, and the identity is given explicitly.
const isolatedEnv = (home: string): NodeJS.ProcessEnv => ({
  ...process.env,
  HOME: home,
  XDG_CONFIG_HOME: join(home, '.config'),
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_SYSTEM: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_AUTHOR_NAME: 'Release Test',
  GIT_AUTHOR_EMAIL: 'release-test@example.invalid',
  GIT_COMMITTER_NAME: 'Release Test',
  GIT_COMMITTER_EMAIL: 'release-test@example.invalid',
  GIT_TERMINAL_PROMPT: '0',
});

const git = (...args: string[]) => execFileSync('git', args, { cwd: repo, encoding: 'utf8', env }).trim();
const commit = (msg: string, image = `docker://onequeuedev/onequeue@${DIGEST}`) => {
  writeFileSync(join(repo, 'action.yml'), `name: x\nruns:\n  using: docker\n  image: ${image}\n  # ${msg}\n`);
  git('add', '-A');
  git('commit', '-q', '-m', msg);
  return git('rev-parse', 'HEAD');
};
const release = (args: string[], answers: string, extra: Record<string, string> = {}) =>
  spawnSync('bash', [SCRIPT, ...args], { cwd: repo, input: answers, encoding: 'utf8', env: { ...env, ...extra } });
const tagTarget = (t: string) => git('rev-parse', `${t}^{commit}`);
const remoteTags = () => execFileSync('git', ['-C', remote, 'tag', '--list'], { encoding: 'utf8', env }).trim().split('\n').filter(Boolean).sort();

beforeEach(() => {
  const dir = mkdtempSync(join(tmpdir(), 'oq-tag-'));
  const home = join(dir, 'home');
  mkdirSync(home);
  env = isolatedEnv(home);
  repo = join(dir, 'repo');
  remote = join(dir, 'remote.git');
  mkdirSync(repo);
  execFileSync('git', ['init', '-q', '--bare', '--initial-branch=main', remote], { env });
  execFileSync('git', ['init', '-q', '--initial-branch=main', repo], { env });
  // also in the repository itself, so the script (which runs git in it) never needs the identity from the environment
  git('config', 'user.name', 'Release Test');
  git('config', 'user.email', 'release-test@example.invalid');
  git('config', 'commit.gpgsign', 'false');
  git('config', 'tag.gpgsign', 'false');
  git('config', 'tag.forceSignAnnotated', 'false');
  git('remote', 'add', 'origin', remote);
});

describe('scripts/release-tag.sh', () => {
  it('creates vX.Y.Z and the major tag after the version is typed, and does not push when told no', () => {
    const c = commit('release 1.1.0');
    const r = release(['1.1.0'], '1.1.0\nn\n');
    expect(r.status, r.stderr + r.stdout).toBe(0);
    expect(r.stdout).toContain('will create tag v1.1.0');
    expect(r.stdout).toContain('will create v1 at');
    expect(tagTarget('v1.1.0')).toBe(c);
    expect(tagTarget('v1')).toBe(c);
    expect(r.stdout).toContain('git push origin +v1');
    expect(remoteTags()).toEqual([]);
  });

  it('the next 1.x release force-moves v1 and leaves the old release tag where it was', () => {
    const first = commit('release 1.1.0');
    release(['1.1.0'], '1.1.0\nn\n');
    const second = commit('release 1.2.0');
    const r = release(['1.2.0'], '1.2.0\nn\n');
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/will MOVE v1 from [0-9a-f]{12} to [0-9a-f]{12}/);
    expect(tagTarget('v1')).toBe(second);
    expect(tagTarget('v1.2.0')).toBe(second);
    expect(tagTarget('v1.1.0')).toBe(first);
  });

  it('a 2.0.0 release moves v2 and leaves v1 alone', () => {
    const one = commit('release 1.1.0');
    release(['1.1.0'], '1.1.0\nn\n');
    const two = commit('breaking');
    expect(release(['2.0.0'], '2.0.0\nn\n').status).toBe(0);
    expect(tagTarget('v2')).toBe(two);
    expect(tagTarget('v1')).toBe(one);
  });

  it('pushes both tags, the major one with force, when confirmed', () => {
    commit('release 1.1.0');
    release(['1.1.0'], '1.1.0\ny\n');
    expect(remoteTags()).toEqual(['v1', 'v1.1.0']);
    const second = commit('release 1.2.0');
    const r = release(['1.2.0'], '1.2.0\ny\n');
    expect(r.status, r.stderr).toBe(0);
    const onRemote = execFileSync('git', ['-C', remote, 'rev-parse', 'v1^{commit}'], { encoding: 'utf8', env }).trim();
    expect(onRemote).toBe(second);
    expect(remoteTags()).toEqual(['v1', 'v1.1.0', 'v1.2.0']);
  });

  it('changes nothing unless the exact version is typed', () => {
    commit('release 1.1.0');
    for (const answer of ['', 'yes\n', '1.1.1\n']) {
      const r = release(['1.1.0'], answer);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('not confirmed');
    }
    expect(git('tag', '--list')).toBe('');
  });

  it('refuses a release tag that exists, and a version lower than one already released', () => {
    commit('release 1.2.0');
    release(['1.2.0'], '1.2.0\nn\n');
    commit('again');
    expect(release(['1.2.0'], '1.2.0\n').stderr).toContain('already exists');
    const low = release(['1.1.0'], '1.1.0\n');
    expect(low.status).toBe(1);
    expect(low.stderr).toContain('lower than 1.2.0');
    expect(git('tag', '--list')).toBe('v1\nv1.2.0');
  });

  it('refuses when the working tree is dirty', () => {
    commit('release 1.1.0');
    writeFileSync(join(repo, 'stray.txt'), 'x');
    const r = release(['1.1.0'], '1.1.0\n');
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('uncommitted changes');
  });

  it('refuses a commit whose action.yml does not pin the new image', () => {
    commit('old image', 'docker://docker.io/rhysha/onequeuedev@' + DIGEST);
    const r = release(['1.1.0'], '1.1.0\n');
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('does not pin docker://onequeuedev/onequeue@sha256');
    expect(release(['1.1.0'], '1.1.0\nn\n', { ALLOW_UNPINNED: '1' }).status).toBe(0);
  });

  it('a pre-release gets its own tag and never moves the major tag', () => {
    const stable = commit('release 1.1.0');
    release(['1.1.0'], '1.1.0\nn\n');
    commit('rc');
    const r = release(['1.2.0-rc.1'], '1.2.0-rc.1\nn\n');
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain('pre-release: v1 is not moved');
    expect(tagTarget('v1')).toBe(stable);
    expect(git('tag', '--list')).toContain('v1.2.0-rc.1');
  });

  it('rejects things that are not versions', () => {
    commit('x');
    for (const v of ['', 'v1.1.0', '1.1', '1.1.0; rm -rf /']) expect(release(v ? [v] : [], '').status).toBe(2);
  });
});
