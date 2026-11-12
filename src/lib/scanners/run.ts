import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { ScannerName } from '../redact/types.ts';
import { SCANNERS } from './definitions.ts';
import type { CommandResult, RunCommand, ScanContext, ScanOutcome } from './types.ts';

const STDERR_TAIL = 4096;

/** Default RunCommand: spawn without a shell, discard stdout, keep a stderr tail. */
export const spawnCommand: RunCommand = (cmd, args, opts) =>
  new Promise<CommandResult>((resolve) => {
    let stderr = '';
    let settled = false;
    const done = (r: CommandResult) => {
      if (!settled) {
        settled = true;
        resolve(r);
      }
    };
    let child;
    try {
      child = spawn(cmd, args, {
        cwd: opts.cwd,
        env: opts.env,
        // stdout is ignored: scanners can print matched code or secrets there.
        stdio: ['ignore', 'ignore', 'pipe'],
        shell: false,
      });
    } catch (e) {
      done({ exitCode: null, stderrTail: '', spawnError: (e as Error).message });
      return;
    }
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      done({ exitCode: null, stderrTail: stderr, spawnError: `timed out after ${opts.timeoutMs} ms` });
    }, opts.timeoutMs);
    child.stderr?.on('data', (b: Buffer) => {
      stderr = (stderr + b.toString('utf8')).slice(-STDERR_TAIL);
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      done({ exitCode: null, stderrTail: stderr, spawnError: e.message });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      done({ exitCode: code, stderrTail: stderr });
    });
  });

/** Run one scanner. Never throws: failures are reported in the outcome. */
export async function runScanner(name: ScannerName, ctx: ScanContext): Promise<ScanOutcome & { stderrTail?: string }> {
  const def = SCANNERS[name];
  const sarifPath = join(ctx.outDir, `${name}.sarif`);
  const { cmd, args, env } = def.command(ctx, sarifPath);
  const started = Date.now();
  const res = await ctx.runCommand(cmd, args, {
    cwd: ctx.workspace,
    env: { ...ctx.env, ...env },
    timeoutMs: ctx.timeoutMs,
  });
  const durationMs = Date.now() - started;
  const base = { name, durationMs, version: def.imageVersion(ctx.env), stderrTail: res.stderrTail };

  if (res.spawnError) return { ...base, ok: false, error: res.spawnError };
  if (res.exitCode === null || !def.okExitCodes.includes(res.exitCode)) {
    return { ...base, ok: false, error: `exited with code ${res.exitCode}` };
  }

  let sarif: unknown;
  try {
    sarif = JSON.parse(await readFile(sarifPath, 'utf8'));
  } catch (e) {
    return { ...base, ok: false, error: `no valid SARIF output (${(e as NodeJS.ErrnoException).code ?? 'parse error'})` };
  }
  if (!Array.isArray((sarif as { runs?: unknown })?.runs)) {
    return { ...base, ok: false, error: 'SARIF output has no runs' };
  }
  const driver = (sarif as any).runs?.[0]?.tool?.driver;
  const raw = driver?.version ?? driver?.semanticVersion;
  const driverVersion = typeof raw === 'string' ? raw.replace(/^v(?=\d)/, '') : undefined;
  return {
    ...base,
    ok: true,
    sarif,
    // The image-pinned version wins: some tools (Gitleaks) report a stale version in SARIF.
    version: base.version ?? (driverVersion && /^[\w.+-]{1,64}$/.test(driverVersion) ? driverVersion : undefined),
  };
}
