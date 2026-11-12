/**
 * Orchestration for the GitHub Action. All side effects are injectable so the
 * whole flow can be tested against the mock API server.
 */
import { randomUUID } from 'node:crypto';
import { lstat, mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { OneQueueClient, type FetchFn, type SleepFn } from './lib/client.ts';
import { decide, type ServerOutcome } from './lib/gate.ts';
import { createLogger, type Writer } from './lib/log.ts';
import { buildMetadata, type ScannerReport } from './lib/metadata.ts';
import { redactSarif } from './lib/redact/allowlist.ts';
import { collectGitleaksSecrets, containsSecret } from './lib/redact/tripwire.ts';
import type { RedactedRun, ScannerName } from './lib/redact/types.ts';
import { runScanner, spawnCommand } from './lib/scanners/run.ts';
import type { RunCommand } from './lib/scanners/types.ts';
import { parseInputs } from './inputs.ts';
import { setOutputs, writeSummary } from './summary.ts';

export interface RunDeps {
  env: NodeJS.ProcessEnv;
  write?: Writer;
  runCommand?: RunCommand;
  fetch?: FetchFn;
  sleep?: SleepFn;
  now?: () => number;
  /** Base backoff for upload retries (tests use a small value). */
  backoffMs?: number;
  /** Verdict poll interval. Default 2000 ms. */
  pollIntervalMs?: number;
  scannerTimeoutMs?: number;
}

export const SCHEMA_VERSION = 1;

export async function run(deps: RunDeps): Promise<number> {
  const env = deps.env;
  const log = createLogger(deps.write ?? ((l) => process.stdout.write(`${l}\n`)), {
    debug: env.RUNNER_DEBUG === '1',
  });
  const actionVersion = env.ONEQUEUE_ACTION_VERSION || 'dev';

  const parsed = parseInputs(env);
  // Mask before anything else is printed.
  log.mask(parsed.inputs.apiKey);

  const dryRun = parsed.inputs.dryRun;
  if (parsed.fatal) {
    // Dry run never fails the build.
    if (dryRun) {
      log.warning(`${parsed.fatal} Dry run: nothing was written.`);
      return 0;
    }
    log.error(parsed.fatal);
    return 1;
  }
  const inputs = parsed.inputs;
  // Gate mode treats input problems as fatal, except in a dry run, which never fails.
  const strict = inputs.mode === 'gate' && !dryRun;
  for (const p of parsed.problems) {
    if (strict) log.error(p);
    else log.warning(`${p} Using defaults where possible.`);
  }
  if (strict && parsed.problems.length > 0) return 1;
  if (dryRun) {
    log.info(`OneQueue dry run: nothing will be sent to the OneQueue API. The payload will be written to ${inputs.outputFile}.`);
  }

  let outDir: string | undefined;
  try {
    return await execute();
  } catch (e) {
    // Unexpected bug. Upload mode and dry runs must never fail the build.
    const msg = `OneQueue Scan hit an unexpected error: ${(e as Error).message}`;
    if (inputs.mode === 'upload' || dryRun) {
      log.warning(msg);
      return 0;
    }
    log.error(msg);
    return 1;
  } finally {
    if (outDir) await rm(outDir, { recursive: true, force: true }).catch(() => {});
  }

  async function execute(): Promise<number> {
    const workspace = env.GITHUB_WORKSPACE || process.cwd();
    const hasKey = inputs.apiKey.length > 0;

    let toRun = inputs.scanners;
    // A dry run sends nothing, so it runs every enabled scanner even without a key.
    if (!hasKey && !dryRun) {
      log.warning(
        'OneQueue api-key is empty, so nothing will be uploaded. This is expected for pull requests from forks, ' +
          'which cannot read repository secrets. Gitleaks still runs locally.',
      );
      toRun = inputs.scanners.filter((s) => s === 'gitleaks');
    }

    outDir = await mkdtemp(join(env.RUNNER_TEMP || tmpdir(), 'onequeue-'));

    const reports: Partial<Record<ScannerName, ScannerReport>> = {};
    for (const s of inputs.scanners) if (!toRun.includes(s)) reports[s] = { status: 'skipped', findings: 0 };

    const runs: RedactedRun[] = [];
    const secrets: string[] = [];
    let findings = 0;
    let gitleaksFindings: number | undefined;

    for (const name of toRun) {
      log.group(`OneQueue: ${name}`);
      const out = await runScanner(name, {
        workspace,
        outDir,
        env,
        runCommand: deps.runCommand ?? spawnCommand,
        timeoutMs: deps.scannerTimeoutMs ?? 20 * 60_000,
        semgrepConfigs: inputs.semgrepConfigs,
        gitleaksHistory: inputs.gitleaksHistory,
      });

      if (!out.ok) {
        log.endGroup();
        log.warning(`${name} failed (${out.error}). Continuing with the other scanners.`);
        if (out.stderrTail) {
          log.info(`${name} stderr (last lines):`);
          log.untrusted(out.stderrTail);
        }
        reports[name] = { status: 'failed', findings: 0, ...(out.version ? { version: out.version } : {}) };
        continue;
      }

      if (name === 'gitleaks') {
        for (const s of collectGitleaksSecrets(out.sarif)) {
          secrets.push(s);
          log.hide(s);
        }
      }
      const red = redactSarif(name, out.sarif, { workspace });
      if (out.version) for (const r of red.runs) r.tool.driver.version = out.version;
      out.sarif = undefined;
      runs.push(...red.runs);
      findings += red.findings;
      if (name === 'gitleaks') gitleaksFindings = red.findings;
      reports[name] = { status: 'ok', findings: red.findings, ...(out.version ? { version: out.version } : {}) };
      log.info(`${name}: ${red.findings} finding(s) in ${(out.durationMs / 1000).toFixed(1)}s${red.dropped ? `, ${red.dropped} dropped by redaction` : ''}`);
      log.endGroup();
    }

    let server: ServerOutcome;
    let uploadId: string | null = null;
    let uploaded: number | null = null;
    let uploadNote = '';

    if (!hasKey && !dryRun) {
      server = { kind: 'skipped', reason: 'api-key is empty' };
      uploadNote = 'skipped: no api-key';
    } else {
      const envelope = {
        schemaVersion: SCHEMA_VERSION,
        mode: inputs.mode,
        failOn: inputs.failOn,
        metadata: buildMetadata(env, actionVersion, reports),
        sarif: { version: '2.1.0', runs },
      };

      if (dryRun) {
        return finishDryRun(envelope, findings, reports, gitleaksFindings, secrets, workspace);
      }

      if (containsSecret(JSON.stringify(envelope), secrets)) {
        // Should be impossible; refuse rather than leak.
        server = { kind: 'upload-failed', message: 'payload failed the secret tripwire check, upload aborted' };
        uploadNote = 'aborted by secret tripwire';
        log.warning('OneQueue upload aborted: the redacted payload still contained a secret value. Please report this privately via the Security tab of github.com/onequeuedev/onequeue (Report a vulnerability).');
      } else {
        const client = new OneQueueClient({
          apiUrl: inputs.apiUrl,
          apiKey: inputs.apiKey,
          userAgent: `onequeue-action/${actionVersion}`,
          fetch: deps.fetch,
          sleep: deps.sleep,
          now: deps.now,
          backoffMs: deps.backoffMs,
          debug: (m) => log.debug(m),
        });
        try {
          // One key per run; the client reuses it on every retry.
          const res = await client.upload(envelope, randomUUID());
          uploadId = res.id;
          uploaded = findings;
          log.info(`Uploaded ${findings} redacted finding(s). Upload ID: ${res.id}`);
          server = { kind: 'uploaded' };
          if (inputs.mode === 'gate') {
            log.info(`Waiting up to ${inputs.gateTimeoutSec}s for the OneQueue verdict...`);
            server = await client.pollVerdict(res.id, inputs.gateTimeoutSec * 1000, deps.pollIntervalMs ?? 2000);
          }
        } catch (e) {
          server = { kind: 'upload-failed', message: (e as Error).message };
          uploadNote = 'upload failed';
          log.warning(`OneQueue upload failed: ${(e as Error).message}`);
        }
      }
    }

    const decision = decide({ mode: inputs.mode, onTimeout: inputs.onTimeout, gitleaksFindings, server });
    for (const m of decision.messages) {
      if (m.level === 'error') log.error(m.text);
      else if (m.level === 'warning') log.warning(m.text);
      else log.info(m.text);
    }

    const gateResult = inputs.mode === 'upload' ? 'not gated (upload mode)' : decision.result;
    try {
      writeSummary(env, { mode: inputs.mode, scanners: reports, findingsUploaded: uploaded, uploadId, uploadNote, gateResult });
      setOutputs(env, { 'upload-id': uploadId ?? '', findings: String(findings), verdict: decision.result });
    } catch (e) {
      log.warning(`Could not write the step summary or outputs: ${(e as Error).message}`);
    }

    return decision.exitCode;
  }

  /**
   * Dry run: write the exact JSON text that would be gzipped and uploaded.
   * No request is made to the OneQueue API, and the step always exits 0.
   */
  async function finishDryRun(
    envelope: unknown,
    findings: number,
    reports: Partial<Record<ScannerName, ScannerReport>>,
    gitleaksFindings: number | undefined,
    secrets: string[],
    workspace: string,
  ): Promise<number> {
    const json = OneQueueClient.serialize(envelope);
    let note: string;
    if (containsSecret(json, secrets)) {
      // Same tripwire as a real upload: never write a payload that contains a secret.
      note = 'dry run: payload failed the secret tripwire check, not written';
      log.warning(
        'OneQueue dry run: the redacted payload still contained a secret value, so it was not written. ' +
          'Please report this privately via the Security tab of github.com/onequeuedev/onequeue (Report a vulnerability).',
      );
    } else {
      try {
        const target = await safeOutputPath(workspace, inputs.outputFile);
        await writeFile(target, json, { encoding: 'utf8', mode: 0o644 });
        note = `dry run: payload written to ${inputs.outputFile}`;
        log.info(`OneQueue dry run: wrote the exact upload payload (${findings} finding(s), ${Buffer.byteLength(json)} bytes before gzip) to ${inputs.outputFile}. Nothing was uploaded.`);
      } catch (e) {
        note = 'dry run: could not write the payload';
        log.warning(`OneQueue dry run: could not write ${inputs.outputFile}: ${(e as Error).message}`);
      }
    }
    if ((gitleaksFindings ?? 0) > 0) {
      log.warning(`Gitleaks found ${gitleaksFindings} secret(s). A dry run does not fail the build${inputs.mode === 'gate' ? ', but gate mode would' : ''}.`);
    }
    try {
      writeSummary(env, { mode: `${inputs.mode} (dry run)`, scanners: reports, findingsUploaded: null, uploadId: null, uploadNote: note, gateResult: 'not gated (dry run)' });
      setOutputs(env, { 'upload-id': '', findings: String(findings), verdict: 'n/a' });
    } catch (e) {
      log.warning(`Could not write the step summary or outputs: ${(e as Error).message}`);
    }
    return 0;
  }
}

/** Resolve output-file inside the workspace; refuse symlinks that would point elsewhere. */
async function safeOutputPath(workspace: string, outputFile: string): Promise<string> {
  const target = resolve(workspace, outputFile);
  await mkdir(dirname(target), { recursive: true });
  const realWs = await realpath(workspace);
  const realParent = await realpath(dirname(target));
  const rel = relative(realWs, realParent);
  if (rel.startsWith('..') || isAbsolute(rel)) throw new Error('output-file resolves outside the workspace');
  const existing = await lstat(target).catch(() => undefined);
  if (existing?.isSymbolicLink()) throw new Error('output-file is a symbolic link');
  if (existing && !existing.isFile()) throw new Error('output-file exists and is not a regular file');
  return join(realParent, basename(target));
}
