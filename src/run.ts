/**
 * Orchestration for the GitHub Action. All side effects are injectable so the
 * whole flow can be tested against the mock API server.
 */
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

  if (parsed.fatal) {
    log.error(parsed.fatal);
    return 1;
  }
  const inputs = parsed.inputs;
  for (const p of parsed.problems) {
    if (inputs.mode === 'gate') log.error(p);
    else log.warning(`${p} Using defaults where possible.`);
  }
  if (inputs.mode === 'gate' && parsed.problems.length > 0) return 1;

  let outDir: string | undefined;
  try {
    return await execute();
  } catch (e) {
    // Unexpected bug. Upload mode must never fail the build.
    const msg = `OneQueue Scan hit an unexpected error: ${(e as Error).message}`;
    if (inputs.mode === 'upload') {
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
    if (!hasKey) {
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

    if (!hasKey) {
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
          const res = await client.upload(envelope);
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
}
