/**
 * Orchestration for the GitHub Action. All side effects are injectable so the
 * whole flow can be tested against the mock API server.
 */
import { randomUUID } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { findBaseImages } from './lib/baseimages.ts';
import { ApiError, OneQueueClient, type FetchFn, type SleepFn } from './lib/client.ts';
import { gitDiff, inChangedLines, parseChangedLines, readBaseSha, type GitDiffFn, type Located } from './lib/diff.ts';
import { decide, type SecretRule, type ServerOutcome } from './lib/gate.ts';
import { createLogger, type Writer } from './lib/log.ts';
import { buildMetadata, type CoverageGap, type ScannerReport } from './lib/metadata.ts';
import { redactSarif } from './lib/redact/allowlist.ts';
import { collectGitleaksSecrets, containsSecret } from './lib/redact/tripwire.ts';
import type { RedactedRun, ScannerName } from './lib/redact/types.ts';
import { runScanner, spawnCommand } from './lib/scanners/run.ts';
import type { RunCommand } from './lib/scanners/types.ts';
import { parseInputs, SCANNER_NAMES_ALL } from './inputs.ts';
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
  /** Produces `git diff` text for the pull request (tests inject it). */
  gitDiff?: GitDiffFn;
  /** Base images named in the repository's Dockerfiles (tests inject it; the default reads the workspace). */
  findBaseImages?: (workspace: string) => Promise<string[]>;
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
    // What this run did not cover, in names and short reasons only (sent with the upload; see README).
    const coverage: CoverageGap[] = [];
    for (const s of SCANNER_NAMES_ALL) if (!inputs.scanners.includes(s)) coverage.push({ type: 'scanner_skipped', detail: s, reason: 'not enabled in the scanners input' });
    for (const s of inputs.scanners) if (!toRun.includes(s)) coverage.push({ type: 'scanner_skipped', detail: s, reason: 'no api-key (for example a pull request from a fork)' });

    const runs: RedactedRun[] = [];
    const secrets: string[] = [];
    let findings = 0;
    let gitleaksFindings: number | undefined;
    // Where Gitleaks found things (repo-relative, redacted); used only for the local rule without an api-key.
    let gitleaksLocations: Located[] = [];

    if (toRun.includes('gitleaks')) await noteGitleaksIgnore(workspace);

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
        coverage.push({ type: 'scanner_failed', detail: name, reason: out.error });
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
      if (name === 'gitleaks') {
        gitleaksFindings = red.findings;
        gitleaksLocations = red.runs.flatMap((r) => r.results.map((x): Located => {
          const p = x.locations?.[0]?.physicalLocation;
          return { path: p?.artifactLocation.uri, startLine: p?.region?.startLine, endLine: p?.region?.endLine };
        }));
      }
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
      // Trivy checks a Dockerfile's settings, not the packages inside the image it starts FROM, and the action never pulls images.
      for (const image of await (deps.findBaseImages ?? findBaseImages)(workspace).catch(() => [] as string[])) {
        coverage.push({ type: 'base_image_not_scanned', detail: image });
      }
      const envelope = {
        schemaVersion: SCHEMA_VERSION,
        mode: inputs.mode,
        failOn: inputs.failOn,
        metadata: buildMetadata(env, actionVersion, reports, coverage),
        sarif: { version: '2.1.0', runs },
      };

      if (dryRun) {
        return finishDryRun(envelope, findings, reports, gitleaksFindings, secrets, workspace);
      }

      if (containsSecret(JSON.stringify(envelope), secrets)) {
        // Should be impossible; refuse rather than leak.
        server = { kind: 'upload-failed', message: 'payload failed the secret tripwire check, upload aborted' };
        uploadNote = 'aborted by secret tripwire';
        log.warning('OneQueue upload aborted: the redacted payload still contained a secret value. Please report this privately to security@onequeue.dev.');
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
          if (e instanceof ApiError && e.status === 402) {
            // The company's plan is not accepting uploads (trial over, or paused). A warning, never a failed build.
            server = { kind: 'skipped', reason: `OneQueue is not accepting uploads for this company right now (${e.message}). Nothing was uploaded and this does not fail the build.` };
            uploadNote = 'skipped: uploads paused (HTTP 402)';
            log.warning(`OneQueue upload skipped: ${e.message}. Ask an owner to check the plan in the dashboard. The build is not failed because of this.`);
          } else {
            server = { kind: 'upload-failed', message: (e as Error).message };
            uploadNote = 'upload failed';
            log.warning(`OneQueue upload failed: ${(e as Error).message}`);
          }
        }
      }
    }

    // With an api-key the server verdict decides about secrets. When there is no verdict (upload failed, paused, timed out) the
    // secrets would otherwise be waved through, so the local rule applies instead: secrets on lines this pull request changed fail.
    const noVerdict = hasKey && server.kind !== 'verdict';
    const scope = await secretScope(hasKey && !noVerdict, inputs.mode, gitleaksFindings, gitleaksLocations, workspace, noVerdict);
    const decision = decide({ mode: inputs.mode, onTimeout: inputs.onTimeout, gitleaksFindings, secretRule: scope.rule, localFindings: scope.count, server });
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

  /** Say that a .gitleaksignore in the repository is honored (Gitleaks reads it; the action never prints its content). */
  async function noteGitleaksIgnore(workspace: string): Promise<void> {
    try {
      const text = await readFile(join(workspace, '.gitleaksignore'), 'utf8');
      const entries = text.split('\n').filter((l) => l.trim() !== '' && !l.trim().startsWith('#')).length;
      log.info(`Honoring .gitleaksignore (${entries} entr${entries === 1 ? 'y' : 'ies'}): findings it lists are not reported.`);
    } catch {
      /* no ignore file */
    }
  }

  /**
   * Which rule decides about secrets, and how many findings it counts.
   * With an api-key the server verdict decides. Without one (fork PRs) only secrets on lines the PR changed count;
   * if the PR's diff cannot be read, or this is not a pull request, every secret in the workspace counts.
   */
  async function secretScope(serverDecides: boolean, mode: string, total: number | undefined, found: Located[], workspace: string, fallback = false): Promise<{ rule: SecretRule; count: number }> {
    const all = total ?? 0;
    if (serverDecides) return { rule: 'server', count: 0 };
    if (mode !== 'gate' || all === 0) return fallback ? { rule: 'server', count: 0 } : { rule: 'workspace', count: all };
    // Fallback (a key, but no verdict): only secrets the pull request itself added can fail; when that cannot be told, warn only.
    const base = readBaseSha(env);
    if (!base) return fallback ? { rule: 'server', count: 0 } : { rule: 'workspace', count: all };
    const text = await (deps.gitDiff ?? gitDiff)(workspace, base, env).catch(() => null);
    if (text === null) {
      if (fallback) return { rule: 'server', count: 0 };
      log.warning('Could not read the pull request diff (the base commit is not available), so every Gitleaks finding in the workspace counts. Use fetch-depth: 0 on checkout to limit the check to changed lines.');
      return { rule: 'workspace', count: all };
    }
    const changed = parseChangedLines(text);
    const count = found.filter((f) => inChangedLines(f, changed, inputs.gitleaksHistory)).length;
    return { rule: 'changed-lines', count };
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
          'Please report this privately to security@onequeue.dev.',
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
      log.warning(`Gitleaks found ${gitleaksFindings} secret(s). A dry run does not fail the build${inputs.mode === 'gate' ? '; gate mode decides about secrets as described in the README' : ''}.`);
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
