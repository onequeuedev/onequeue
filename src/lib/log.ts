/**
 * Logging that cannot leak registered secrets.
 *
 * Every line passes through `sanitize`, which replaces any registered secret
 * (the API key, secret values found by Gitleaks) with `***` before it is
 * written. Untrusted text (scanner stderr, server messages) is written between
 * `::stop-commands::` markers so it cannot run GitHub workflow commands.
 */
import { randomUUID } from 'node:crypto';

export interface Logger {
  info(msg: string): void;
  debug(msg: string): void;
  warning(msg: string): void;
  error(msg: string): void;
  group(title: string): void;
  endGroup(): void;
  /** Register a value that must never be printed. Also emits ::add-mask::. */
  mask(secret: string): void;
  /** Register a value that must never be printed, without emitting anything. */
  hide(secret: string): void;
  /** Print untrusted multi-line text with workflow commands disabled. */
  untrusted(text: string): void;
}

export type Writer = (line: string) => void;

/** Escape data for workflow command messages (same rules as @actions/core). */
export function escapeData(s: string): string {
  return s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

export function createLogger(write: Writer, opts: { debug?: boolean } = {}): Logger {
  const secrets = new Set<string>();

  const sanitize = (s: string): string => {
    let out = s;
    for (const secret of secrets) {
      if (secret.length > 0) out = out.split(secret).join('***');
    }
    return out;
  };

  const command = (cmd: string, msg: string) => write(`::${cmd}::${escapeData(sanitize(msg))}`);

  return {
    info: (msg) => write(sanitize(msg)),
    debug: (msg) => {
      if (opts.debug) command('debug', msg);
    },
    warning: (msg) => command('warning', msg),
    error: (msg) => command('error', msg),
    group: (title) => write(`::group::${escapeData(sanitize(title))}`),
    endGroup: () => write('::endgroup::'),
    mask: (secret) => {
      if (!secret) return;
      secrets.add(secret);
      // The mask command itself must contain the value; GitHub hides it from the log.
      write(`::add-mask::${escapeData(secret)}`);
    },
    hide: (secret) => {
      if (secret) secrets.add(secret);
    },
    untrusted: (text) => {
      const token = randomUUID().replace(/-/g, '');
      write(`::stop-commands::${token}`);
      for (const line of sanitize(text).split(/\r?\n/)) write(line);
      write(`::${token}::`);
    },
  };
}
