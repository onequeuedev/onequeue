/**
 * OneQueue API client. See docs/openapi.yaml for the contract.
 *
 * - POST {apiUrl}/v1/uploads: gzip JSON, Bearer auth, Idempotency-Key that is
 *   identical across retries so a retried request cannot create a duplicate.
 * - GET  {apiUrl}/v1/uploads/{id}/verdict: polled until pass/fail or deadline.
 * Redirects are never followed, so the Authorization header is never forwarded.
 */
import { randomUUID } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { scrubText } from './redact/scrub.ts';

export type FetchFn = typeof fetch;
export type SleepFn = (ms: number) => Promise<void>;

export interface ClientOptions {
  apiUrl: string;
  apiKey: string;
  userAgent: string;
  fetch?: FetchFn;
  sleep?: SleepFn;
  now?: () => number;
  random?: () => number;
  /** Retries after the first attempt. Default 3. */
  maxRetries?: number;
  /** Base backoff in ms (1s, 2s, 4s ...). Default 1000. */
  backoffMs?: number;
  requestTimeoutMs?: number;
  debug?: (msg: string) => void;
}

export class ApiError extends Error {
  readonly status: number | undefined;
  readonly code: string | undefined;
  constructor(message: string, status?: number, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

export interface UploadResult {
  id: string;
  attempts: number;
}

export type VerdictStatus = 'pending' | 'pass' | 'fail';

export interface Verdict {
  status: VerdictStatus;
  reason?: string;
  detailsUrl?: string;
}

export type PollResult =
  | { kind: 'verdict'; verdict: Verdict & { status: 'pass' | 'fail' } }
  | { kind: 'timeout' }
  | { kind: 'error'; message: string };

const UPLOAD_ID = /^[A-Za-z0-9_-]{1,128}$/;

const defaultSleep: SleepFn = (ms) => new Promise((r) => setTimeout(r, ms));

export function validateApiUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`api-url is not a valid URL`);
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) {
    throw new Error('api-url must use https:// (http:// is allowed only for localhost)');
  }
  if (u.username || u.password) throw new Error('api-url must not contain credentials');
  if (u.search || u.hash) throw new Error('api-url must not contain a query string or fragment');
  return u;
}

function describeNetworkError(e: unknown): string {
  const err = e as Error & { cause?: { code?: string; message?: string } };
  if (err?.name === 'TimeoutError') return 'request timed out';
  const cause = err?.cause?.code ?? err?.cause?.message;
  return scrubText(`${err?.message ?? 'unknown'}${cause ? ` (${cause})` : ''}`, { maxLen: 200 });
}

function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

async function readError(res: Response): Promise<{ code?: string; message: string }> {
  try {
    const body: any = await res.json();
    const code = typeof body?.error?.code === 'string' ? body.error.code.slice(0, 64) : undefined;
    const msg = typeof body?.error?.message === 'string' ? body.error.message : '';
    const requestId = typeof body?.error?.requestId === 'string' ? ` (request ${body.error.requestId.slice(0, 64)})` : '';
    return { code, message: scrubText(`${msg}${requestId}`, { maxLen: 300 }) };
  } catch {
    return { message: '' };
  }
}

export class OneQueueClient {
  private readonly base: string;
  private readonly fetch: FetchFn;
  private readonly sleep: SleepFn;
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly maxRetries: number;
  private readonly backoffMs: number;
  private readonly requestTimeoutMs: number;
  private readonly debug: (msg: string) => void;
  private readonly opts: ClientOptions;

  constructor(opts: ClientOptions) {
    this.opts = opts;
    this.base = validateApiUrl(opts.apiUrl).toString().replace(/\/+$/, '');
    this.fetch = opts.fetch ?? fetch;
    this.sleep = opts.sleep ?? defaultSleep;
    this.now = opts.now ?? Date.now;
    this.random = opts.random ?? Math.random;
    this.maxRetries = opts.maxRetries ?? 3;
    this.backoffMs = opts.backoffMs ?? 1000;
    this.requestTimeoutMs = opts.requestTimeoutMs ?? 10_000;
    this.debug = opts.debug ?? (() => {});
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    return {
      Authorization: `Bearer ${this.opts.apiKey}`,
      Accept: 'application/json',
      'User-Agent': this.opts.userAgent,
      ...extra,
    };
  }

  private backoff(attempt: number, retryAfter: string | null): number {
    const secs = retryAfter !== null ? Number(retryAfter) : NaN;
    if (Number.isFinite(secs) && secs >= 0) return Math.min(secs * 1000, 10_000);
    return this.backoffMs * 2 ** attempt + Math.floor(this.random() * 250);
  }

  /** Serialize + gzip the envelope. Exposed for tests. */
  static encode(envelope: unknown): Buffer {
    return gzipSync(Buffer.from(JSON.stringify(envelope), 'utf8'));
  }

  async upload(envelope: unknown, idempotencyKey: string = randomUUID()): Promise<UploadResult> {
    const body = OneQueueClient.encode(envelope);
    let lastError = new ApiError('upload failed');

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      let res: Response;
      try {
        res = await this.fetch(`${this.base}/v1/uploads`, {
          method: 'POST',
          headers: this.headers({
            'Content-Type': 'application/json',
            'Content-Encoding': 'gzip',
            'Idempotency-Key': idempotencyKey,
          }),
          body,
          redirect: 'manual',
          signal: AbortSignal.timeout(this.requestTimeoutMs),
        });
      } catch (e) {
        lastError = new ApiError(`network error: ${describeNetworkError(e)}`);
        this.debug(`upload attempt ${attempt + 1} failed: ${lastError.message}`);
        if (attempt < this.maxRetries) await this.sleep(this.backoff(attempt, null));
        continue;
      }

      if (res.status >= 300 && res.status < 400) {
        // Never follow: the Authorization header would go to the new location.
        throw new ApiError(`unexpected redirect (HTTP ${res.status}); check api-url`, res.status, 'redirect');
      }
      if (res.status >= 200 && res.status < 300) {
        let id: unknown;
        try {
          id = ((await res.json()) as any)?.id;
        } catch {
          /* handled below */
        }
        if (typeof id !== 'string' || !UPLOAD_ID.test(id)) {
          throw new ApiError('server returned an invalid upload id', res.status, 'invalid_response');
        }
        return { id, attempts: attempt + 1 };
      }

      const err = await readError(res);
      lastError = new ApiError(`HTTP ${res.status}${err.code ? ` ${err.code}` : ''}${err.message ? `: ${err.message}` : ''}`, res.status, err.code);
      this.debug(`upload attempt ${attempt + 1} failed: ${lastError.message}`);
      if (!isRetryableStatus(res.status)) throw lastError;
      if (attempt < this.maxRetries) await this.sleep(this.backoff(attempt, res.headers.get('retry-after')));
    }
    throw lastError;
  }

  async getVerdict(id: string, timeoutMs = this.requestTimeoutMs): Promise<Verdict> {
    if (!UPLOAD_ID.test(id)) throw new ApiError('invalid upload id');
    const res = await this.fetch(`${this.base}/v1/uploads/${encodeURIComponent(id)}/verdict`, {
      method: 'GET',
      headers: this.headers(),
      redirect: 'manual',
      signal: AbortSignal.timeout(Math.max(1, timeoutMs)),
    });
    if (res.status !== 200) {
      const err = await readError(res);
      throw new ApiError(`HTTP ${res.status}${err.code ? ` ${err.code}` : ''}${err.message ? `: ${err.message}` : ''}`, res.status, err.code);
    }
    const body: any = await res.json();
    const status = body?.status;
    if (status !== 'pending' && status !== 'pass' && status !== 'fail') {
      throw new ApiError('server returned an invalid verdict', res.status, 'invalid_response');
    }
    const v: Verdict = { status };
    if (typeof body.reason === 'string') v.reason = scrubText(body.reason, { maxLen: 500 });
    if (typeof body.detailsUrl === 'string' && /^https:\/\/[^\s]{1,2000}$/.test(body.detailsUrl)) v.detailsUrl = body.detailsUrl;
    return v;
  }

  /**
   * Poll the verdict every `intervalMs` until pass/fail or `timeoutMs` elapses.
   * Transient errors (network, 5xx, 429) are retried until the deadline;
   * other 4xx responses stop polling.
   */
  async pollVerdict(id: string, timeoutMs: number, intervalMs = 2000): Promise<PollResult> {
    const deadline = this.now() + timeoutMs;
    for (;;) {
      const remaining = deadline - this.now();
      if (remaining <= 0) return { kind: 'timeout' };
      try {
        const v = await this.getVerdict(id, Math.min(this.requestTimeoutMs, remaining));
        if (v.status === 'pass' || v.status === 'fail') return { kind: 'verdict', verdict: v as Verdict & { status: 'pass' | 'fail' } };
      } catch (e) {
        const status = e instanceof ApiError ? e.status : undefined;
        if (status !== undefined && status >= 400 && status < 500 && status !== 408 && status !== 429) {
          return { kind: 'error', message: (e as Error).message };
        }
        if (e instanceof ApiError && e.code === 'invalid_response') return { kind: 'error', message: e.message };
        this.debug(`verdict poll failed: ${(e as Error).message}`);
      }
      const wait = Math.min(intervalMs, deadline - this.now());
      if (wait <= 0) return { kind: 'timeout' };
      await this.sleep(wait);
    }
  }
}
