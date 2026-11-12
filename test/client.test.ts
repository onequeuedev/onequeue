import { afterEach, describe, expect, it } from 'vitest';
import { ApiError, OneQueueClient, validateApiUrl } from '../src/lib/client.ts';
import { SCENARIOS, startMockServer, type MockConfig, type MockServer } from './mock-server.ts';

let server: MockServer | undefined;
afterEach(async () => {
  await server?.close();
  server = undefined;
});

// Built at runtime so secret scanners do not flag this public repository.
const KEY = ['oq', 'test', 'key', '123456'].join('_');

function fakeClock() {
  let t = 0;
  const sleeps: number[] = [];
  return {
    now: () => t,
    sleep: async (ms: number) => {
      sleeps.push(ms);
      t += ms;
    },
    sleeps,
  };
}

async function client(cfg: MockConfig, extra: Partial<ConstructorParameters<typeof OneQueueClient>[0]> = {}) {
  server = await startMockServer({ ...cfg, apiKey: KEY });
  const clock = fakeClock();
  const c = new OneQueueClient({
    apiUrl: server.url,
    apiKey: KEY,
    userAgent: 'onequeue-action/test',
    sleep: clock.sleep,
    now: clock.now,
    random: () => 0,
    ...extra,
  });
  return { c, clock };
}

describe('upload', () => {
  it('POSTs gzip JSON with bearer auth and an Idempotency-Key', async () => {
    const { c } = await client(SCENARIOS.accepted);
    const res = await c.upload({ hello: 'world' });
    expect(res).toEqual({ id: 'upl_test123', attempts: 1 });
    const req = server!.requests[0]!;
    expect(req.method).toBe('POST');
    expect(req.path).toBe('/v1/uploads');
    expect(req.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(req.headers['content-encoding']).toBe('gzip');
    expect(req.headers['content-type']).toBe('application/json');
    expect(req.headers['idempotency-key']).toMatch(/^[0-9a-f-]{36}$/);
    expect(req.headers['user-agent']).toBe('onequeue-action/test');
    expect(req.json).toEqual({ hello: 'world' });
  });

  it('retries 5xx up to 3 times with exponential backoff and the same Idempotency-Key', async () => {
    const { c, clock } = await client({
      upload: [{ status: 500 }, { status: 502 }, { status: 503 }, { status: 202, body: { id: 'upl_ok' } }],
      verdict: [],
    });
    const res = await c.upload({});
    expect(res).toEqual({ id: 'upl_ok', attempts: 4 });
    expect(clock.sleeps).toEqual([1000, 2000, 4000]);
    const keys = new Set(server!.requests.map((r) => r.headers['idempotency-key']));
    expect(keys.size).toBe(1);
  });

  it('gives up after 1 + 3 attempts on persistent 500', async () => {
    const { c } = await client(SCENARIOS.error500);
    await expect(c.upload({})).rejects.toThrow(/HTTP 500 internal_error: Something went wrong/);
    expect(server!.requests).toHaveLength(4);
  });

  it('retries network errors', async () => {
    const { c } = await client({ upload: [{ status: 0, destroy: true }, { status: 202, body: { id: 'upl_ok' } }], verdict: [] });
    expect((await c.upload({})).attempts).toBe(2);
  });

  it('honours Retry-After on 429 (capped)', async () => {
    const { c, clock } = await client({
      upload: [{ status: 429, headers: { 'retry-after': '3' } }, { status: 202, body: { id: 'upl_ok' } }],
      verdict: [],
    });
    await c.upload({});
    expect(clock.sleeps).toEqual([3000]);
  });

  it.each([400, 401, 403, 409, 413, 422])('does not retry %i', async (status) => {
    const { c } = await client({ upload: [{ status, body: { error: { code: 'nope', message: 'bad' } } }], verdict: [] });
    await expect(c.upload({})).rejects.toBeInstanceOf(ApiError);
    expect(server!.requests).toHaveLength(1);
  });

  it('rejects a wrong API key with 401 and does not retry', async () => {
    server = await startMockServer({ ...SCENARIOS.accepted, apiKey: 'other' });
    const c = new OneQueueClient({ apiUrl: server.url, apiKey: KEY, userAgent: 'x', sleep: async () => {} });
    await expect(c.upload({})).rejects.toThrow(/HTTP 401 unauthorized/);
    expect(server.requests).toHaveLength(1);
  });

  it('refuses an upload id that is not URL-safe', async () => {
    const { c } = await client({ upload: [{ status: 202, body: { id: '../../admin' } }], verdict: [] });
    await expect(c.upload({})).rejects.toThrow(/invalid upload id/);
  });

  it('does not follow redirects (Authorization would be forwarded)', async () => {
    const { c } = await client({ upload: [{ status: 307, headers: { location: 'https://evil.example/' } }], verdict: [] });
    await expect(c.upload({})).rejects.toThrow();
    expect(server!.requests).toHaveLength(1);
  });
});

describe('pollVerdict', () => {
  it('returns pass after pending, polling every 2s', async () => {
    const { c, clock } = await client(SCENARIOS.pass);
    const r = await c.pollVerdict('upl_test123', 30_000);
    expect(r).toEqual({ kind: 'verdict', verdict: { status: 'pass', reason: 'No blocking findings' } });
    expect(clock.sleeps).toEqual([2000]);
    expect(server!.requests[0]!.path).toBe('/v1/uploads/upl_test123/verdict');
  });

  it('returns fail with reason and details URL', async () => {
    const { c } = await client(SCENARIOS.fail);
    const r = await c.pollVerdict('upl_test123', 30_000);
    expect(r).toMatchObject({ kind: 'verdict', verdict: { status: 'fail', detailsUrl: 'https://app.onequeue.dev/uploads/upl_test123' } });
  });

  it('times out when the verdict stays pending', async () => {
    const { c, clock } = await client(SCENARIOS.timeout);
    expect(await c.pollVerdict('upl_test123', 10_000)).toEqual({ kind: 'timeout' });
    expect(clock.sleeps.reduce((a, b) => a + b, 0)).toBe(10_000);
    expect(server!.requests).toHaveLength(5);
  });

  it('keeps polling through transient 500s until the deadline', async () => {
    const { c } = await client({ upload: [], verdict: [{ status: 500 }, { status: 500 }, { status: 200, body: { status: 'pass' } }] });
    expect(await c.pollVerdict('upl_test123', 30_000)).toMatchObject({ kind: 'verdict' });
  });

  it('stops on 404', async () => {
    const { c } = await client({ upload: [], verdict: [{ status: 404, body: { error: { code: 'not_found', message: 'no' } } }] });
    expect(await c.pollVerdict('upl_test123', 30_000)).toMatchObject({ kind: 'error' });
    expect(server!.requests).toHaveLength(1);
  });
});

describe('validateApiUrl', () => {
  it.each(['https://api.onequeue.dev', 'https://api.example.com/prefix', 'http://localhost:8080', 'http://127.0.0.1:1'])('accepts %s', (u) => {
    expect(() => validateApiUrl(u)).not.toThrow();
  });
  it.each(['http://api.onequeue.dev', 'ftp://x', 'not a url', 'https://u:p@host', 'https://host/?a=1'])('rejects %s', (u) => {
    expect(() => validateApiUrl(u)).toThrow();
  });
});
