/**
 * Mock OneQueue API for tests (and the Docker smoke test).
 *
 * Scenarios:
 *   accepted  upload 202, verdict pass (default)
 *   pass      upload 202, verdict pending once, then pass
 *   fail      upload 202, verdict fail
 *   timeout   upload 202, verdict pending forever
 *   error500  upload always 500
 *
 * Run standalone: node test/mock-server.ts --scenario fail --port 8787 --record /tmp/req.jsonl
 */
import { appendFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { gunzipSync } from 'node:zlib';

export interface MockResponse {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
  /** Close the socket without a response (network error). */
  destroy?: boolean;
}

export interface MockConfig {
  /** Consumed in order; the last entry repeats. */
  upload: MockResponse[];
  verdict: MockResponse[];
  /** Expected bearer token. Requests without it get 401. */
  apiKey?: string;
}

export interface RecordedRequest {
  method: string;
  path: string;
  headers: IncomingMessage['headers'];
  /** Decoded (gunzipped) body text. */
  body: string;
  /** Parsed JSON body, if any. */
  json?: any;
}

export type ScenarioName = 'accepted' | 'pass' | 'fail' | 'timeout' | 'error500';

const UPLOAD_OK: MockResponse = { status: 202, body: { id: 'upl_test123', status: 'processing' } };
const err = (status: number, code: string, message: string): MockResponse => ({
  status,
  body: { error: { code, message, requestId: 'req_mock' } },
});

export const SCENARIOS: Record<ScenarioName, MockConfig> = {
  accepted: { upload: [UPLOAD_OK], verdict: [{ status: 200, body: { id: 'upl_test123', status: 'pass' } }] },
  pass: {
    upload: [UPLOAD_OK],
    verdict: [
      { status: 200, body: { id: 'upl_test123', status: 'pending' } },
      { status: 200, body: { id: 'upl_test123', status: 'pass', reason: 'No blocking findings' } },
    ],
  },
  fail: {
    upload: [UPLOAD_OK],
    verdict: [
      {
        status: 200,
        body: {
          id: 'upl_test123',
          status: 'fail',
          reason: '2 critical findings exceed fail-on=critical',
          detailsUrl: 'https://app.keytrionlabs.com/uploads/upl_test123',
        },
      },
    ],
  },
  timeout: { upload: [UPLOAD_OK], verdict: [{ status: 200, body: { id: 'upl_test123', status: 'pending' } }] },
  error500: { upload: [err(500, 'internal_error', 'Something went wrong')], verdict: [err(500, 'internal_error', 'x')] },
};

export interface MockServer {
  url: string;
  requests: RecordedRequest[];
  close(): Promise<void>;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export async function startMockServer(
  config: MockConfig,
  opts: { port?: number; host?: string; record?: string } = {},
): Promise<MockServer> {
  const requests: RecordedRequest[] = [];
  let uploadIdx = 0;
  let verdictIdx = 0;
  const next = (list: MockResponse[], i: number) => list[Math.min(i, list.length - 1)]!;

  const server: Server = createServer(async (req, res) => {
    const raw = await readBody(req);
    let body = '';
    try {
      body = req.headers['content-encoding'] === 'gzip' ? gunzipSync(raw).toString('utf8') : raw.toString('utf8');
    } catch {
      body = '<<invalid gzip>>';
    }
    const rec: RecordedRequest = { method: req.method ?? '', path: req.url ?? '', headers: req.headers, body };
    try {
      if (body) rec.json = JSON.parse(body);
    } catch {
      /* not json */
    }
    requests.push(rec);
    if (opts.record) appendFileSync(opts.record, `${JSON.stringify({ method: rec.method, path: rec.path, headers: rec.headers, body })}\n`);

    let r: MockResponse;
    if (config.apiKey !== undefined && req.headers.authorization !== `Bearer ${config.apiKey}`) {
      r = err(401, 'unauthorized', 'Invalid API key');
    } else if (req.method === 'POST' && req.url === '/v1/uploads') {
      r = next(config.upload, uploadIdx++);
    } else if (req.method === 'GET' && /^\/v1\/uploads\/[^/]+\/verdict$/.test(req.url ?? '')) {
      r = next(config.verdict, verdictIdx++);
    } else {
      r = err(404, 'not_found', 'Not found');
    }

    if (r.destroy) {
      req.socket.destroy();
      return;
    }
    res.writeHead(r.status, { 'content-type': 'application/json', ...r.headers });
    res.end(r.body === undefined ? '' : JSON.stringify(r.body));
  });

  await new Promise<void>((resolve) => server.listen(opts.port ?? 0, opts.host ?? '127.0.0.1', resolve));
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${addr.port}`,
    requests,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

// Standalone mode for the Docker smoke test.
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const arg = (name: string) => {
    const i = process.argv.indexOf(`--${name}`);
    return i > 0 ? process.argv[i + 1] : undefined;
  };
  const scenario = (arg('scenario') ?? 'accepted') as ScenarioName;
  const cfg = SCENARIOS[scenario];
  if (!cfg) throw new Error(`unknown scenario ${scenario}`);
  const s = await startMockServer(cfg, { port: Number(arg('port') ?? 8787), host: arg('host') ?? '127.0.0.1', record: arg('record') });
  console.log(`mock OneQueue API (${scenario}) listening on ${s.url}`);
}
