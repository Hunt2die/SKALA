import { scanSite, ProbeError } from './diagnostics.mjs';

const baseHeaders = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' };
const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), {
  status, headers: { ...baseHeaders, 'content-type': 'application/json; charset=utf-8', ...extra },
});
async function readInput(request, timeoutMs) {
  if (!request.headers.get('content-type')?.startsWith('application/json')) throw new ProbeError('content_type', 'Send a JSON request.');
  if (Number(request.headers.get('content-length')) > 4096) throw new ProbeError('body_size', 'The request is too large.');
  if (!request.body) throw new ProbeError('invalid_input', 'A domain is required.');
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  let timer, onAbort;
  const interrupted = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new ProbeError('body_timeout', 'The scan request took too long to arrive. Try again.')), timeoutMs);
    onAbort = () => reject(new ProbeError('request_aborted', 'The scan request was cancelled.'));
    if (request.signal.aborted) onAbort();
    else request.signal.addEventListener('abort', onAbort, { once: true });
  });
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), interrupted]);
      if (done) break;
      size += value.length;
      if (size > 4096) throw new ProbeError('body_size', 'The request is too large.');
      chunks.push(value);
    }
  } finally {
    clearTimeout(timer);
    request.signal.removeEventListener('abort', onAbort);
    // A stalled stream's cancellation may also stall; release the scan slot without awaiting it.
    void reader.cancel().catch(() => {});
  }
  const bytes = new Uint8Array(size);
  let pos = 0;
  for (const chunk of chunks) { bytes.set(chunk, pos); pos += chunk.length; }
  try { return JSON.parse(new TextDecoder().decode(bytes)); }
  catch { throw new ProbeError('invalid_json', 'The scan request was not valid JSON.'); }
}

export function createHandler(assets, scan = scanSite, build = { version: 'development', revision: 'unbuilt', id: 'development' }, { inputTimeoutMs = 5000 } = {}) {
  let active = 0;
  const recent = new Map();
  const respond = (data, status, headers) => json(data, status, { 'x-skala-build': build.id, ...headers });
  return async function handle(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/api/health') {
      return respond({ service: 'SKALA', version: build.version, build, mode: 'live', backend: 'available',
        outbound: 'not_checked', capabilities: ['http', 'https', 'redirects', 'dns', 'reverse-dns', 'response-headers', 'cloudflare-detection', 'manual-server-registration'] });
    }
    if (url.pathname === '/api/scan') {
      if (request.method !== 'POST') return respond({ error: 'Use POST for a scan.' }, 405, { allow: 'POST' });
      if (request.headers.get('x-skala-scan') !== '1' || request.headers.get('sec-fetch-site') === 'cross-site') {
        return respond({ error: 'Start the check from the SKALA interface.' }, 403);
      }
      const key = request.headers.get('cf-connecting-ip') || 'private-workspace';
      const now = Date.now();
      for (const [k, expiry] of recent) if (expiry <= now) recent.delete(k);
      if (active >= 3 || (recent.get(key) || 0) > now) return respond({ error: 'A check is already running, or was just requested. Try again shortly.' }, 429, { 'retry-after': '5' });
      active++;
      recent.set(key, now + 5000);
      try {
        const input = await readInput(request, inputTimeoutMs);
        const report = await scan(input?.domain, { excludedHosts: [url.hostname], build });
        return respond({ ...report, build });
      } catch (error) {
        if (error instanceof ProbeError) return respond({ error: error.message, code: error.code },
          error.code === 'body_size' ? 413 : ['body_timeout', 'request_aborted'].includes(error.code) ? 408 : 400);
        return respond({ error: 'The scan service could not finish this request. No site status was inferred.' }, 502);
      } finally { active--; }
    }
    if (!['GET', 'HEAD'].includes(request.method)) return new Response('Method not allowed', { status: 405, headers: { allow: 'GET, HEAD' } });
    const asset = assets[url.pathname === '/' ? '/index.html' : url.pathname];
    if (!asset) return new Response('Not found', { status: 404, headers: baseHeaders });
    return new Response(request.method === 'HEAD' ? null : asset.body, {
      headers: { ...baseHeaders, 'content-type': asset.type, 'referrer-policy': 'no-referrer' },
    });
  };
}
