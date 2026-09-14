import { parseTarget, validPublicHostname, ProbeError } from './target.mjs';
import { lookupRegistration } from './registration.mjs';
import { detectCloudflare } from './cloudflare.mjs';
export { parseTarget, validPublicHostname, ProbeError } from './target.mjs';

const DNS_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const TYPES = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };
const TYPE_NAMES = Object.fromEntries(Object.entries(TYPES).map(([k, v]) => [v, k]));
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const SAFE_HEADERS = new Set([
  'date', 'server', 'content-type', 'content-length', 'x-powered-by', 'location',
  'cache-control', 'age', 'expires', 'last-modified', 'strict-transport-security',
  'x-frame-options', 'x-content-type-options', 'referrer-policy', 'content-security-policy',
  'permissions-policy', 'cf-cache-status', 'cf-ray', 'via', 'x-cache', 'x-robots-tag',
]);
export function isPublicIP(address) {
  if (/^\d+(?:\.\d+){3}$/.test(address)) {
    const p = address.split('.').map(Number);
    if (p.some(n => n < 0 || n > 255)) return false;
    const [a, b, c] = p;
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 192 && b === 0 && (c === 0 || c === 2)) ||
      (a === 192 && b === 88 && c === 99) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113));
  }
  // Only global-unicast IPv6, excluding documentation and transition ranges.
  if (!/^[0-9a-f:]+$/i.test(address) || address.split('::').length > 2) return false;
  const halves = address.toLowerCase().split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  if (![...left, ...right].every(x => /^[a-f0-9]{1,4}$/.test(x))) return false;
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return false;
  const words = [...left, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...right].map(x => parseInt(x, 16));
  if (words.length !== 8 || words[0] < 0x2000 || words[0] > 0x3fff) return false;
  if (words[0] === 0x2001 && (words[1] < 0x200 || words[1] === 0xdb8)) return false;
  if (words[0] === 0x2002 || (words[0] === 0x3fff && words[1] <= 0x0fff)) return false;
  return true;
}

async function limitedText(response, limit = 65536) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new ProbeError('response_too_large', 'Resolver response exceeded its size limit.');
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return new TextDecoder().decode(bytes);
  } finally { await reader.cancel().catch(() => {}); }
}

async function timedRequest(fetcher, url, init, deadline, timeoutMs, consume) {
  const remaining = Math.min(timeoutMs, deadline - Date.now());
  if (remaining <= 0) throw new ProbeError('timeout', 'The scan time limit was reached.');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), remaining);
  try {
    const response = await fetcher(url, { ...init, signal: controller.signal });
    return await consume(response);
  } catch (error) {
    if (controller.signal.aborted) throw new ProbeError('timeout', 'No response before the probe timeout.');
    throw error;
  } finally { clearTimeout(timer); }
}

function readHeaders(headers) {
  const entries = [];
  for (const [name, value] of headers) {
    if (SAFE_HEADERS.has(name.toLowerCase())) entries.push([name.toLowerCase(), value.slice(0, 2048)]);
  }
  return Object.fromEntries(entries);
}

function failure(error) {
  return {
    code: error instanceof ProbeError ? error.code : 'fetch_failed',
    message: error instanceof ProbeError ? error.message : 'The probe could not complete this request. The site may block automated or cloud-hosted requests.',
  };
}

export function summarize(https, http) {
  const chosen = https.complete ? https : http.complete ? http : null;
  if (!chosen) {
    const error = https.error || http.error;
    return { state: 'unverified', title: 'Could not verify', detail: error?.message || 'Neither probe completed.',
      status: null, finalUrl: null, timeMs: null };
  }
  const last = chosen.steps.at(-1);
  const status = last.status;
  const secure = new URL(last.url).protocol === 'https:';
  const common = { status, finalUrl: last.url, timeMs: last.timeMs };
  if ([401, 403, 407, 429].includes(status)) return { ...common, state: 'restricted', title: 'Access restricted',
    detail: 'HTTP ' + status + ' received. The server responded, but this probe was not allowed normal access.' };
  if (status >= 400) return { ...common, state: 'http_error', title: 'HTTP error',
    detail: 'The server returned HTTP ' + status + ' to the homepage probe.' };
  if (status >= 200 && status < 300) return { ...common, state: secure ? 'reachable' : 'http_only',
    title: secure ? 'Reachable' : 'HTTP only',
    detail: secure ? 'The homepage returned HTTP ' + status + ' over HTTPS.' : 'The homepage responded over HTTP. HTTPS could not be confirmed.' };
  return { ...common, state: 'unverified', title: 'Response needs review',
    detail: 'HTTP ' + status + ' received, without a normal successful homepage response.' };
}

export async function scanSite(input, options = {}) {
  const target = parseTarget(input);
  const fetcher = options.fetcher || fetch;
  const startedAt = new Date().toISOString();
  const deadline = Date.now() + (options.budgetMs || 22000);
  const dnsTimeout = options.dnsTimeoutMs || 4500;
  const httpTimeout = options.httpTimeoutMs || 7000;
  const dnsCache = new Map(), hostChecks = new Map(), httpCache = new Map();
  const excluded = new Set(options.excludedHosts || []);
  const root = target.hostname.startsWith('www.') ? target.hostname.slice(4) : target.hostname;
  const www = 'www.' + root;

  function queryDNS(name, type) {
    const key = name + ':' + type;
    if (dnsCache.has(key)) return dnsCache.get(key);
    const promise = (async () => {
      try {
        const url = DNS_ENDPOINT + '?name=' + encodeURIComponent(name) + '&type=' + type;
        const data = await timedRequest(fetcher, url, {
          headers: { accept: 'application/dns-json' }, redirect: 'error', cache: 'no-store',
        }, deadline, dnsTimeout, async response => {
          if (!response.ok) throw new ProbeError('resolver_error', 'The DNS resolver returned HTTP ' + response.status + '.');
          return JSON.parse(await limitedText(response));
        });
        if (!Number.isInteger(data.Status) || data.TC) throw new ProbeError('resolver_error', 'The resolver returned an incomplete DNS response.');
        const answers = (Array.isArray(data.Answer) ? data.Answer : []).slice(0, 64)
          .filter(r => typeof r.name === 'string' && typeof r.data === 'string' && Number.isInteger(r.type))
          .map(r => ({ name: r.name.replace(/\.$/, ''), type: TYPE_NAMES[r.type] || String(r.type),
            value: r.data.slice(0, 2048), ttl: Number.isFinite(r.TTL) ? r.TTL : null }));
        const records = answers.filter(r => r.type === type);
        const state = data.Status === 3 ? 'nxdomain' : data.Status !== 0 ? 'error' : records.length ? 'ok' : 'no_data';
        return { name, type, state, status: data.Status, answers, records,
          error: state === 'error' ? 'DNS response code ' + data.Status : null };
      } catch (error) {
        return { name, type, state: 'error', status: null, answers: [], records: [], error: failure(error).message };
      }
    })();
    dnsCache.set(key, promise);
    return promise;
  }

  function checkHost(hostname) {
    const host = hostname.toLowerCase().replace(/\.$/, '');
    if (hostChecks.has(host)) return hostChecks.get(host);
    const promise = (async () => {
      if (!validPublicHostname(host) || excluded.has(host)) throw new ProbeError('blocked_target', 'The redirect target is not an eligible public website.');
      const results = await Promise.all([queryDNS(host, 'A'), queryDNS(host, 'AAAA')]);
      if (results.some(r => r.state === 'error')) throw new ProbeError('dns_error', 'Public address resolution could not be verified.');
      const addresses = results.flatMap(r => r.answers.filter(a => ['A', 'AAAA'].includes(a.type)).map(a => a.value));
      if (!addresses.length) throw new ProbeError('dns_no_address', 'No public A or AAAA address was found by this resolver.');
      if (addresses.some(a => !isPublicIP(a))) throw new ProbeError('blocked_target', 'The hostname resolves to a private or reserved address. The HTTP probe was stopped.');
      return addresses;
    })();
    hostChecks.set(host, promise);
    return promise;
  }

  function requestPage(url) {
    if (httpCache.has(url)) return httpCache.get(url);
    const promise = (async () => {
      const parsed = new URL(url);
      if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.port || url.length > 4096) {
        throw new ProbeError('blocked_redirect', 'The redirect uses an unsupported protocol, port or credentialed URL.');
      }
      await checkHost(parsed.hostname);
      const started = Date.now();
      return timedRequest(fetcher, url, {
        method: 'GET', redirect: 'manual', cache: 'no-store',
        headers: { 'user-agent': 'SKALA/' + (options.build?.version || 'development') + ' (public website status check)', accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5' },
      }, deadline, httpTimeout, async response => {
        const result = { url, status: response.status, timeMs: Math.max(0, Date.now() - started),
          headers: readHeaders(response.headers), location: response.headers.get('location') };
        // Status and headers only: never proxy page HTML, cookies or credentials.
        if (response.body) await response.body.cancel().catch(() => {});
        return result;
      });
    })();
    httpCache.set(url, promise);
    return promise;
  }

  async function trace(startUrl) {
    const steps = [], seen = new Set();
    let current = startUrl;
    try {
      for (let hop = 0; hop <= 5; hop++) {
        if (seen.has(current)) throw new ProbeError('redirect_loop', 'A redirect loop was detected.');
        seen.add(current);
        const page = await requestPage(current);
        steps.push({ url: page.url, status: page.status, timeMs: page.timeMs, headers: page.headers });
        if (!REDIRECTS.has(page.status)) return { startUrl, complete: true, steps, error: null };
        if (!page.location) throw new ProbeError('missing_location', 'A redirect response did not include a Location header.');
        let next;
        try { next = new URL(page.location, current); }
        catch { throw new ProbeError('invalid_redirect', 'The redirect Location was not a valid URL.'); }
        next.hash = '';
        if (next.href.length > 4096) throw new ProbeError('blocked_redirect', 'The redirect URL exceeds the probe limit.');
        steps.at(-1).redirectTo = next.href;
        if (hop === 5) throw new ProbeError('redirect_limit', 'The probe stopped after five redirects.');
        current = next.href;
      }
    } catch (error) { return { startUrl, complete: false, steps, error: failure(error) }; }
  }

  // DNS queries and both entry points run concurrently; repeated URLs share one request.
  const dnsJobs = [
    ...[root, www].flatMap(name => ['A', 'AAAA'].map(type => queryDNS(name, type))),
    ...['NS', 'MX', 'TXT', 'CNAME'].map(type => queryDNS(root, type)),
    queryDNS('_dmarc.' + root, 'TXT'),
  ];
  const [queries, https, http] = await Promise.all([
    Promise.all(dnsJobs), trace(target.entryUrls.https), trace(target.entryUrls.http),
  ]);
  const summary = summarize(https, http);
  const entrypoints = { https: summarize(https, { complete: false }), http: summarize(http, { complete: false }) };
  const primary = https.complete ? https : http.complete ? http : https.steps.length ? https : http;
  const last = primary.steps.at(-1);
  const records = [...new Map(queries.flatMap(q => q.answers).map(r => [r.name + '|' + r.type + '|' + r.value, r])).values()];
  const secureResponse = [...https.steps, ...http.steps].find(step => step.url.startsWith('https:'));
  const findings = [];
  if (summary.state !== 'reachable') findings.push({ id: 'status', severity: summary.state === 'http_error' ? 'error' : 'review', title: summary.title, detail: summary.detail, section: 'http' });
  for (const [protocol, entry] of Object.entries(entrypoints)) {
    if (['http_error', 'restricted'].includes(entry.state) &&
        (entry.status !== summary.status || entry.finalUrl !== summary.finalUrl)) {
      findings.push({ id: protocol + '_entry', severity: entry.state === 'http_error' ? 'error' : 'review',
        title: protocol.toUpperCase() + ' entry returned HTTP ' + entry.status,
        detail: entry.detail + ' Entry URL: ' + target.entryUrls[protocol], section: 'http' });
    }
  }
  if (https.error || http.error) findings.push({ id: 'incomplete', severity: 'info', title: 'A probe did not complete',
    detail: [https.error && 'HTTPS: ' + https.error.message, http.error && 'HTTP: ' + http.error.message].filter(Boolean).join(' '), section: 'redirect' });
  if (http.complete && http.steps.length > 2) findings.push({ id: 'redirects', severity: 'info', title: (http.steps.length - 1) + ' redirect hops',
    detail: 'Inspect the HTTP entry path before deciding whether every hop is needed.', section: 'redirect' });
  if ([...https.steps, ...http.steps].some(s => REDIRECTS.has(s.status) && s.url.startsWith('https:') && s.redirectTo?.startsWith('http:'))) {
    findings.push({ id: 'downgrade', severity: 'review', title: 'HTTPS redirects to HTTP', detail: 'A secure response redirects to an unencrypted URL.', section: 'redirect' });
  }
  const missingAAAA = queries.filter(q => q.type === 'AAAA').every(q => q.state === 'no_data' || q.state === 'nxdomain');
  if (missingAAAA) findings.push({ id: 'ipv6', severity: 'info', title: 'No IPv6 records observed', detail: 'The checked root and www names returned no AAAA record. This alone does not indicate an outage.', section: 'dns' });
  const dmarc = queries.find(q => q.name === '_dmarc.' + root);
  if (dmarc && ['no_data', 'nxdomain'].includes(dmarc.state)) findings.push({ id: 'dmarc', severity: 'info', title: 'No DMARC record at checked name',
    detail: 'No TXT record was returned for ' + dmarc.name + '. Parent-domain policy inheritance has not been evaluated.', section: 'dns' });
  if (queries.some(q => q.state === 'error')) findings.push({ id: 'dns_partial', severity: 'review', title: 'Some DNS checks were inconclusive',
    detail: 'Resolver failures are shown as unknown, rather than as missing records.', section: 'dns' });
  return {
    schemaVersion: 1, mode: 'live', domain: target.hostname, scope: 'homepage', startedAt, checkedAt: new Date().toISOString(),
    vantage: 'SKALA server-side probe', summary, entrypoints, target,
    dns: { resolver: 'Cloudflare 1.1.1.1 (DoH)', name: root, queries, records },
    https, http,
    environment: { server: last?.headers.server || null, poweredBy: last?.headers['x-powered-by'] || null, os: null, database: null, cms: null, source: 'reported response headers' },
    tls: { httpsResponse: Boolean(secureResponse), responseUrl: secureResponse?.url || null, responseStatus: secureResponse?.status ?? null,
      issuer: null, expiresAt: null, detail: 'HTTPS response availability only. Certificate issuer, expiry and origin TLS are not inspected.' },
    mapping: lookupRegistration(target.hostname),
    cdn: detectCloudflare(target.hostname, [...await Promise.all(dnsCache.values())], [https, http]),
    headers: last?.headers || {}, headersUrl: last?.url || null,
    findings,
  };
}
