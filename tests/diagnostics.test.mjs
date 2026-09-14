import test from 'node:test';
import assert from 'node:assert/strict';
import { parseTarget, isPublicIP, scanSite } from '../worker/diagnostics.mjs';
import { cloudflareNetwork, detectCloudflare } from '../worker/cloudflare.mjs';
import { lookupRegistration } from '../worker/registration.mjs';

const domain = 'alpha.example.com';
const response = (status, headers = {}) => new Response(null, { status, headers });
function fixture({ page, address = '93.184.216.34', dnsError = false, dnsDelay = false } = {}) {
  const calls = [];
  const fetcher = async (input, init) => {
    const url = new URL(input);
    calls.push({ url: url.href, init });
    if (url.hostname === 'cloudflare-dns.com') {
      if (dnsDelay) return new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true }));
      if (dnsError) return response(503);
      const name = url.searchParams.get('name'), type = url.searchParams.get('type');
      const records = {
        A: [{ name, type: 1, data: address, TTL: 300 }],
        AAAA: [],
        NS: [{ name, type: 2, data: 'ns1.example.net.', TTL: 3600 }],
        CNAME: [],
        MX: [{ name, type: 15, data: '10 mail.example.com.', TTL: 300 }],
        TXT: [{ name, type: 16, data: '"v=spf1 -all"', TTL: 300 }],
      };
      return Response.json({ Status: name.startsWith('_dmarc.') ? 3 : 0, Answer: name.startsWith('_dmarc.') ? [] : records[type] });
    }
    if (page) return page(url, init);
    return url.protocol === 'http:' ? response(301, { location: 'https://' + domain + '/' }) :
      response(200, { server: 'nginx', 'x-powered-by': 'PHP/8.3', 'set-cookie': 'do-not-return=private', authorization: 'private', 'content-type': 'text/html' });
  };
  return { calls, fetcher, webCalls: () => calls.filter(c => !c.url.startsWith('https://cloudflare-dns.com/')) };
}

test('accepts public hostnames and normalizes input to the homepage', () => {
  assert.equal(parseTarget('https://ALPHA.example.com/path?q=1').hostname, domain);
  assert.equal(parseTarget('  alpha.example.com  ').url, 'https://' + domain + '/');
  assert.equal(parseTarget('https://alpha.example.com:443/').hostname, domain);
  assert.equal(parseTarget('www.alpha.example.com').hostname, 'www.alpha.example.com');
});
test('rejects local, credentialed, non-HTTP and nonstandard-port targets', () => {
  for (const value of ['', 'localhost', '127.1', '0x7f000001', '10.0.0.1', '[::1]', 'x.local', 'x.internal', 'x.home.arpa',
    'ftp://example.com', 'https://a:b@example.com', 'https://example.com:8443', 'a b.com', 'https://bad\\host.com']) {
    assert.throws(() => parseTarget(value), undefined, value);
  }
});
test('only eligible global addresses pass the address guard', () => {
  for (const ip of ['93.184.216.34', '1.1.1.1', '2606:4700:4700::1111', '2a00:1450:4001:800::200e']) assert.equal(isPublicIP(ip), true, ip);
  for (const ip of ['0.0.0.0', '10.1.2.3', '127.0.0.1', '169.254.169.254', '172.20.0.1', '192.168.1.1', '100.64.0.1',
    '192.0.2.84', '198.18.0.1', '198.51.100.2', '203.0.113.1', '224.0.0.1', '999.0.0.1', '::1', 'fc00::1', 'fe80::1',
    '::ffff:127.0.0.1', '2001:db8::1', '2002:7f00:1::', '3fff::1', '2606:::1']) assert.equal(isPublicIP(ip), false, ip);
});
test('real-shaped success includes paths and headers without response cookies', async () => {
  const f = fixture();
  const report = await scanSite(domain, { fetcher: f.fetcher });
  assert.equal(report.mode, 'live');
  assert.equal(report.summary.state, 'reachable');
  assert.equal(report.summary.status, 200);
  assert.equal(report.http.steps.length, 2);
  assert.equal(report.https.steps.length, 1);
  assert.equal(f.webCalls().length, 2, 'Repeated URLs should share one GET');
  assert.equal(report.headers.server, 'nginx');
  assert.equal(report.headers['set-cookie'], undefined);
  assert.equal(report.headers.authorization, undefined);
  assert.equal(report.tls.expiresAt, null);
  assert.equal(report.mapping.server, null);
  for (const call of f.webCalls()) {
    assert.equal(call.init.redirect, 'manual');
    assert.equal(call.init.method, 'GET');
    assert.equal(call.init.headers.cookie, undefined);
    assert.equal(call.init.headers.authorization, undefined);
  }
});
test('restriction and HTTP errors remain distinct from unreachable', async () => {
  for (const [status, state] of [[401, 'restricted'], [403, 'restricted'], [429, 'restricted'], [404, 'http_error'], [503, 'http_error']]) {
    const f = fixture({ page: () => response(status) });
    const report = await scanSite(domain, { fetcher: f.fetcher });
    assert.equal(report.summary.state, state);
    assert.equal(report.summary.status, status);
  }
});
test('HTTPS transport failure can still expose an HTTP-only response', async () => {
  const f = fixture({ page: url => { if (url.protocol === 'https:') throw new TypeError('network'); return response(200); } });
  const report = await scanSite(domain, { fetcher: f.fetcher });
  assert.equal(report.summary.state, 'http_only');
  assert.equal(report.tls.httpsResponse, false);
  assert.equal(report.https.complete, false);
});
test('network failures never become a fabricated HTTP error or healthy result', async () => {
  const f = fixture({ page: () => { throw new TypeError('network'); } });
  const report = await scanSite(domain, { fetcher: f.fetcher });
  assert.equal(report.summary.state, 'unverified');
  assert.equal(report.summary.status, null);
  assert.equal(report.https.steps.length, 0);
});
test('DNS failure is unknown, not a missing AAAA or DMARC record', async () => {
  const f = fixture({ dnsError: true });
  const report = await scanSite(domain, { fetcher: f.fetcher });
  assert.equal(f.webCalls().length, 0);
  assert.equal(report.summary.state, 'unverified');
  assert.ok(!report.findings.some(f => ['ipv6', 'dmarc'].includes(f.id)));
  assert.ok(report.findings.some(f => f.id === 'dns_partial'));
  assert.equal(report.dns.queries[0].errorCode, 'resolver_error');
  assert.match(report.summary.detail, /Public DNS verification failed:.*DNS resolver returned HTTP 503/);
});
test('DNS failures distinguish runtime options, connectivity and malformed resolver responses', async () => {
  for (const [fetcher, code] of [
    [() => { throw new TypeError('Invalid redirect value, must be one of follow or manual'); }, 'runtime_redirect_mode'],
    [() => { throw new TypeError('network failure with https://private.example.com/?secret=hidden'); }, 'resolver_network'],
    [() => new Response('<html>upstream error</html>'), 'resolver_format'],
    [() => Response.json(null), 'resolver_error'],
  ]) {
    const report = await scanSite(domain, { fetcher });
    assert.ok(report.dns.queries.every(q => q.errorCode === code), code);
    assert.equal(report.summary.state, 'unverified');
    assert.ok(!JSON.stringify(report).includes('secret=hidden'));
    assert.ok(!JSON.stringify(report).includes('<html>'));
    assert.match(report.findings.find(f => f.id === 'dns_partial').title, /All DNS checks failed/);
  }
});
test('DNS timeout completes with an inconclusive report', async () => {
  const f = fixture({ dnsDelay: true });
  const report = await scanSite(domain, { fetcher: f.fetcher, dnsTimeoutMs: 15, budgetMs: 200 });
  assert.equal(report.summary.state, 'unverified');
  assert.equal(f.webCalls().length, 0);
});
test('private addresses returned by public DNS prevent the HTTP request', async () => {
  const f = fixture({ address: '10.0.0.7' });
  const report = await scanSite(domain, { fetcher: f.fetcher });
  assert.equal(f.webCalls().length, 0);
  assert.equal(report.https.error.code, 'blocked_target');
});
test('every redirect is validated before contacting a different host', async () => {
  const f = fixture({ page: () => response(302, { location: 'http://169.254.169.254/latest/meta-data/' }) });
  const report = await scanSite(domain, { fetcher: f.fetcher });
  assert.ok(f.webCalls().every(c => new URL(c.url).hostname === domain));
  assert.equal(report.summary.state, 'unverified');
  assert.equal(report.https.steps.length, 1);
});
test('private resolution on a redirected hostname is also blocked', async () => {
  const f = fixture({ page: () => response(301, { location: 'https://private.example.com/' }) });
  const fetcher = (url, init) => {
    if (String(url).includes('name=private.example.com') && String(url).includes('type=A')) {
      return Promise.resolve(Response.json({ Status: 0, Answer: [{ name: 'private.example.com', type: 1, data: '192.168.1.1', TTL: 300 }] }));
    }
    return f.fetcher(url, init);
  };
  const report = await scanSite(domain, { fetcher });
  assert.ok(f.webCalls().every(c => new URL(c.url).hostname === domain));
  assert.equal(report.https.error.code, 'blocked_target');
});
test('loops and redirect caps retain the responses already observed', async () => {
  const loop = fixture({ page: url => response(301, { location: url.href }) });
  const a = await scanSite(domain, { fetcher: loop.fetcher });
  assert.equal(a.https.error.code, 'redirect_loop');
  assert.equal(a.https.steps.length, 1);
  const endless = fixture({ page: url => response(302, { location: url.origin + '/hop/' + (Number(url.pathname.split('/').at(-1)) + 1) }) });
  const b = await scanSite(domain, { fetcher: endless.fetcher });
  assert.equal(b.https.error.code, 'redirect_limit');
  assert.equal(b.https.steps.length, 6);
});
test('the app cannot recursively scan its own hostname', async () => {
  const f = fixture();
  const report = await scanSite(domain, { fetcher: f.fetcher, excludedHosts: [domain] });
  assert.equal(f.webCalls().length, 0);
  assert.equal(report.https.error.code, 'blocked_target');
});

test('downgrade findings use normalized redirect destinations only', async () => {
  for (const location of ['http://alpha.example.com/', 'HTTP://alpha.example.com/', 'HtTp://alpha.example.com/']) {
    const f = fixture({ page: url => url.protocol === 'https:' ? response(301, { location }) : response(200) });
    const r = await scanSite(domain, { fetcher: f.fetcher });
    assert.ok(r.findings.some(f => f.id === 'downgrade'), location);
    assert.equal(r.https.steps[0].redirectTo, 'http://alpha.example.com/');
  }
  for (const status of [200, 201, 404]) {
    const f = fixture({ page: () => response(status, { location: 'http://alpha.example.com/' }) });
    const r = await scanSite(domain, { fetcher: f.fetcher });
    assert.ok(!r.findings.some(f => f.id === 'downgrade'), String(status));
    assert.equal(r.https.steps[0].redirectTo, undefined);
  }
});
test('relative and protocol-relative secure redirects do not raise downgrade warnings', async () => {
  for (const location of ['/landing', '//alpha.example.com/landing']) {
    const f = fixture({ page: url => url.pathname === '/' ? response(302, { location }) : response(200) });
    const r = await scanSite(domain, { fetcher: f.fetcher });
    assert.equal(r.summary.state, 'reachable');
    assert.ok(!r.findings.some(f => f.id === 'downgrade'));
  }
});
test('HTTP entry failures stay visible when the HTTPS homepage is reachable', async () => {
  for (const [status, severity] of [[500, 'error'], [403, 'review']]) {
    const f = fixture({ page: url => response(url.protocol === 'http:' ? status : 200) });
    const r = await scanSite(domain, { fetcher: f.fetcher });
    assert.equal(r.summary.state, 'reachable');
    assert.equal(r.entrypoints.https.status, 200);
    assert.equal(r.entrypoints.http.status, status);
    assert.equal(r.findings.find(f => f.id === 'http_entry')?.severity, severity);
  }
});
test('a shared failing final response does not create duplicate entry findings', async () => {
  const f = fixture({ page: url => url.protocol === 'http:' ? response(301, { location: 'https://' + domain + '/' }) : response(503) });
  const r = await scanSite(domain, { fetcher: f.fetcher });
  assert.equal(r.summary.state, 'http_error');
  assert.equal(r.findings.filter(f => f.severity === 'error').length, 1);
});
test('reported homepage targets match the actual requests and identify removed URL parts', async () => {
  const f = fixture();
  const r = await scanSite('https://ALPHA.example.com./contact/?token=private#section', { fetcher: f.fetcher });
  assert.deepEqual(r.target.entryUrls, { https: 'https://' + domain + '/', http: 'http://' + domain + '/' });
  assert.equal(r.target.omittedPath, true);
  assert.equal(f.webCalls().length, 2);
  assert.ok(f.webCalls().every(c => new URL(c.url).pathname === '/' && !new URL(c.url).search));
  assert.ok(!JSON.stringify(r).includes('token=private'));
  assert.equal(parseTarget(domain).omittedPath, false);
});

test('Cloudflare network matching respects IPv4/IPv6 boundaries and rejects malformed addresses', () => {
  for (const ip of ['104.16.0.0','104.23.255.255','172.71.255.255','2606:4700::1','2a06:98c7:ffff::1']) {
    assert.ok(cloudflareNetwork(ip),ip);
  }
  for (const ip of ['104.15.255.255','104.28.0.0','172.72.0.0','2606:4701::1','2a06:98c8::1','1.1.1.1','999.0.0.1','2606:::1','']) {
    assert.equal(cloudflareNetwork(ip),null,ip);
  }
});

test('proxy detection uses target evidence; resolver choice and nameservers alone do not prove proxying', async () => {
  const f = fixture();
  const plain = await scanSite(domain,{fetcher:f.fetcher});
  assert.equal(plain.cdn.state,'not_observed');
  assert.equal(plain.cdn.provider,null);
  const nsQuery = value => ({ name:domain,type:'NS',state:'ok',records:[{name:domain,type:'NS',value}] });
  const dnsOnly = detectCloudflare(domain,[nsQuery('ada.ns.cloudflare.com.')],[plain.https,plain.http]);
  assert.equal(dnsOnly.state,'dns_observed');
  assert.equal(dnsOnly.evidence.length,0);
  assert.equal(dnsOnly.dnsEvidence.length,1);
  const lookalike = detectCloudflare(domain,[nsQuery('ada.ns.cloudflare.com.evil.test')],[plain.https,plain.http]);
  assert.equal(lookalike.dnsProvider,null);
  const unknown = await scanSite(domain,{fetcher:fixture({dnsError:true}).fetcher});
  assert.equal(unknown.cdn.state,'unverified');
});

test('Cloudflare headers and public addresses produce scoped, exportable evidence without claiming an origin', async () => {
  const viaHeaders = await scanSite(domain,{fetcher:fixture({page:()=>response(403,{
    server:'cloudflare','cf-ray':'aabbccdd11223344-AMS','cf-cache-status':'DYNAMIC',
  })}).fetcher});
  assert.equal(viaHeaders.cdn.state,'detected');
  assert.equal(viaHeaders.summary.state,'restricted');
  assert.equal(viaHeaders.cdn.hostname,domain);
  assert.ok(viaHeaders.cdn.evidence.every(e=>e.source.startsWith('http')));
  assert.equal(viaHeaders.mapping.server,null);
  const networkOnly = await scanSite(domain,{fetcher:fixture({address:'104.16.1.2'}).fetcher});
  assert.equal(networkOnly.cdn.state,'detected');
  assert.ok(networkOnly.cdn.evidence.some(e=>e.kind==='network' && e.range==='104.16.0.0/13'));
  const single = await scanSite(domain,{fetcher:fixture({page:()=>response(200,{server:'cloudflare'})}).fetcher});
  assert.equal(single.cdn.state,'possible');
});

test('Cloudflare on a redirect destination is not attributed to the requested hostname', async () => {
  const r = await scanSite(domain,{fetcher:fixture({page:u=>u.hostname===domain
    ? response(302,{location:'https://elsewhere.example.net/'})
    : response(200,{server:'cloudflare','cf-ray':'aabbccdd11223344-AMS'})}).fetcher});
  assert.equal(r.cdn.state,'not_observed');
  assert.equal(r.cdn.otherHosts[0].hostname,'elsewhere.example.net');
  assert.equal(r.cdn.otherHosts[0].state,'detected');
  assert.equal(r.mapping.server,null);
});

test('manual registration is an exact, sourced match and remains available when public DNS fails', async () => {
  const known = lookupRegistration('KINGLAMINAAT.NL.');
  assert.equal(known.server,'S01');
  assert.equal(known.provider,'Interfile');
  assert.equal(known.method,'manual');
  assert.match(known.source,/colleague/);
  for (const host of ['kinglaminaat.nl.evil.test','notkinglaminaat.nl','www.kinglaminaat.nl',domain]) {
    assert.equal(lookupRegistration(host).state,'unmapped');
  }
  const r = await scanSite('kinglaminaat.nl',{fetcher:fixture({dnsError:true}).fetcher});
  assert.equal(r.mapping.server,'S01');
  assert.equal(r.cdn.state,'unverified');
  assert.equal(r.summary.state,'unverified');
  assert.equal(r.mapping.recordedAt,'2026-09-14');
});
