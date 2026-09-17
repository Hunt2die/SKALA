import { scanSite } from '../worker/diagnostics.mjs';
import { createHandler } from '../worker/handler.mjs';

function check(condition, message) { if (!condition) throw new Error(message); }

export const successfulScan = { async test() {
  const request = new Request('https://skala.example.com/api/scan', {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-skala-scan': '1' },
    body: JSON.stringify({ domain: 'alpha.example.com' })
  });
  const response = await createHandler({})(request, {}, {});
  const report = await response.json();
  check(response.status === 200, 'Scan endpoint failed');
  check(report.dns.queries.length === 9 && report.dns.queries.every(q => q.state !== 'error'),
    'Native Worker fetch must complete all nine DNS queries: ' + JSON.stringify(report.dns.queries));
  check(report.summary.state === 'reachable' && report.summary.status === 200, 'HTTPS response missing');
  check(report.http.steps.length === 2 && report.http.steps[0].status === 301, 'HTTP redirect trace missing');
  check(report.headers.server === 'fixture-server' && !report.headers['set-cookie'], 'Response header filtering failed');
}};

export const resolverRedirect = { async test() {
  const report = await scanSite('redirect.example.com');
  check(report.dns.queries.every(q => q.errorCode === 'resolver_redirect'), 'Resolver redirects must be rejected explicitly');
  check(!report.https.steps.length && !report.http.steps.length, 'Website checks must wait for verified public DNS');
  check(report.summary.state === 'unverified', 'Resolver redirects must not imply website health');
}};

export const resolverUnavailable = { async test() {
  const report = await scanSite('unavailable.example.com');
  check(report.dns.queries.every(q => q.errorCode === 'resolver_error' && q.error.includes('503')), 'Resolver HTTP errors must retain their cause');
  check(report.summary.detail.includes('503'), 'The overview must identify the resolver failure');
  check(!report.https.steps.length && !report.http.steps.length, 'Website probes must not run after resolver failure');
}};

export const privateAddress = { async test() {
  const report = await scanSite('private.example.com');
  check(report.dns.queries.every(q => q.state !== 'error'), 'The DNS fixture must respond');
  check(report.https.error?.code === 'blocked_target' && report.http.error?.code === 'blocked_target', 'Private addresses must remain blocked');
  check(!report.https.steps.length && !report.http.steps.length, 'A private hostname must never be requested');
}};

export const headerOnlyCloudflare = { async test() {
  const report = await scanSite('header-only.example.com');
  check(report.summary.state === 'reachable' && report.summary.status === 200, 'Header signals must not change website reachability');
  check(report.headers.server === 'cloudflare' && report.headers['cf-ray'], 'Keep the response evidence');
  check(report.cdn.state === 'possible' && report.cdn.provider === null, 'Multiple headers must not confirm Cloudflare');
  check(report.cdn.basis === 'headers-only', 'Expose the basis for the unconfirmed signal');
  check(report.cdn.dnsAddresses[0].address === '185.107.91.213' && report.cdn.dnsAddresses[0].cloudflareRange === null,
    'Include the contradictory network evidence');
}};

export const reverseResolution = { async test() {
  const report = await scanSite('alpha.example.com');
  const entries = report.reverseDNS.entries;
  check(entries.length === 2, 'Deduplicate public addresses shared by base and www');
  check(entries.every(entry => entry.query.state === 'ok' && entry.query.type === 'PTR'), 'Native Worker PTR requests must succeed');
  check(entries[0].hostnames[0] === 's09.fixture.example.net' && entries[1].hostnames[0] === 'ipv6.fixture.example.net',
    'Resolve both address families into their PTR hostnames');
  check(entries[0].sources.length === 2 && entries[0].query.records[0].ttl === 600, 'Keep attribution and TTL');
  check(report.mapping.server === null, 'PTR records must not assign an internal server');
}};

export const reverseFailure = { async test() {
  const report = await scanSite('reverse-failure.example.com');
  check(report.reverseDNS.entries[0].query.errorCode === 'resolver_error', 'Keep reverse DNS failure evidence');
  check(report.reverseDNS.entries[0].hostnames.length === 0, 'Do not fabricate a PTR hostname after a failed query');
  check(report.summary.state === 'reachable' && report.summary.status === 200, 'A failed PTR query must not change HTTP health');
}};
