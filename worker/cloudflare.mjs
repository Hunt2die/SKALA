// Published Cloudflare proxy networks, checked 2026-09-14.
// https://www.cloudflare.com/ips-v4/ and https://www.cloudflare.com/ips-v6/
// A match identifies the public network, never an internal/origin server.
const networks = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];
function ipNumber(address) {
  if (/^\d+(?:\.\d+){3}$/.test(address)) {
    const parts = address.split('.').map(Number);
    if (parts.some(n => n > 255)) return null;
    return { bits: 32, value: parts.reduce((n, p) => (n << 8n) + BigInt(p), 0n) };
  }
  const halves = address.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  if (![...left, ...right].every(word => /^[a-f0-9]{1,4}$/i.test(word))) return null;
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const words = [...left, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...right];
  return { bits: 128, value: words.reduce((n, word) => (n << 16n) + BigInt('0x' + word), 0n) };
}
const ranges = networks.map(cidr => {
  const [address, prefix] = cidr.split('/');
  return { ...ipNumber(address), prefix: Number(prefix), cidr };
});
export function cloudflareNetwork(address) {
  const ip = ipNumber(String(address));
  if (!ip) return null;
  return ranges.find(range => ip.bits === range.bits &&
    ip.value >> BigInt(ip.bits - range.prefix) === range.value >> BigInt(ip.bits - range.prefix))?.cidr || null;
}
const normalHost = value => value.toLowerCase().replace(/\.$/, '');

export function detectCloudflare(hostname, queries, traces) {
  const host = normalHost(hostname);
  const steps = [...new Map(traces.flatMap(trace => trace.steps).map(step => [step.url, step])).values()];
  function observe(name) {
    const evidence = [];
    const addresses = queries.filter(q => q.name === name && ['A','AAAA'].includes(q.type) && q.state === 'ok')
      .flatMap(q => q.records.map(record => ({ hostname: name, type: q.type, address: record.value,
        cloudflareRange: cloudflareNetwork(record.value) })));
    for (const record of addresses) {
      if (record.cloudflareRange) evidence.push({ kind: 'network', value: record.address,
        source: name + ' DNS', range: record.cloudflareRange });
    }
    const responses = steps.filter(step => normalHost(new URL(step.url).hostname) === name);
    for (const step of responses) {
      const h = step.headers;
      const signals = [
        ['server', /^cloudflare$/i.test(h.server || '')],
        ['cf-ray', /^[a-f0-9]{16,32}(?:-[a-z]{3})?$/i.test(h['cf-ray'] || '')],
        ['cf-cache-status', /^(HIT|MISS|DYNAMIC|BYPASS|EXPIRED|STALE|UPDATING|REVALIDATED|NONE|UNKNOWN)$/i.test(h['cf-cache-status'] || '')],
      ].filter(([, present]) => present);
      for (const [key] of signals) evidence.push({ kind: 'header', value: key + ': ' + h[key], source: step.url });
    }
    // Multiple headers from one request path are not independent corroboration.
    // In particular, a Worker may observe headers from intermediaries on its own path.
    // Require a DNS address in a published Cloudflare range for this exact hostname.
    const networkMatch = evidence.some(item => item.kind === 'network');
    const state = networkMatch ? 'detected'
      : evidence.length ? 'possible' : responses.length || addresses.length ? 'not_observed' : 'unverified';
    return { hostname: name, state, basis: networkMatch ? 'dns-network' : evidence.length ? 'headers-only' : null,
      dnsAddresses: addresses, evidence };
  }
  const result = observe(host);
  const ns = queries.filter(q => q.type === 'NS' && q.state === 'ok').flatMap(q => q.records)
    .filter(record => /\.ns\.cloudflare\.com\.?$/i.test(record.value));
  // Nameservers and resolver identity must never become proxy detections.
  if (ns.length && ['not_observed','unverified'].includes(result.state)) {
    result.state = 'dns_observed';
    result.basis = 'nameservers-only';
  }
  return { ...result, provider: result.state === 'detected' ? 'Cloudflare' : null,
    dnsProvider: ns.length ? 'Cloudflare' : null,
    dnsEvidence: ns.map(record => ({ kind: 'nameserver', value: record.value, source: record.name })),
    otherHosts: [...new Set(steps.map(step => normalHost(new URL(step.url).hostname)))]
      .filter(name => name !== host).map(observe).filter(item => ['detected','possible'].includes(item.state)),
    networkListCheckedAt: '2026-09-14',
    detail: 'Cloudflare detection requires a DNS address in a published Cloudflare proxy range for the named host. Headers alone remain unconfirmed: intermediaries on the probe request path can supply them. A non-matching address does not rule out all Cloudflare services or custom IP configurations. WAF settings and origin hosting are not verified.' };
}
