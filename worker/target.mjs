export class ProbeError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

export function validPublicHostname(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host.length > 253 || !host.includes('.') || /^\d+(?:\.\d+){3}$/.test(host)) return false;
  if (!host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return false;
  return !/(?:^|\.)(localhost|local|internal|intranet|lan|home|test|invalid|example|onion)$/.test(host)
    && !host.endsWith('.home.arpa') && !host.endsWith('.localdomain');
}

export function parseTarget(input) {
  if (typeof input !== 'string' || input.length > 2048 || /[\s\\]/.test(input.trim())) {
    throw new ProbeError('invalid_target', 'Enter a public domain or an HTTP(S) URL.');
  }
  let url;
  try {
    const value = input.trim();
    url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : 'https://' + value);
  } catch { throw new ProbeError('invalid_target', 'Enter a valid domain or URL.'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.port) {
    throw new ProbeError('invalid_target', 'Use HTTP or HTTPS on its standard port, without login credentials.');
  }
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!validPublicHostname(hostname)) {
    throw new ProbeError('invalid_target', 'Only public DNS hostnames are supported. IP literals and local hosts are excluded.');
  }
  return { hostname, url: 'https://' + hostname + '/', scope: 'homepage',
    entryUrls: { https: 'https://' + hostname + '/', http: 'http://' + hostname + '/' },
    omittedPath: url.pathname !== '/' || Boolean(url.search || url.hash) };
}

