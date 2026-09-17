// This service substitutes network responses, not the Worker's native fetch implementation.
export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.hostname === 'cloudflare-dns.com') {
      if (request.headers.get('accept') !== 'application/dns-json') throw new Error('Missing DoH Accept header');
      const name = url.searchParams.get('name'), type = url.searchParams.get('type');
      if (type === 'PTR') {
        if (name === '35.216.184.93.in-addr.arpa') return new Response('Unavailable', { status: 503 });
        const hostname = name === '34.216.184.93.in-addr.arpa' ? 's09.fixture.example.net.'
          : name === '4.1.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.0.1.1.a.2.ip6.arpa' ? 'ipv6.fixture.example.net.' : null;
        return Response.json({ Status: 0, Answer: hostname ? [{ name, type: 12, data: hostname, TTL: 600 }] : [] });
      }
      if (name.endsWith('redirect.example.com')) {
        return new Response('Moved', { status: 302, headers: { location: 'https://unexpected.example.net/' } });
      }
      if (name.endsWith('unavailable.example.com')) return new Response('Unavailable', { status: 503 });
      const address = name.endsWith('private.example.com') ? '10.0.0.7'
        : name.endsWith('header-only.example.com') ? '185.107.91.213'
        : name.endsWith('reverse-failure.example.com') ? '93.184.216.35' : '93.184.216.34';
      return Response.json({ Status: 0, Answer: type === 'A' ? [{ name, type: 1, data: address, TTL: 300 }]
        : type === 'AAAA' && name.endsWith('alpha.example.com') ? [{ name, type: 28, data: '2a11:800::414', TTL: 300 }] : [] });
    }
    if (url.hostname === 'header-only.example.com') return new Response('Fixture homepage', { status: 200,
      headers: { server: 'cloudflare', 'cf-ray': 'aabbccdd11223344-AMS', 'cf-cache-status': 'DYNAMIC' } });
    if (url.hostname === 'reverse-failure.example.com') return new Response('Fixture homepage', { status: 200 });
    if (url.hostname !== 'alpha.example.com') throw new Error('Unexpected website request: ' + url.hostname);
    if (url.protocol === 'http:') return new Response('Moved', { status: 301, headers: { location: 'https://alpha.example.com/' } });
    return new Response('Fixture homepage', { status: 200, headers: { server: 'fixture-server', 'set-cookie': 'private=never-return' } });
  }
};
