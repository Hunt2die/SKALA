// This service substitutes network responses, not the Worker's native fetch implementation.
export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.hostname === 'cloudflare-dns.com') {
      if (request.headers.get('accept') !== 'application/dns-json') throw new Error('Missing DoH Accept header');
      const name = url.searchParams.get('name'), type = url.searchParams.get('type');
      if (name.endsWith('redirect.example.com')) {
        return new Response('Moved', { status: 302, headers: { location: 'https://unexpected.example.net/' } });
      }
      if (name.endsWith('unavailable.example.com')) return new Response('Unavailable', { status: 503 });
      const address = name.endsWith('private.example.com') ? '10.0.0.7' : '93.184.216.34';
      return Response.json({ Status: 0, Answer: type === 'A' ? [{ name, type: 1, data: address, TTL: 300 }] : [] });
    }
    if (url.hostname !== 'alpha.example.com') throw new Error('Unexpected website request: ' + url.hostname);
    if (url.protocol === 'http:') return new Response('Moved', { status: 301, headers: { location: 'https://alpha.example.com/' } });
    return new Response('Fixture homepage', { status: 200, headers: { server: 'fixture-server', 'set-cookie': 'private=never-return' } });
  }
};
