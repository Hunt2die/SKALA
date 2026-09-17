import test from 'node:test';
import assert from 'node:assert/strict';
import { createHandler } from '../worker/handler.mjs';
import { ProbeError } from '../worker/diagnostics.mjs';

const origin = 'https://skala.example.com';
const build = { version: '0.4.1', revision: 'test123', id: '0.4.1+test123' };
const assets = { '/index.html': { type: 'text/html', body: '<h1>SKALA</h1>' } };
const request = (body, headers = {}) => new Request(origin + '/api/scan', {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-skala-scan': '1', ...headers },
  body: JSON.stringify(body),
});
test('serves the interface and announces only implemented capabilities', async () => {
  const handle = createHandler(assets);
  assert.equal(await (await handle(new Request(origin))).text(), '<h1>SKALA</h1>');
  const health = await (await handle(new Request(origin + '/api/health'))).json();
  assert.equal(health.mode, 'live');
  assert.ok(health.capabilities.includes('reverse-dns'));
  assert.ok(!health.capabilities.includes('certificate-expiry'));
  assert.equal(health.backend, 'available');
  assert.equal(health.outbound, 'not_checked');
});
test('API is same-app JSON POST, with no permissive CORS', async () => {
  const handle = createHandler(assets, async () => { throw new Error('Should not run'); });
  assert.equal((await handle(new Request(origin + '/api/scan'))).status, 405);
  const cross = await handle(request({ domain: 'example.com' }, { 'sec-fetch-site': 'cross-site' }));
  assert.equal(cross.status, 403);
  assert.equal(cross.headers.get('access-control-allow-origin'), null);
  assert.equal((await handle(request({ domain: 'example.com' }, { 'x-skala-scan': 'no' }))).status, 403);
});
test('returns scan observations and does not forward incoming cookies', async () => {
  let received;
  const handle = createHandler(assets, async (...args) => { received = args; return { mode: 'live', domain: args[0] }; });
  const result = await handle(request({ domain: 'kinglaminaat.nl' }, { cookie: 'private=secret', authorization: 'Bearer private' }));
  assert.equal(result.status, 200);
  assert.equal((await result.json()).domain, 'kinglaminaat.nl');
  assert.deepEqual(received, ['kinglaminaat.nl', { excludedHosts: ['skala.example.com'], build: { version: 'development', revision: 'unbuilt', id: 'development' } }]);
});
test('invalid targets produce actionable client errors without a site verdict', async () => {
  const handle = createHandler(assets, async () => { throw new ProbeError('invalid_target', 'Public domains only.'); });
  const response = await handle(request({ domain: 'localhost' }));
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, 'Public domains only.');
});
test('oversized streamed request bodies are bounded', async () => {
  const handle = createHandler(assets);
  const response = await handle(request({ domain: 'x'.repeat(5000) }));
  assert.equal(response.status, 413);
});
test('repeat requests are throttled without running another scan', async () => {
  let count = 0;
  const handle = createHandler(assets, async () => { count++; return { mode: 'live' }; });
  assert.equal((await handle(request({ domain: 'example.com' }))).status, 200);
  const second = await handle(request({ domain: 'example.com' }));
  assert.equal(second.status, 429);
  assert.equal(second.headers.get('retry-after'), '5');
  assert.equal(count, 1);
});

test('stalled uploads time out and release every scan slot even when stream cancellation stalls', async () => {
  let scanned=0, cancelled=0;
  const handle=createHandler(assets,async()=>{scanned++;return {mode:'live'};},build,{inputTimeoutMs:25});
  const pending=[];
  for(let i=1;i<=3;i++) {
    const body=new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('{"domain":"'));},cancel(){cancelled++;return new Promise(()=>{});}});
    pending.push(handle(new Request(origin+'/api/scan',{method:'POST',body,duplex:'half',headers:{
      'content-type':'application/json','x-skala-scan':'1','cf-connecting-ip':'192.0.2.'+i,
    }})));
  }
  const valid=()=>request({domain:'example.com'},{'cf-connecting-ip':'192.0.2.4'});
  assert.equal((await handle(valid())).status,429);
  for(const response of await Promise.all(pending)) {
    assert.equal(response.status,408);
    assert.equal((await response.json()).code,'body_timeout');
  }
  assert.equal(cancelled,3);
  assert.equal(scanned,0);
  assert.equal((await handle(valid())).status,200);
  assert.equal(scanned,1);
});

test('aborting an upload stops input processing before the scan starts', async () => {
  let cancelled=false;
  const controller=new AbortController();
  const body=new ReadableStream({cancel(){cancelled=true;}});
  const handle=createHandler(assets,async()=>{assert.fail('Cancelled request must not scan');});
  const pending=handle(new Request(origin+'/api/scan',{method:'POST',body,duplex:'half',signal:controller.signal,
    headers:{'content-type':'application/json','x-skala-scan':'1'}}));
  controller.abort();
  const response=await pending;
  assert.equal(response.status,408);
  assert.equal((await response.json()).code,'request_aborted');
  assert.equal(cancelled,true);
});

test('health, scan reports and errors identify the same backend build', async () => {
  const handle = createHandler(assets, async () => ({ mode: 'live', summary: {} }), build);
  const health = await handle(new Request(origin + '/api/health'));
  assert.deepEqual((await health.json()).build, build);
  assert.equal(health.headers.get('x-skala-build'), build.id);
  const scan = await handle(request({ domain: 'example.com' }));
  assert.deepEqual((await scan.json()).build, build);
  assert.equal(scan.headers.get('x-skala-build'), build.id);
  const limited = await handle(request({ domain: 'example.com' }));
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get('x-skala-build'), build.id);
});
