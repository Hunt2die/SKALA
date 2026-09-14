import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createAssets } from '../scripts/assets.mjs';
import { withCloudflareAccess } from '../worker/access.mjs';

const { assets, build } = await createAssets();
const env = { SKALA_ALLOWED_EMAILS: ' owner@example.com, ADMIN@example.com ' };
const identity = email => ({ access: { getIdentity: async () => ({email}) } });

test('Cloudflare entry refuses unconfigured, unauthenticated, spoofed and non-allowed identities on every route', async () => {
  let calls=0;
  const handle=withCloudflareAccess(async()=>{calls++;return new Response('private');});
  for(const path of ['/','/api/health','/api/scan','/registration.js','/sw.js','/manifest.webmanifest','/icon-512.png']) {
    const request=new Request('https://skala.example.com'+path,{headers:{'cf-access-authenticated-user-email':'owner@example.com','cf-access-jwt-assertion':'forged'}});
    assert.equal((await handle(request,{},identity('owner@example.com'))).status,503);
    const denied=await handle(request,env,{});
    assert.equal(denied.status,403);
    assert.equal(denied.headers.get('cache-control'),'no-store');
    assert.equal((await handle(request,env,identity('other@example.com'))).status,403);
    assert.equal((await handle(request,env,identity('owner@example.com.attacker.test'))).status,403);
  }
  assert.equal(calls,0);
});

test('Cloudflare entry passes an allowed runtime identity and fails closed when identity lookup fails', async () => {
  const request=new Request('https://skala.example.com/');
  const ctx=identity('OWNER@example.com');
  const handle=withCloudflareAccess(async (r,e,c)=>{
    assert.equal(r,request);assert.equal(e,env);assert.equal(c,ctx);
    return new Response('private');
  });
  assert.equal(await (await handle(request,env,ctx)).text(),'private');
  assert.equal((await handle(request,env,identity(undefined))).status,403);
  assert.equal((await handle(request,env,{access:{getIdentity:async()=>{throw new Error('identity service unavailable');}}})).status,503);
});

test('PWA manifest points to real opaque PNG icons and all shipped markers are hydrated', () => {
  const manifest=JSON.parse(assets['/manifest.webmanifest'].body);
  assert.equal(manifest.name,'SKALA');
  assert.equal(manifest.display,'standalone');
  assert.equal(manifest.scope,'/');
  assert.equal(manifest.start_url,'/#overview');
  assert.ok(manifest.icons.some(i=>i.purpose==='maskable'));
  for(const icon of manifest.icons) {
    const url=new URL(icon.src,'https://skala.example.com');
    const asset=assets[url.pathname];
    const bytes=Buffer.from(asset.body,'base64');
    assert.equal(asset.type,'image/png');
    assert.equal(url.searchParams.get('v'),build.revision);
    assert.deepEqual([...bytes.subarray(0,8)],[137,80,78,71,13,10,26,10]);
    const size=Number(icon.sizes.split('x')[0]);
    assert.equal(bytes.readUInt32BE(16),size);
    assert.equal(bytes.readUInt32BE(20),size);
  }
  for(const asset of Object.values(assets)) if(asset.encoding!=='base64') assert.ok(!asset.body.includes('__SKALA_'));
  assert.match(assets['/index.html'].body,/rel="manifest"[^>]+crossorigin="use-credentials"/);
});

function workerHarness(fetcher) {
  const events=new Map();
  let claimed=false, skipped=false;
  const self={location:{origin:'https://skala.example.com'},addEventListener:(k,v)=>events.set(k,v),
    skipWaiting:async()=>{skipped=true;},clients:{claim:async()=>{claimed=true;}}};
  // Intentionally no Cache API: private data must not need an offline cache.
  vm.runInNewContext(assets['/sw.js'].body,{self,fetch:fetcher,URL,Response});
  return {events,state:()=>({claimed,skipped}),fetch(path,mode='navigate',method='GET') {
    let response;
    events.get('fetch')({request:{url:new URL(path,self.location.origin).href,mode,method},respondWith:value=>{response=value;}});
    return response;
  }};
}

test('service worker shows only a generic offline page after a navigation network failure', async () => {
  const sw=workerHarness(async()=>{throw new TypeError('offline');});
  const response=await sw.fetch('/');
  assert.equal(response.status,503);
  assert.equal(response.headers.get('cache-control'),'no-store');
  const body=await response.text();
  assert.match(body,/You’re offline/);
  assert.doesNotMatch(body,/kinglaminaat|Interfile|S01/);
  for(const event of ['install','activate']) await new Promise(resolve=>sw.events.get(event)({waitUntil:p=>p.then(resolve)}));
  assert.deepEqual(sw.state(),{claimed:true,skipped:true});
});

test('service worker passes through authentication and HTTP errors; API, sign-in and external paths are untouched', async () => {
  for(const status of [403,500,302]) {
    const response=new Response('sign-in or server response',{status});
    const sw=workerHarness(async()=>response);
    assert.equal(await sw.fetch('/index.html'),response);
    assert.equal(sw.fetch('/api/scan','cors','POST'),undefined);
    assert.equal(sw.fetch('/api/health'),undefined);
    assert.equal(sw.fetch('/cdn-cgi/access/login'),undefined);
    assert.equal(sw.fetch('/','cors'),undefined);
    assert.equal(sw.fetch('https://other.example.com/'),undefined);
  }
});
