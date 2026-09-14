import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { setImmediate as tick } from 'node:timers/promises';
import { createAssets } from '../scripts/assets.mjs';
import { scanSite, parseTarget } from '../worker/diagnostics.mjs';

const { assets, build } = await createAssets();
const html = assets['/index.html'].body;
const freshHealth = () => Response.json({ service: 'SKALA', mode: 'live', build, outbound: 'not_checked' });
async function snapshot(dnsFails = false) {
  const r = await scanSite('alpha.example.com', { fetcher: async input => {
    const u = new URL(input);
    if (u.hostname === 'cloudflare-dns.com') {
      if (dnsFails) return new Response(null, { status: 503 });
      return Response.json({ Status: 0, Answer: u.searchParams.get('type') === 'A'
        ? [{ name: u.searchParams.get('name'), type: 1, data: '93.184.216.34', TTL: 300 }] : [] });
    }
    return new Response(null, { status: 200 });
  }});
  return { ...r, build };
}
function harness(fetcher) {
  const nodes = new Map();
  const events = new Map();
  function node(id = '') {
    const attributes = new Map(), events = new Map();
    return { id, dataset: {}, hidden: false, disabled: false, innerHTML: '', textContent: '', value: '', title: '',
      classList: { add() {}, remove() {}, toggle() {} },
      setAttribute(k,v) { attributes.set(k,String(v)); }, getAttribute(k) { return attributes.get(k); },
      toggleAttribute(k,on) { if(on) attributes.set(k,''); else attributes.delete(k); },
      addEventListener(k,v) { events.set(k,v); }, events,
      focus() {}, scrollIntoView() {}, append() {}, remove() {}, click() {}, showModal() {}, close() {} };
  }
  for (const [, id] of html.matchAll(/\bid="([^"]+)"/g)) nodes.set('#' + id, node(id));
  for (const [, id, value] of html.matchAll(/<[^>]+\bid="([^"]+)"[^>]*>([^<]*)<\//g)) {
    nodes.get('#' + id).textContent = value;
  }
  nodes.get('#buildMetadata').textContent = JSON.stringify(build);
  nodes.get('#domainInput').value = 'kinglaminaat.nl';
  const get = selector => {
    if (!nodes.has(selector)) {
      if(selector.startsWith('#') && !selector.includes(' ')) throw new Error('Missing element: ' + selector);
      nodes.set(selector,node(selector));
    }
    return nodes.get(selector);
  };
  const tabs = ['overview','infrastructure','dns','http','findings'].map(name => {
    const tab = get('#tab-' + name); tab.dataset.view = name; return tab;
  });
  const traces = ['https','http'].map(name => { const tab = get('#' + name + 'Tab'); tab.dataset.trace = name; return tab; });
  const panels = ['serverPanel','ipPanel','environmentPanel','nameserverPanel','dnsPanel','certificatePanel'].map(id => get('#' + id + ' .panel-content'));
  const all = selector => ({ '[data-view]': tabs, '[data-trace]': traces, '.panel-content': panels,
    '.view-panel': tabs.map(t => get('#view-' + t.dataset.view)), '[data-action="export"]': [get('.export-report')] }[selector] || []);
  let savedBlob;
  class BrowserURL extends URL {
    static createObjectURL(blob) { savedBlob = blob; return 'blob:preview'; }
    static revokeObjectURL() {}
  }
  const body = node('body');
  const document = { querySelector: get, querySelectorAll: all, addEventListener() {},
    documentElement: { dataset: { theme: 'dark' } }, body, createElement: () => node() };
  const sandbox = { document, URL: BrowserURL, Response, Blob, AbortController, AbortSignal, fetch: fetcher,
    location: { protocol: 'https:', hash: '' }, history: { pushState() {} },
    localStorage: { getItem: () => null, setItem() {} }, matchMedia: query => ({ matches: query.includes('reduced-motion') }),
    navigator: { onLine: true, serviceWorker: { register: async () => ({}) } },
    setTimeout: () => 0, clearTimeout() {}, addEventListener(k,v) { events.set(k,v); } };
  sandbox.window = sandbox;
  const context = vm.createContext(sandbox);
  for (const name of ['target.js','registration.js','app.js','workspace.js','pwa.js']) vm.runInContext(assets['/' + name].body,context,{filename:name});
  return { context, get, events, run: code => vm.runInContext(code,context), blob: () => savedBlob };
}

test('install control offers instructions, uses a browser prompt once and hides after installation', async () => {
  const h = harness(async () => freshHealth());
  assert.equal(h.get('#installApp').hidden,false);
  const click = h.get('#installApp').events.get('click');
  await click();
  assert.equal(h.get('#detailTitle').textContent,'Install SKALA');
  let prompted=0, prevented=0;
  h.events.get('beforeinstallprompt')({preventDefault(){prevented++;},prompt:async()=>{prompted++;},userChoice:Promise.resolve({outcome:'accepted'})});
  await click();
  await click();
  assert.equal(prompted,1);
  assert.equal(prevented,1);
  h.events.get('appinstalled')();
  assert.equal(h.get('#installApp').hidden,true);
});

test('offline state prevents new scans without discarding the open snapshot, and reconnect respects an active scan', async () => {
  let scans=0;
  const result=await snapshot();
  const h=harness(async path=>{ if(path==='/api/health') return freshHealth(); scans++; return Response.json(result); });
  await h.run('runScan("alpha.example.com")');
  h.context.navigator.onLine=false;
  h.events.get('offline')();
  assert.equal(h.get('#connectivityNotice').hidden,false);
  assert.equal(h.get('#scanButton').disabled,true);
  await h.run('runScan("beta.example.com")');
  assert.equal(scans,1);
  assert.equal(h.run('report.domain'),'alpha.example.com');
  h.run('setBusy(true)');
  h.context.navigator.onLine=true;
  h.events.get('online')();
  assert.equal(h.get('#scanButton').disabled,true);
  h.run('setBusy(false)');
  assert.equal(h.get('#scanButton').disabled,false);
  assert.equal(h.get('#connectivityNotice').hidden,true);
});

test('browser and probe share URL normalization, while backend readiness leaves checks unverified', async () => {
  const h = harness(async () => freshHealth());
  await tick();
  assert.equal(h.get('#probeBackend').textContent, 'Backend: Available');
  assert.equal(h.get('#probeDns').textContent, 'DNS: Not checked');
  assert.equal(h.get('#probeHttps').textContent, 'HTTPS: Not checked');
  const value = 'https://ALPHA.example.com./contact/?q=1#section';
  h.get('#domainInput').value = value;
  h.run('renderTarget()');
  assert.equal(h.get('#scanTarget').dataset.adjusted,'true');
  assert.ok(h.get('#scanTarget').innerHTML.includes('https://alpha.example.com/'));
  assert.ok(!h.get('#scanTarget').innerHTML.includes('/contact/'));
  h.context.targetInput = value;
  assert.deepEqual(JSON.parse(h.run('JSON.stringify(SkalaTarget.parseTarget(targetInput))')),parseTarget(value));
  h.get('#domainInput').value = 'http://127.0.0.1/';
  h.run('renderTarget()');
  assert.match(h.get('#scanTarget').textContent,/Enter a public domain/);
});

test('scan observations distinguish resolver failure and clear stale data after a backend failure', async () => {
  const good = await snapshot(), failedDns = await snapshot(true);
  const queue = [good,failedDns,null];
  const h = harness(async path => {
    if(path === '/api/health') return freshHealth();
    const next = queue.shift();
    if(!next) throw new TypeError('network unavailable');
    return Response.json(next);
  });
  await tick();
  await h.run('runScan("alpha.example.com")');
  assert.equal(h.get('#probeHttps').textContent,'HTTPS: 200');
  await h.run('runScan("alpha.example.com")');
  assert.equal(h.get('#probeBackend').dataset.state,'ok');
  assert.equal(h.get('#probeDns').textContent,'DNS: 0/9 replies');
  assert.equal(h.get('#probeHttps').textContent,'HTTPS: Not attempted');
  assert.equal(h.get('#statusCard').dataset.state,'unverified');
  assert.match(h.get('#scanFeedback').textContent,/HTTP\/HTTPS checks were not started\..*503/);
  assert.match(h.get('#view-dns').innerHTML,/resolver_error/);
  assert.equal(h.get('#toast').textContent,'DNS failed · website status not checked');
  await h.run('runScan("beta.example.com")');
  assert.equal(h.get('#probeBackend').dataset.state,'review');
  assert.equal(h.get('#probeDns').textContent,'DNS: No result');
  assert.equal(h.run('report'),null);
  assert.equal(h.get('.export-report').disabled,true);
  assert.ok(!h.get('#view-dns').innerHTML.includes('93.184.216.34'));
});

test('a late initial health response cannot overwrite a failed scan connection', async () => {
  let finishHealth;
  const pending = new Promise(resolve => { finishHealth = resolve; });
  const h = harness(async path => path === '/api/health' ? pending : Promise.reject(new TypeError('offline')));
  await h.run('runScan("alpha.example.com")');
  finishHealth(freshHealth());
  await tick();
  assert.equal(h.get('#probeBackend').textContent,'Backend: Unavailable');
});

test('exports retain the backend and interface build IDs and mismatches are visible', async () => {
  const result = await snapshot();
  result.build = { version:'0.4.0',revision:'older',id:'0.4.0+older' };
  const h = harness(async path => path === '/api/health' ? freshHealth() : Response.json(result));
  await tick();
  await h.run('runScan("alpha.example.com")');
  assert.equal(h.get('#buildNotice').hidden,false);
  assert.match(h.get('#buildNotice').textContent,/0\.4\.0\+older/);
  h.run('exportReport()');
  const exported = JSON.parse(await h.blob().text());
  assert.deepEqual(exported.build,result.build);
  assert.deepEqual(exported.interfaceBuild,build);
  assert.ok(html.includes(build.revision));
  assert.ok(!html.includes('__SKALA_'));
});

test('registered server is visible before scanning, updates with the input and survives unavailable probes', async () => {
  const h = harness(async path=>path==='/api/health'?freshHealth():Promise.reject(new TypeError('offline')));
  assert.match(h.get('#registrationHint').innerHTML,/S01 · Interfile/);
  assert.match(h.get('#registrationHint').innerHTML,/Manual record/);
  h.get('#domainInput').value='alpha.example.com';
  h.run('renderTarget()');
  assert.ok(!h.get('#registrationHint').innerHTML.includes('S01'));
  h.get('#domainInput').value='kinglaminaat.nl';
  await h.run('runScan("kinglaminaat.nl")');
  assert.match(h.get('#registrationHint').innerHTML,/S01 · Interfile/);
  assert.equal(h.get('#cdnNotice').hidden,true);
  assert.equal(h.get('#cdnBadge').hidden,true);
});

test('Cloudflare shield, server source and export agree; new and failed scans remove stale identity badges', async () => {
  const known = await scanSite('kinglaminaat.nl',{fetcher:async input=>{
    const u=new URL(input);
    if(u.hostname==='cloudflare-dns.com') return Response.json({Status:0,Answer:u.searchParams.get('type')==='A'
      ? [{name:u.searchParams.get('name'),type:1,data:'104.16.1.2',TTL:300}]:[]});
    return new Response(null,{status:200,headers:{server:'cloudflare','cf-ray':'aabbccdd11223344-AMS'}});
  }});
  known.build=build;
  const plain=await snapshot();
  const queue=[known,plain,null];
  const h=harness(async path=>{
    if(path==='/api/health') return freshHealth();
    const next=queue.shift();
    if(!next) throw new TypeError('offline');
    return Response.json(next);
  });
  await tick();
  await h.run('runScan("kinglaminaat.nl")');
  assert.equal(h.get('#cdnBadge').hidden,false);
  assert.match(h.get('#cdnBadge').innerHTML,/i-shield/);
  assert.equal(h.get('#cdnNotice').hidden,false);
  assert.match(h.get('#registeredServer').innerHTML,/S01 · Interfile/);
  assert.match(h.get('#view-infrastructure').innerHTML,/confirmed with a colleague/);
  assert.match(h.get('#view-infrastructure').innerHTML,/104.16.1.2/);
  assert.match(h.run('detail("cdn").html'),/aabbccdd11223344-AMS/);
  assert.match(h.run('detail("mapping").html'),/2026-09-14/);
  h.run('exportReport()');
  const exported=JSON.parse(await h.blob().text());
  assert.equal(exported.mapping.server,'S01');
  assert.equal(exported.cdn.state,'detected');
  await h.run('runScan("alpha.example.com")');
  assert.equal(h.get('#cdnNotice').hidden,true);
  assert.equal(h.get('#cdnBadge').hidden,true);
  assert.equal(h.get('#registeredServer').hidden,true);
  assert.ok(!h.get('#view-infrastructure').innerHTML.includes('Interfile'));
  await h.run('runScan("alpha.example.com")');
  assert.equal(h.get('#cdnBadge').innerHTML,'');
});

test('header-only Cloudflare signals show an unconfirmed info badge, DNS evidence and faithful export', async () => {
  const result=await scanSite('alpha.example.com',{fetcher:async input=>{
    const u=new URL(input);
    if(u.hostname==='cloudflare-dns.com') return Response.json({Status:0,Answer:u.searchParams.get('type')==='A'
      ? [{name:u.searchParams.get('name'),type:1,data:'185.107.91.213',TTL:300}]:[]});
    return new Response(null,{status:200,headers:{server:'cloudflare','cf-ray':'aabbccdd11223344-AMS','cf-cache-status':'DYNAMIC'}});
  }});
  const queue=[{...result,build},await snapshot()];
  const h=harness(async path=>path==='/api/health'?freshHealth():Response.json(queue.shift()));
  await h.run('runScan("alpha.example.com")');
  assert.equal(h.get('#cdnBadge').hidden,false);
  assert.equal(h.get('#cdnBadge').dataset.state,'unconfirmed');
  assert.match(h.get('#cdnBadge').innerHTML,/Cloudflare unconfirmed/);
  assert.match(h.get('#cdnBadge').innerHTML,/i-info/);
  assert.doesNotMatch(h.get('#cdnBadge').innerHTML,/i-shield/);
  assert.equal(h.get('#cdnNotice').hidden,true);
  assert.equal(h.get('#cdnNotice').innerHTML,'');
  assert.equal(h.get('#statusCard').dataset.state,'reachable');
  assert.match(h.get('#environmentPanel .panel-content').innerHTML,/Server header/);
  assert.match(h.get('#environmentPanel .panel-content').innerHTML,/cloudflare/);
  assert.match(h.get('#view-infrastructure').innerHTML,/Cloudflare unconfirmed/);
  const evidence=h.run('detail("cdn").html');
  assert.match(evidence,/185\.107\.91\.213/);
  assert.match(evidence,/No published range match/);
  assert.match(evidence,/cf-ray: aabbccdd11223344-AMS/);
  h.run('exportReport()');
  const exported=JSON.parse(await h.blob().text());
  assert.equal(exported.cdn.state,'possible');
  assert.equal(exported.cdn.provider,null);
  assert.equal(exported.cdn.basis,'headers-only');
  assert.equal(exported.cdn.dnsAddresses[0].address,'185.107.91.213');
  assert.equal(exported.cdn.dnsAddresses[0].cloudflareRange,null);
  assert.equal(exported.headers.server,'cloudflare');
  await h.run('runScan("alpha.example.com")');
  assert.equal(h.get('#cdnBadge').hidden,true);
  assert.equal(h.get('#cdnNotice').hidden,true);
});

test('confirmed redirect networks take priority over ambiguous entry headers without misattribution', async () => {
  const result=await scanSite('alpha.example.com',{fetcher:async input=>{
    const u=new URL(input);
    if(u.hostname==='cloudflare-dns.com') {
      const name=u.searchParams.get('name');
      return Response.json({Status:0,Answer:u.searchParams.get('type')==='A'
        ? [{name,type:1,data:name==='elsewhere.example.net'?'104.16.1.2':'185.107.91.213',TTL:300}]:[]});
    }
    return u.hostname==='alpha.example.com'
      ? new Response(null,{status:302,headers:{location:'https://elsewhere.example.net/',server:'cloudflare','cf-ray':'aabbccdd11223344-AMS'}})
      : new Response(null,{status:200});
  }});
  const h=harness(async path=>path==='/api/health'?freshHealth():Response.json({...result,build}));
  await h.run('runScan("alpha.example.com")');
  assert.equal(h.get('#cdnNotice').hidden,false);
  assert.match(h.get('#cdnNotice').innerHTML,/Cloudflare on redirect/);
  assert.match(h.get('#cdnNotice').innerHTML,/redirect host elsewhere\.example\.net/);
  assert.match(h.get('#cdnNotice').innerHTML,/does not establish proxy use on alpha\.example\.com/);
  assert.equal(h.run('report.cdn.state'),'possible');
  assert.equal(h.run('report.cdn.otherHosts[0].state'),'detected');
});
