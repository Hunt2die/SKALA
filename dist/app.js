'use strict';

const $ = selector => document.querySelector(selector);
const e = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const icon = (name, cls = '') => '<svg class="icon '+cls+'" aria-hidden="true"><use href="#i-'+name+'"/></svg>';
const badge = (text, type = 'neutral') => '<span class="badge badge-'+type+'">'+e(text)+'</span>';
const empty = text => '<p class="empty-copy">'+e(text)+'</p>';
const rows = list => '<dl class="data-list">'+list.map(([k,v,cls=''])=>'<div><dt>'+e(k)+'</dt><dd class="'+cls+'">'+e(v ?? 'Not observed')+'</dd></div>').join('')+'</dl>';
const footer = (text, title, detail) => '<div class="panel-footer"><span>'+e(text)+'</span>'+(title?'<button class="text-button" data-go-view="'+({mapping:'infrastructure',environment:'infrastructure',dns:'dns',certificate:'http'}[detail]||'overview')+'">'+e(title)+icon('arrow')+'</button>':'')+'</div>';
const table = (headings, data) => '<div class="detail-table-wrap"><table class="detail-table"><thead><tr>'+headings.map(x=>'<th scope="col">'+e(x)+'</th>').join('')+'</tr></thead><tbody>'+data.map(row=>'<tr>'+row.map(x=>'<td>'+e(x ?? 'Unknown')+'</td>').join('')+'</tr>').join('')+'</tbody></table></div>';
const interfaceBuild = JSON.parse($('#buildMetadata').textContent);
let report = null, busy = false, activeTrace = 'https', toastTimer, opener, serviceEpoch = 0;

function renderTarget(target) {
  const node = $('#scanTarget');
  try {
    target = target || SkalaTarget.parseTarget($('#domainInput').value);
    const registration = SkalaRegistration.lookupRegistration(target.hostname);
    $('#registrationHint').dataset.state = registration.state;
    $('#registrationHint').innerHTML = registration.server
      ? icon('server') + '<span>Registered server <strong>' + e(registration.server + ' · ' + registration.provider) + '</strong></span><span class="registration-source">Manual record · ' + e(registration.recordedAt) + '</span>'
      : icon('server') + '<span>No internal registration for ' + e(target.hostname) + '</span>';
    $('#registrationHint').title = registration.source || 'An internal server is shown only when a matching registration exists.';
    node.dataset.adjusted = String(target.omittedPath);
    node.innerHTML = '<strong>Homepage targets</strong><code>' + e(target.entryUrls.https) + '</code><span>and</span><code>' + e(target.entryUrls.http) + '</code>' +
      (target.omittedPath ? '<span class="target-note">The supplied path, query or fragment will not be checked.</span>' : '');
  } catch {
    $('#registrationHint').innerHTML = '';
    $('#registrationHint').dataset.state = 'idle';
    node.dataset.adjusted = 'false';
    node.textContent = 'Enter a public domain to preview the two homepage URLs.';
  }
}
function showBuild(serverBuild) {
  const notice = $('#buildNotice');
  const matches = serverBuild?.id === interfaceBuild.id;
  notice.hidden = matches;
  notice.textContent = matches ? '' : serverBuild?.id
    ? 'The interface (' + interfaceBuild.id + ') and backend (' + serverBuild.id + ') use different builds. Reload SKALA before comparing results.'
    : 'The backend did not identify its build. Reload SKALA to check for an update.';
}
function probeChip(id, state, text, description = '') {
  const chip = $('#probe' + id);
  chip.dataset.state = state;
  chip.textContent = text;
  chip.title = description;
}
function resetProbeResults(state) {
  const label = state === 'checking' ? 'Checking…' : state === 'failed' ? 'No result' : 'Not checked';
  for (const [id, name] of [['Dns','DNS'],['Https','HTTPS'],['Http','HTTP']]) probeChip(id, state, name + ': ' + label);
  $('#probeContext').textContent = state === 'checking' ? 'Current scan' : state === 'failed' ? 'No completed scan' : 'No scan yet';
}
function renderProbeResults(snapshot) {
  const queries = snapshot.dns.queries;
  const replies = queries.filter(q => q.state !== 'error').length;
  probeChip('Dns', replies === queries.length && replies > 0 ? 'ok' : 'review',
    'DNS: ' + replies + '/' + queries.length + ' replies',
    'Forward DNS responses for this scan. PTR lookups are listed separately on the DNS page. A reply may report that a name or record does not exist.');
  for (const [key, id] of [['https','Https'], ['http','Http']]) {
    const trace = snapshot[key], last = trace.steps.at(-1);
    const state = snapshot.entrypoints?.[key]?.state;
    if (trace.complete && last) {
      probeChip(id, state === 'http_error' ? 'error' : state === 'restricted' || last.status >= 300 ? 'review' : 'ok',
        key.toUpperCase() + ': ' + last.status, 'Final response for ' + trace.startUrl + ': ' + last.url);
    } else {
      const stopped = ['dns_error','dns_no_address','blocked_target'].includes(trace.error?.code);
      const label = last ? 'Partial trace' : stopped ? 'Not attempted' : 'No response';
      probeChip(id, 'review', key.toUpperCase() + ': ' + label, trace.error?.message || 'No completed result.');
    }
  }
  $('#probeContext').textContent = 'Last scan · ' + snapshot.domain;
  $('#probeContext').title = snapshot.checkedAt;
}

function toast(text) {
  clearTimeout(toastTimer);
  $('#toast').textContent = text;
  $('#toast').classList.add('show');
  toastTimer = setTimeout(()=>$('#toast').classList.remove('show'),3500);
}
function feedback(text, invalid = false) {
  $('#scanFeedback').textContent = text;
  $('#scanFeedback').hidden = !text;
  $('#domainInput').toggleAttribute('aria-invalid',invalid);
  if (invalid) { $('#domainInput').setAttribute('aria-invalid','true'); $('#domainInput').focus(); }
}
function status(state, title, detail) {
  $('#statusCard').dataset.state = state;
  $('#statusTitle').textContent = title;
  $('#statusDetail').textContent = detail;
  const name = state === 'reachable' ? 'check' : state === 'checking' ? 'refresh' : state === 'idle' ? 'globe' : 'info';
  $('#statusIcon').innerHTML = icon(name);
}
function panel(id, body) { $('#'+id+' .panel-content').innerHTML = body; }
function mappingRows(snapshot) {
  const m = snapshot.mapping || {};
  return [['Registered hostname',m.hostname || snapshot.domain],['Internal server',m.server || 'Not registered'],
    ['Hosting group',m.provider || 'Not registered'],['Source',m.source || 'No matching registration'],
    ['Recorded on',m.recordedAt || '—'],['Origin IP','Not verified']];
}
function reverseForTarget(snapshot) {
  return (snapshot.reverseDNS?.entries || []).filter(entry => entry.sources.some(source => source.hostname === snapshot.domain));
}
function reverseHostnames(snapshot) {
  return [...new Set(reverseForTarget(snapshot).flatMap(entry => entry.hostnames))];
}
function reverseSummary(snapshot) {
  if (!snapshot.reverseDNS) return 'Not checked';
  const entries = reverseForTarget(snapshot), names = reverseHostnames(snapshot);
  const partial = entries.some(entry => entry.query.state === 'error');
  if (names.length) return names.slice(0, 3).join(', ') + (names.length > 3 ? ' (+' + (names.length - 3) + ' more)' : '') + (partial ? ' · partial result' : '');
  return !entries.length ? 'No public address observed' : partial ? 'Could not verify' : 'No PTR record';
}
function reverseEvidence(snapshot, includeQueries = false) {
  const reverse = snapshot.reverseDNS;
  if (!reverse) return empty('Run a new scan to include reverse DNS.');
  const data = reverse.entries.flatMap(entry => {
    const q = entry.query;
    const outcome = q.state === 'ok' ? 'PTR returned' : q.state === 'error' ? 'Could not verify: ' + q.error : 'No PTR record';
    const records = q.state === 'ok' ? q.records : [];
    return (records.length ? records : [null]).map(record => [entry.address,
      entry.sources.map(source => source.hostname + ' (' + source.type + ')').join(', '),
      record ? record.value.replace(/\.$/, '') : '—', outcome, record?.ttl ?? '—']);
  });
  return (data.length ? table(['IP address','Used by','PTR hostname','Outcome','TTL (s)'], data)
    : empty('No eligible public address was available for reverse DNS.')) +
    (reverse.omitted ? '<p class="cdn-evidence-note">' + e(reverse.omitted) + ' additional addresses were not checked (limit ' + e(reverse.limit) + ').</p>' : '') +
    (includeQueries && reverse.entries.length ? '<h3 class="detail-subheading">PTR query evidence</h3>' +
      table(['Address','Queried name','Outcome','DNS status','Error code'], reverse.entries.map(entry =>
        [entry.address,entry.query.name,entry.query.state,entry.query.status ?? '—',entry.query.errorCode || '—'])) : '') +
    '<p class="cdn-evidence-note">' + e(reverse.detail) + '</p>';
}
function cdnPresentation(snapshot) {
  const cdn = snapshot.cdn;
  if (!cdn) return { label: 'Not checked', active: false };
  if (cdn.state === 'detected') return { label: 'Cloudflare detected', active: true, host: cdn.hostname,
    description: 'A public DNS address for ' + cdn.hostname + ' matches a published Cloudflare proxy range. Origin hosting and WAF settings are not verified.' };
  const other = cdn.otherHosts?.find(host => host.state === 'detected');
  if (other) return { label: 'Cloudflare on redirect', active: true, host: other.hostname,
    description: 'A DNS address for redirect host ' + other.hostname + ' matches a published Cloudflare proxy range. This does not establish proxy use on ' + snapshot.domain + '.' };
  if (cdn.state === 'possible') return { label: 'Cloudflare unconfirmed', active: false, uncertain: true, host: cdn.hostname,
    description: 'Cloudflare-like headers were received for ' + cdn.hostname + ', without a matching Cloudflare DNS address. Headers can come from intermediaries on the probe request path; they do not establish that this site is protected by Cloudflare.' };
  const possibleRedirect = cdn.otherHosts?.find(host => host.state === 'possible');
  if (possibleRedirect) return { label: 'Redirect proxy unconfirmed', active: false, uncertain: true, host: possibleRedirect.hostname,
    description: 'Cloudflare-like headers were received on redirect host ' + possibleRedirect.hostname + ', without a matching Cloudflare DNS address. Proxy use is unconfirmed.' };
  return { active: false, label: cdn.state === 'dns_observed' ? 'Cloudflare DNS' : cdn.state === 'not_observed' ? 'Not observed' : 'Could not verify',
    description: cdn.state === 'dns_observed' ? 'Cloudflare nameservers observed; web proxy use is unconfirmed.' : 'No Cloudflare proxy was established from the available evidence.' };
}
function cdnEvidence(snapshot) {
  const c = snapshot.cdn;
  if (!c) return empty('No Cloudflare observation is available.');
  const p = cdnPresentation(snapshot);
  const signals = [...(c.evidence || []), ...(c.dnsEvidence || []), ...(c.otherHosts || []).flatMap(h => h.evidence)];
  const addresses = [...(c.dnsAddresses || []), ...(c.otherHosts || []).flatMap(h => h.dnsAddresses || [])];
  return '<p class="cdn-evidence-intro">' + e(p.description) + '</p>' +
    '<h3 class="detail-subheading">Public DNS addresses</h3>' +
    (addresses.length ? table(['Hostname','Type','Address','Cloudflare range'], addresses.map(item =>
      [item.hostname,item.type,item.address,item.cloudflareRange || 'No published range match'])) : empty('No DNS address evidence is available.')) +
    '<h3 class="detail-subheading">Observed signals</h3>' +
    (signals.length ? table(['Evidence','Value','Observed at'], signals.map(item => [item.kind,item.value,item.source])) : empty('No matching signals were returned.')) +
    '<p class="cdn-evidence-note">' + e(c.detail) + ' Network list checked ' + e(c.networkListCheckedAt) + '.</p>';
}
function renderIdentity(snapshot) {
  const p = cdnPresentation(snapshot), m = snapshot.mapping || {};
  const mark = $('#cdnBadge');
  mark.hidden = !p.active && !p.uncertain && snapshot.cdn?.state !== 'dns_observed';
  mark.dataset.state = p.active ? 'proxy' : p.uncertain ? 'unconfirmed' : 'dns';
  mark.innerHTML = icon(p.active ? 'shield' : p.uncertain ? 'info' : 'network') + '<span>' + e(p.label) + '</span>';
  $('#registeredServer').hidden = !m.server;
  $('#registeredServer').innerHTML = icon('server') + '<span>' + e(m.server + ' · ' + m.provider) + '</span>';
  $('#registeredServer').title = 'Manual registration · ' + (m.recordedAt || '') + '. Open the source details.';
  $('#cdnNotice').hidden = !p.active;
  $('#cdnNotice').innerHTML = p.active ? '<span class="cdn-shield">' + icon('shield') + '</span><div><strong>' + e(p.label) +
    '</strong><p>' + e(p.description) + '</p></div><button type="button" class="text-button" data-detail="cdn">Evidence' + icon('arrow') + '</button>' : '';
}
function query(name,type) { return report.dns.queries.find(q=>q.name===name && q.type===type); }
function resultLabel(q) {
  if (!q || q.state === 'error') return 'Could not verify';
  if (q.state === 'nxdomain') return 'Name not found';
  if (q.state === 'no_data') return 'No record';
  return q.records.map(r=>r.value).join(', ');
}
function setService(ready,text) {
  $('#backendStatus').dataset.ready = String(ready);
  $('#backendStatus').textContent = text;
  $('#serviceLabel').textContent = ready ? 'Backend connected' : 'Basic diagnostics';
  probeChip('Backend', ready ? 'ok' : 'review', ready ? 'Backend: Available' : 'Backend: Unavailable', text);
}
function setBusy(next) {
  busy = next;
  const unavailable = next || globalThis.navigator?.onLine === false;
  document.body.classList.toggle('scanning',next);
  $('.domain-overview').setAttribute('aria-busy',String(next));
  $('.evidence-grid').setAttribute('aria-busy',String(next));
  document.querySelectorAll('.detail-page').forEach(page=>page.setAttribute('aria-busy',String(next)));
  $('#domainInput').disabled = next;
  $('#scanButton').disabled = unavailable;
  $('#refreshButton').disabled = unavailable;
  document.querySelectorAll('[data-action="refresh"]').forEach(button=>{button.disabled=unavailable;});
  $('#scanButton span').textContent = next ? 'Checking…' : 'Run scan';
}

function clearResults(domain, loading) {
  report = null;
  for (const id of ['cdnBadge','cdnNotice','registeredServer']) { $('#'+id).hidden = true; $('#'+id).innerHTML = ''; }
  resetProbeResults(loading ? 'checking' : 'failed');
  $('#domainTitle').textContent = domain;
  $('#snapshotBadge').textContent = loading ? 'Checking now' : 'No result';
  $('#updatedAt').textContent = loading ? 'Resolving DNS and requesting the homepage…' : 'No completed scan for this domain.';
  $('#httpStat').textContent = '—';
  $('#httpStat').className = '';
  $('#timingStat').innerHTML = '—<span class="unit">ms</span>';
  $('#findingStat').textContent = '—';
  $('#findingsCount').textContent = '—';
  $('#findingsSummary').textContent = loading ? 'Waiting for evidence' : 'No result available';
  $('#findingsList').innerHTML = '<div class="finding"><p>'+(loading?'Checks are running. Findings will appear when the responses arrive.':'No findings were inferred from the failed check.')+'</p></div>';
  const placeholder = loading ? '<div class="loading-rows" aria-hidden="true"><span class="loading-value"></span><span class="loading-value"></span><span class="loading-value"></span></div>' : empty('No verified result. Run the check again when the service is available.');
  document.querySelectorAll('.panel-content').forEach(node=>{node.innerHTML=placeholder;});
  $('#redirectCount').textContent = loading ? 'Checking' : 'Not checked';
  $('#traceResults').innerHTML = empty(loading?'Checking the HTTP and HTTPS entry points…':'No redirect result available.');
  $('#headerCode').innerHTML = '<code>'+(loading?'Waiting for response headers…':'No response headers received.')+'</code>';
  $('#headersURL').textContent = loading ? domain : 'No response';
  $('#headersStatus').textContent = '—';
  $('#copyHeaders').disabled = true;
  document.querySelectorAll('[data-action="export"]').forEach(button=>{button.disabled=true;});
  renderDetailPages(null,loading?'loading':'failed');
}

function renderReport() {
  renderProbeResults(report);
  renderIdentity(report);
  const root = report.dns.name;
  const primaryA = query(report.domain,'A') || query(root,'A');
  const primaryAAAA = query(report.domain,'AAAA') || query(root,'AAAA');
  const publicAddresses = [primaryA,primaryAAAA].filter(Boolean).flatMap(q=>q.records.map(r=>r.value));
  const address = publicAddresses.length ? publicAddresses.join(', ') : 'Not observed';
  $('#domainTitle').textContent = report.domain;
  $('#snapshotBadge').textContent = 'Live snapshot';
  const checked = new Date(report.checkedAt);
  $('#updatedAt').textContent = 'Checked '+checked.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'})+' · '+checked.toLocaleDateString();
  $('#httpStat').textContent = report.summary.status == null ? 'Unknown' : 'HTTP '+report.summary.status;
  $('#httpStat').className = report.summary.state==='reachable'?'status-text-ok':report.summary.state==='http_error'?'status-text-error':'status-text-review';
  $('#timingStat').innerHTML = (report.summary.timeMs == null ? '—' : e(report.summary.timeMs))+'<span class="unit">ms</span>';
  $('#findingStat').innerHTML = e(report.findings.length)+icon('arrow');
  status(report.summary.state,report.summary.title,report.summary.detail);

  const mapping = report.mapping || {};
  const ptrNames = reverseHostnames(report);
  panel('serverPanel','<div class="server-identity"><div><span class="eyebrow">'+(mapping.server || !ptrNames.length ? 'INTERNAL REGISTRATION' : 'PUBLIC HOSTNAME (PTR)')+'</span><strong>'+
    (mapping.server ? '<b>'+e(mapping.server)+'</b> · '+e(mapping.provider) : ptrNames.length ? '<b>'+e(ptrNames[0])+'</b>'+(ptrNames.length>1?' <small>+'+(ptrNames.length-1)+' more</small>':'') : 'Not registered')+'</strong></div>'+badge(mapping.server?'Manual record':ptrNames.length?'PTR record':'No match',mapping.server||ptrNames.length?'blue':'neutral')+'</div>'+
    rows([['Public IP',address,'mono'],['Reverse DNS',reverseSummary(report),'mono'],['Internal server',mapping.server ? mapping.server+' · '+mapping.provider : 'Not registered'],['CDN / proxy',cdnPresentation(report).label],['Origin IP','Not verified','unknown'],
      ['Registration source',mapping.source || 'No matching registration'],['Recorded on',mapping.recordedAt || '—']])+
    footer('PTR hostnames describe the public IP.','Details','mapping'));

  panel('ipPanel','<div class="card-intro"><span>Public resolver results</span>'+badge('A / AAAA','blue')+'</div><dl class="ip-list">'+
    [root,'www.'+root].flatMap(name=>['A','AAAA'].map(type=>{
      const q=query(name,type), found=q?.state==='ok';
      return '<div class="'+(found?'':'missing-record')+'"><dt><span class="record-tag">'+type+'</span><span title="'+e(name)+'">'+(name===root?'Base host':'www')+'</span></dt><dd class="'+(found?'mono':'')+'">'+e(resultLabel(q))+(found?icon('check','success-icon'):'')+'</dd></div>';
    })).join('')+'</dl>'+footer('Base host: '+root,'Details','dns'));

  panel('environmentPanel','<div class="card-intro"><span>Exposed technology</span>'+badge('Reported headers')+'</div>'+
    rows([['Server header',report.environment.server],['Powered by',report.environment.poweredBy],['Operating system','Not inspected','unknown'],['Database','Not inspected','unknown'],['CMS / platform','Not inspected','unknown']])+
    footer('Headers may describe an intermediary.','Evidence','environment'));

  const ns=query(root,'NS');
  panel('nameserverPanel','<div class="card-intro"><span>NS query: '+e(root)+'</span><span class="count-label">'+(ns?.records?.length||'—')+'</span></div>'+
    (ns?.state==='ok'?'<dl class="nameserver-list">'+ns.records.map((r,i)=>'<div><dt><span>'+String(i+1).padStart(2,'0')+'</span><code>'+e(r.value)+'</code></dt><dd>'+e(r.ttl)+'s</dd></div>').join('')+'</dl>':empty(resultLabel(ns)+'. Parent-zone delegation is not inferred.'))+
    footer('Public recursive resolver','Inspect','dns'));

  const records=report.dns.records;
  panel('dnsPanel','<div class="dns-table"><div class="table-labels"><span>TYPE</span><span>VALUE</span></div>'+
    records.slice(0,6).map(r=>'<div><span class="record-tag">'+e(r.type)+'</span><code class="truncate" title="'+e(r.name+' → '+r.value)+'">'+e(r.value)+'</code></div>').join('')+'</div>'+
    (records.length?'':empty('No records returned. Check the query results for resolver errors.'))+
    footer(records.length+' distinct records observed','View all','dns'));

  panel('certificatePanel','<div class="transport-label">'+icon('shield')+'<strong>'+(report.tls.httpsResponse?'HTTPS responded':'Not confirmed')+'</strong></div>'+
    rows([['HTTPS response',report.tls.responseStatus==null?'Not observed':'HTTP '+report.tls.responseStatus],['Issuer','Not inspected','unknown'],['Expiry date','Not inspected','unknown'],['Origin TLS','Not inspected','unknown']])+
    footer('Response availability, not a full certificate audit.','Details','certificate'));

  $('#findingsCount').textContent=report.findings.length;
  const review=report.findings.filter(f=>f.severity!=='info').length;
  $('#findingsSummary').textContent = review+' to review · '+(report.findings.length-review)+' informational';
  $('#findingsList').innerHTML=report.findings.length?report.findings.map(f=>'<div class="finding '+(f.severity==='info'?'informational':f.severity==='error'?'error':'')+'"><div class="finding-topline"><span class="finding-category">'+icon(f.section==='dns'?'network':'route')+e(f.section.toUpperCase())+'</span><span class="severity">'+(f.severity==='info'?'Info':f.severity==='error'?'Error':'Review')+'</span></div><h3>'+e(f.title)+'</h3><p>'+e(f.detail)+'</p><button data-detail="'+(f.section==='dns'?'dns':f.section==='redirect'?'redirect':'http')+'">Inspect evidence'+icon('arrow')+'</button></div>').join(''):'<div class="finding"><h3>No findings from these basic checks</h3><p>This is a point-in-time homepage check, not a full application health audit.</p></div>';
  renderTrace();
  $('#headersURL').textContent=report.headersUrl||'No response headers received';
  const headerStep=[...report.https.steps,...report.http.steps].find(step=>step.url===report.headersUrl);
  $('#headersStatus').textContent=headerStep?'HTTP '+headerStep.status:'—';
  $('#headerCode').innerHTML='<code>'+Object.entries(report.headers).map(([k,v],i)=>'<span class="code-line"><span class="line-number">'+String(i+1).padStart(2,'0')+'</span><span class="header-key">'+e(k)+':</span> '+e(v)+'</span>').join('\n')+'</code>';
  if(!Object.keys(report.headers).length) $('#headerCode').innerHTML='<code>No response headers were received.</code>';
  $('#copyHeaders').disabled=!Object.keys(report.headers).length;
  document.querySelectorAll('[data-action="export"]').forEach(button=>{button.disabled=false;});
  renderDetailPages(report);
}

function renderTrace() {
  document.querySelectorAll('[data-trace]').forEach(button=>{
    const selected=button.dataset.trace===activeTrace;
    button.setAttribute('aria-selected',String(selected));
    button.tabIndex=selected?0:-1;
  });
  $('#traceResults').setAttribute('aria-labelledby',activeTrace+'Tab');
  if(!report) return;
  const trace=report[activeTrace];
  const redirects=trace.steps.filter(step=>[301,302,303,307,308].includes(step.status)).length;
  $('#redirectCount').textContent=redirects+' redirect'+(redirects===1?'':'s');
  $('#traceResults').innerHTML=(trace.steps.length?'<ol class="redirect-chain">'+trace.steps.map((step,i)=>{
    const final=trace.complete&&i===trace.steps.length-1,success=final&&step.status>=200&&step.status<300;
    return '<li class="'+(success?'final-step':'')+'"><span class="step-caption">'+String(i+1).padStart(2,'0')+'<span>'+(final?'FINAL RESPONSE':i===0?'ENTRY POINT':'NEXT RESPONSE')+'</span>'+ (success?icon('check'):'')+'</span><code>'+e(step.url)+'</code><div><span class="http-code '+(success?'code-ok':step.status>=400?'code-error':'code-redirect')+'">'+e(step.status)+'</span><span>'+e(step.timeMs)+' ms to headers</span></div></li>';
  }).join('')+'</ol>':empty('No HTTP response was received for this entry point.'))+
    (trace.error?'<p class="trace-error">'+e(trace.error.message)+'</p>':'<p class="redirect-note">'+icon('info')+'Public GET requests. Response bodies are not downloaded for analysis.</p>');
}

async function runScan(value) {
  if(busy) return;
  if(globalThis.navigator?.onLine === false) { feedback('You’re offline. Reconnect to run a live check.',true); return; }
  const input=String(value||'').trim();
  let target;
  try { target = SkalaTarget.parseTarget(input); }
  catch(error) { feedback(error.message,true); renderTarget(); return; }
  const domain = target.hostname;
  renderTarget(target);
  serviceEpoch++;
  feedback('');
  setBusy(true);
  clearResults(domain,true);
  status('checking','Checking site','Resolving public DNS and requesting the homepage.');
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),28000);
  let apiResponded = false;
  try {
    if(!['http:','https:'].includes(location.protocol)) throw new Error('Live checks need the hosted SKALA backend. This local HTML file can only preview the interface.');
    const response=await fetch('/api/scan',{method:'POST',headers:{'content-type':'application/json','x-skala-scan':'1'},body:JSON.stringify({domain:input}),signal:controller.signal,cache:'no-store'});
    const contentType=response.headers.get('content-type')||'';
    if(!contentType.includes('application/json')) throw new Error('The scan service is not available here. Open the hosted release and check that you are signed in.');
    const data=await response.json();
    apiResponded = data?.mode === 'live' || typeof data?.error === 'string';
    if (apiResponded) {
      setService(true,'Backend responded; individual probe outcomes are shown above.');
      showBuild(data.build || (response.headers.get('x-skala-build') ? {id:response.headers.get('x-skala-build')} : null));
    }
    if(!response.ok) throw new Error(data.error||'The scan service could not finish this request.');
    if(data.mode!=='live'||!data.summary||!Array.isArray(data.dns?.queries)||!Array.isArray(data.https?.steps)||!Array.isArray(data.http?.steps)) throw new Error('The scan service returned an incomplete result.');
    report=data;
    $('#domainInput').value=data.domain;
    renderReport();
    renderTarget(data.target || target);
    const dnsBlocked = [data.https,data.http].every(trace => trace.error?.code === 'dns_error' && !trace.steps.length);
    feedback(dnsBlocked ? 'HTTP/HTTPS checks were not started. ' + data.summary.detail : 'Checked '+data.domain+' from the SKALA probe. Results reflect this moment and location.');
    toast(dnsBlocked ? 'DNS failed · website status not checked' : 'Live check complete · '+data.summary.title.toLowerCase());
  } catch(error) {
    clearResults(domain,false);
    if (!apiResponded) setService(false, ['http:','https:'].includes(location.protocol) ? 'Backend connection could not be verified.' : 'Preview only; live checks require the hosted tool.');
    const text=controller.signal.aborted?'The scan service timed out. No site status was inferred.':error.message;
    status('unverified','Could not verify',text);
    feedback(text);
  } finally {clearTimeout(timer);setBusy(false);}
}

function detail(key) {
  if(key==='install') return {title:'Install SKALA',html:'<p>Keep SKALA on your home screen or open it in its own window. Sign in at the hosted address before installing.</p>'+table(['Device','How to install'],[['Chrome / Edge','Use Install SKALA or the install option in the browser menu.'],['iPhone / iPad','Open SKALA in Safari. Choose Share → Add to Home Screen → Add.'],['Mac Safari','Choose File → Add to Dock.'],['Other browsers','Use the browser’s install option if available, or bookmark SKALA.']])+'<div class="detail-note"><p>Live scans need an internet connection. Sign-in may be required again when opening the installed app. Reports stay in the open tab; export a report if you want to keep it.</p></div>'};
  if(key==='about') return {title:'SKALA basic diagnostics',html:'<p>Live HTTP and HTTPS homepage requests, redirect paths, DNS results and reported response headers.</p>'+table(['Check','Scope'],[['Website status','Point-in-time response from the SKALA server'],['Response time','Time until headers arrive; not page-load speed'],['DNS','Cloudflare 1.1.1.1 public resolver'],['Reverse DNS','PTR lookups for up to 8 distinct public IPv4/IPv6 addresses'],['SSL','HTTPS response availability only'],['Cloudflare','Public network and response-header signals'],['Internal server mapping','Owner-supplied registrations; no hosting panel sync'],['Storage','Scan results stay in this tab; export JSON to keep a report']])+'<div class="detail-note"><p>No authenticated requests, browser rendering, certificate expiry checks or server changes are performed.</p></div>'};
  if(!report) return {title:'No scan result yet',html:'<p>Run a check to inspect real observations for the selected domain.</p>'};
  if(key==='dns') return {title:'DNS evidence',html:'<p>Queried names and resolver outcomes are shown separately. A resolver error does not mean a record is missing.</p>'+table(['Query','Outcome','Error code'],report.dns.queries.map(q=>[q.type+' '+q.name,q.state==='error'?'Unknown: '+q.error:q.state,q.errorCode || '—']))+'<h3 class="detail-subheading">Observed records</h3>'+table(['Type / name','Value / TTL'],report.dns.records.map(r=>[r.type+' '+r.name,r.value+' · '+r.ttl+'s']))+'<h3 class="detail-subheading">Reverse DNS (PTR)</h3>'+reverseEvidence(report,true)};
  if(key==='reverse') return {title:'Reverse DNS (PTR)',html:reverseEvidence(report,true)};
  if(key==='certificate') return {title:'HTTPS / SSL',html:'<p>'+e(report.tls.detail)+'</p>'+table(['Observation','Result'],[['HTTPS response',report.tls.httpsResponse?'Received':'Not confirmed'],['Responding URL',report.tls.responseUrl],['HTTP response',report.tls.responseStatus],['Certificate issuer','Not inspected'],['Certificate expiry','Not inspected'],['Origin TLS behind a proxy','Not inspected']])};
  if(key==='environment') return {title:'Environment evidence',html:'<p>These are the headers reported by the responding endpoint. They may identify a proxy or CDN, and do not prove installed versions.</p>'+table(['Evidence','Value'],[['URL',report.headersUrl],['server',report.environment.server],['x-powered-by',report.environment.poweredBy],['OS / database / CMS','Not inspected']])};
  if(key==='mapping') return {title:'Server registration',html:'<p>This is an owner-supplied record, not a live hosting-panel lookup. Registrations must be updated after migrations.</p>'+table(['Mapping','Value'],mappingRows(report))};
  if(key==='cdn') return {title:'Cloudflare evidence',html:cdnEvidence(report)};
  if(key==='redirect') return {title:'HTTP & HTTPS paths',html:'<p>Each redirect is checked before it is followed. Redirect loops, timeouts and stopped checks remain visible.</p>'+['https','http'].map(k=>'<h3 class="detail-subheading">'+k.toUpperCase()+' entry</h3>'+table(['Response','URL'],report[k].steps.map(s=>[s.status,s.url]))+(report[k].error?'<p>'+e(report[k].error.message)+'</p>':'')).join('')};
  return {title:'Website status',html:'<p>'+e(report.summary.detail)+'</p>'+table(['Observation','Value'],[['Domain',report.domain],['Checked at',report.checkedAt],['Vantage',report.vantage],['HTTP response',report.summary.status],['Final URL',report.summary.finalUrl],['Time to headers (ms)',report.summary.timeMs]])};
}
function openDetail(key,button) {
  const content=detail(key);
  opener=button||document.activeElement;
  $('#detailTitle').textContent=content.title;
  $('#detailContext').textContent=report?report.domain+' · '+new Date(report.checkedAt).toLocaleString():'SKALA ' + interfaceBuild.id;
  $('#detailContent').innerHTML=content.html;
  $('#detailDialog').showModal();
  document.body.classList.add('inspector-open');
  $('#closeDialog').focus();
}
function focusSection(id) {
  const target=$('#'+id);
  target.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth',block:'center'});
  target.focus({preventScroll:true});
}
function exportReport() {
  if(!report) return;
  const blob=new Blob([JSON.stringify({...report,interfaceBuild},null,2)+'\n'],{type:'application/json'});
  const url=URL.createObjectURL(blob),a=document.createElement('a');
  a.href=url;
  a.download='skala-'+report.domain+'-'+(report.build?.id || 'unknown-build')+'-'+report.checkedAt.replace(/[:.]/g,'-')+'.json';
  document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
  toast('Current report download started.');
}
$('#scanForm').addEventListener('submit',event=>{event.preventDefault();runScan($('#domainInput').value);});
$('#domainInput').addEventListener('input',()=>{feedback('');renderTarget();});
$('#refreshButton').addEventListener('click',()=>runScan(report?.domain||$('#domainInput').value));
document.addEventListener('click',event=>{
  const button=event.target.closest('button');
  if(!button||button.disabled) return;
  if(button.dataset.detail) openDetail(button.dataset.detail,button);
  if(button.dataset.trace) {activeTrace=button.dataset.trace;renderTrace();}
  if(button.dataset.action==='export') exportReport();
  if(button.dataset.action==='trace') selectView('http',{focus:true});
  if(button.dataset.action==='findings') selectView('findings',{focus:true});
  if(button.dataset.action==='refresh') runScan(report?.domain||$('#domainInput').value);
});
$('.trace-tabs').addEventListener('keydown',event=>{
  if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
  event.preventDefault();
  activeTrace=event.key==='Home'?'https':event.key==='End'?'http':activeTrace==='https'?'http':'https';
  renderTrace();$('#'+activeTrace+'Tab').focus();
});
$('#closeDialog').addEventListener('click',()=>$('#detailDialog').close());
$('#detailDialog').addEventListener('close',()=>{document.body.classList.remove('inspector-open');if(opener?.isConnected)opener.focus();});
$('#detailDialog').addEventListener('click',event=>{
  if(event.target!==$('#detailDialog'))return;
  const r=event.target.getBoundingClientRect();
  if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)event.target.close();
});
$('#copyHeaders').addEventListener('click',async()=>{
  if(!report)return;
  const text=Object.entries(report.headers).map(([k,v])=>k+': '+v).join('\n');
  try {await navigator.clipboard.writeText(text);toast('Observed response headers copied.');}
  catch {const range=document.createRange();range.selectNodeContents($('#headerCode'));const selection=getSelection();selection.removeAllRanges();selection.addRange(range);toast('Headers selected for manual copying.');}
});
renderTarget();
(async()=>{
  const epoch = serviceEpoch;
  try{
    if(!['http:','https:'].includes(location.protocol))throw new Error();
    const r=await fetch('/api/health',{signal:AbortSignal.timeout(5000),cache:'no-store'});
    const data=await r.json();
    if(!r.ok||data.service!=='SKALA'||data.mode!=='live')throw new Error();
    if(epoch !== serviceEpoch) return;
    setService(true,'Backend available. DNS and website connectivity are checked when you run a scan.');
    showBuild(data.build);
  }catch{if(epoch === serviceEpoch) setService(false, ['http:','https:'].includes(location.protocol) ? 'Backend connection could not be verified.' : 'Preview only; live checks require the hosted tool.');}
})();
