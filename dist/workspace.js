'use strict';

const views = {
  overview: { label: 'Overview', title: 'Domain overview', icon: 'grid' },
  infrastructure: { label: 'Infrastructure', title: 'Infrastructure details', icon: 'server', empty: 'Public endpoints, reported technology and internal server mapping.' },
  dns: { label: 'DNS', title: 'DNS records', icon: 'database', empty: 'Every returned record, its TTL and the outcome of each DNS query.' },
  http: { label: 'HTTP & redirects', title: 'HTTP & redirects', icon: 'route', empty: 'Both entry paths, response headers and HTTPS availability.' },
  findings: { label: 'Findings', title: 'Findings & evidence', icon: 'search', empty: 'Observations from the current scan, with the evidence behind each one.' },
};
let activeView = 'overview';

function selectView(name, { history: writeHistory = true, focus = false } = {}) {
  if (!Object.hasOwn(views, name)) name = 'overview';
  activeView = name;
  document.querySelectorAll('[data-view]').forEach(tab => {
    const selected = tab.dataset.view === name;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
  });
  document.querySelectorAll('.view-panel').forEach(page => { page.hidden = page.id !== 'view-' + name; });
  $('#pageTitle').textContent = views[name].title;
  $('#viewBreadcrumb').textContent = views[name].label;
  document.title = 'SKALA — ' + views[name].label;
  if (writeHistory && location.hash !== '#' + name) {
    try { window.history.pushState(null, '', '#' + name); }
    catch { location.hash = name; }
  }
  if (focus) {
    const page = $('#view-' + name);
    page.focus({ preventScroll: true });
    $('.view-navigation').scrollIntoView({ block: 'start', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth' });
  }
}

function setTheme(theme, persist = false) {
  const light = theme === 'light';
  document.documentElement.dataset.theme = light ? 'light' : 'dark';
  $('meta[name="theme-color"]').content = light ? '#eef3f8' : '#07121c';
  const label = 'Switch to ' + (light ? 'dark' : 'light') + ' mode';
  $('#themeToggle').setAttribute('aria-label', label);
  $('#themeToggle').title = label;
  $('#themeToggle').innerHTML = icon(light ? 'moon' : 'sun') + '<span>' + (light ? 'Dark' : 'Light') + ' mode</span>';
  if (persist) { try { localStorage.setItem('skala.theme', light ? 'light' : 'dark'); } catch {} }
}

const detailCard = (title, symbol, html, wide = false) => '<article class="detail-card'+(wide?' detail-wide':'')+'"><header>'+icon(symbol)+'<h2>'+e(title)+'</h2></header><div class="detail-card-body">'+html+'</div></article>';
const metrics = items => '<dl class="page-metrics">'+items.map(([label,value])=>'<div><dt>'+e(label)+'</dt><dd>'+e(value)+'</dd></div>').join('')+'</dl>';
const pageNote = text => '<p class="page-note">'+icon('info')+'<span>'+e(text)+'</span></p>';
const queryState = q => ({ok:'Records returned',no_data:'No matching record',nxdomain:'Name not found',error:'Could not verify'}[q.state] || 'Unknown');

function renderDetailPages(snapshot, state = 'idle') {
  const count = $('#findingsTabCount');
  count.hidden = !snapshot;
  count.textContent = snapshot ? snapshot.findings.length : '';
  if (!snapshot) {
    const waiting = state==='loading'?'Waiting for the current scan.':'Run a scan to populate these observations.';
    const unscanned = (title,symbol,columns) => detailCard(title,symbol,table(columns,[])+empty(waiting));
    const layouts = {
      infrastructure: unscanned('Public endpoints','network',['Host','Type','Address','TTL (s)'])+unscanned('Reported technology','layers',['Evidence','Value'])+detailCard('Server mapping','server',empty('Any recorded server registration appears beside the domain input. Scan to see it alongside the public endpoint.')+pageNote('Public DNS does not reliably identify the origin behind a CDN.'),true),
      dns: unscanned('Observed records','database',['Type','Name','Value','TTL (s)'])+unscanned('Query outcomes','network',['Query','Outcome'])+detailCard('Names checked','network',pageNote('A / AAAA for the base host and www; NS, MX, TXT and CNAME for the base host; TXT for its DMARC name.'),true),
      http: unscanned('HTTPS entry path','route',['Step','HTTP','Response URL','Time (ms)'])+unscanned('HTTP entry path','route',['Step','HTTP','Response URL','Time (ms)'])+unscanned('Response headers','code',['Header','Value'])+detailCard('HTTPS / SSL evidence','shield',table(['Observation','State'],[['HTTPS response','Awaiting scan'],['Certificate issuer / expiry','Not inspected'],['Origin TLS','Not inspected']])),
      findings: '',
    };
    for (const [name, view] of Object.entries(views)) {
      if (name === 'overview') continue;
      const heading = state === 'loading' ? 'Checking the domain…' : state === 'failed' ? 'No verified result yet' : 'Ready when you are';
      const copy = state === 'loading' ? 'Results will appear here when the current scan finishes.' : state === 'failed' ? 'The last check did not return a usable report. Run the scan again when the service is available.' : view.empty;
      $('#view-' + name).innerHTML = '<div class="page-empty'+(name==='findings'?'':' page-empty-compact')+'">'+icon(state==='loading'?'refresh':view.icon,state==='loading'?'empty-spinner':'')+'<h2>'+heading+'</h2><p>'+e(copy)+'</p>'+(state==='loading'?'':'<button type="button" class="button button-primary" data-go-scan>'+icon('search')+'Check a domain</button>')+'</div>'+(layouts[name]?'<div class="detail-grid">'+layouts[name]+'</div>':'');
    }
    return;
  }
  const r = snapshot;
  const addresses = r.dns.records.filter(record=>['A','AAAA'].includes(record.type));
  const uniqueIPs = new Set(addresses.map(record=>record.value));
  const environment = [['Server header',r.environment.server],['Powered by',r.environment.poweredBy],['Source URL',r.headersUrl]];
  $('#view-infrastructure').innerHTML = metrics([['Public addresses observed',uniqueIPs.size],['CDN / proxy',cdnPresentation(r).label],['Registered server',r.mapping?.server ? r.mapping.server+' · '+r.mapping.provider : 'Not registered']])+
    '<div class="detail-grid">'+
    detailCard('Public endpoints','network',addresses.length?table(['Host','Type','Address','TTL (s)'],addresses.map(a=>[a.name,a.type,a.value,a.ttl])):empty('No public addresses were verified. The DNS page shows each query outcome.'),true)+
    detailCard('Reported technology','layers',table(['Evidence','Value'],environment.map(([k,v])=>[k,v||'Not observed']))+pageNote('A proxy or CDN may supply these headers. OS, database and CMS are not inspected.'))+
    detailCard('Server registration','server',table(['Mapping','Value'],mappingRows(r))+pageNote('Owner-supplied registration. No hosting panel was contacted; update this record after a migration.'))+
    detailCard('CDN & origin','shield',cdnEvidence(r),true)+'</div>';

  const failures = r.dns.queries.filter(q=>q.state==='error').length;
  $('#view-dns').innerHTML = metrics([['Queries completed',r.dns.queries.length-failures+' / '+r.dns.queries.length],['Records observed',r.dns.records.length],['Inconclusive queries',failures]])+
    pageNote('Resolver: '+r.dns.resolver+'. Records reflect this scan; a resolver error does not establish a missing record.')+
    '<div class="detail-grid">'+
    detailCard('All observed records','database',r.dns.records.length?table(['Type','Name','Value','TTL (s)'],r.dns.records.map(a=>[a.type,a.name,a.value,a.ttl])):empty('No records were returned. Inspect the query outcomes below.'),true)+
    detailCard('Query outcomes','network',table(['Type','Queried name','Outcome','Evidence','Error code'],r.dns.queries.map(q=>[q.type,q.name,queryState(q),q.error||(q.records.length+' matching records'),q.errorCode || '—'])) ,true)+'</div>';

  const traceCard = (key,title) => {
    const trace = r[key];
    return detailCard(title,'route','<div class="path-status">'+badge(trace.complete?'Path completed':'Could not complete',trace.complete?'neutral':'amber')+'<code>'+e(trace.startUrl)+'</code></div>'+
      (trace.steps.length?table(['Step','HTTP','Response URL','Time (ms)'],trace.steps.map((step,i)=>[i+1,step.status,step.url,step.timeMs])):empty('No HTTP response was received for this entry point.'))+
      (trace.error?pageNote(trace.error.message):''));
  };
  $('#view-http').innerHTML = metrics([['HTTP response',r.summary.status==null?'Unknown':r.summary.status],['Time to headers',r.summary.timeMs==null?'Not measured':r.summary.timeMs+' ms'],['HTTPS response',r.tls.httpsResponse?'Received':'Not confirmed']])+
    '<div class="detail-grid">'+traceCard('https','HTTPS entry path')+traceCard('http','HTTP entry path')+
    detailCard('Response headers','code',(r.headersUrl?'<p class="detail-source">'+e(r.headersUrl)+'</p>':'')+(Object.keys(r.headers).length?table(['Header','Value'],Object.entries(r.headers)):empty('No response headers were received.')),true)+
    detailCard('HTTPS / SSL evidence','shield',table(['Observation','Result'],[['HTTPS response',r.tls.httpsResponse?'Received':'Not confirmed'],['Responding URL',r.tls.responseUrl||'Not observed'],['Response status',r.tls.responseStatus??'Not observed'],['Certificate issuer / expiry','Not inspected'],['Origin TLS','Not inspected']])+pageNote(r.tls.detail),true)+'</div>'+
    pageNote('Timings measure how long response headers take to arrive at the SKALA probe. They do not measure a full page load.');

  const counts = ['error','review','info'].map(severity=>r.findings.filter(f=>f.severity===severity).length);
  $('#view-findings').innerHTML = metrics([['Errors',counts[0]],['To review',counts[1]],['Informational',counts[2]]])+
    '<div class="findings-page-list">'+(r.findings.length?r.findings.map((finding,i)=>{
      const level=finding.severity==='error'?'error':finding.severity==='info'?'info':'review';
      return '<article class="finding-detail" data-severity="'+level+'"><div class="finding-number">'+String(i+1).padStart(2,'0')+'</div><div class="finding-detail-content"><div class="finding-topline"><span class="finding-category">'+e(finding.section.toUpperCase())+'</span>'+badge(level==='error'?'Error':level==='info'?'Info':'Review',level==='info'?'blue':'amber')+'</div><h2>'+e(finding.title)+'</h2><p>'+e(finding.detail)+'</p><div class="finding-detail-actions"><button type="button" class="text-button" data-detail="'+(finding.section==='dns'?'dns':finding.section==='redirect'?'redirect':'http')+'">Inspect evidence'+icon('external')+'</button><button type="button" class="text-button" data-go-view="'+(finding.section==='dns'?'dns':'http')+'">Open '+(finding.section==='dns'?'DNS':'HTTP')+' page'+icon('arrow')+'</button></div></div></article>';
    }).join(''):'<div class="page-empty"><h2>No findings from these checks</h2><p>The current scan raised no observations. Its scope covers the homepage response and public DNS.</p></div>')+'</div>'+pageNote('These findings describe one scan from the SKALA probe, not a complete application health audit.');
}

document.addEventListener('click', event => {
  const target = event.target.closest('button');
  if (!target || target.disabled) return;
  if (target.dataset.view) selectView(target.dataset.view);
  if (target.dataset.goView) selectView(target.dataset.goView, {focus:true});
  if (target.hasAttribute('data-go-scan')) { $('#domainInput').focus(); $('#scanForm').scrollIntoView({block:'center'}); }
});
$('.view-tabs').addEventListener('keydown', event => {
  if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
  event.preventDefault();
  const names = Object.keys(views), index = names.indexOf(activeView);
  const next = event.key==='Home'?names[0]:event.key==='End'?names.at(-1):names[(index+(event.key==='ArrowRight'?1:-1)+names.length)%names.length];
  selectView(next); $('#tab-'+next).focus();
});
function readViewFromLocation() {
  const name = location.hash.slice(1);
  if (!name || Object.hasOwn(views,name)) selectView(name||'overview',{history:false});
}
window.addEventListener('popstate',readViewFromLocation);
window.addEventListener('hashchange',readViewFromLocation);
$('#themeToggle').addEventListener('click',()=>setTheme(document.documentElement.dataset.theme==='light'?'dark':'light',true));
window.addEventListener('storage',event=>{if(event.key==='skala.theme'||event.key===null)setTheme(event.newValue==='light'?'light':'dark');});
setTheme(document.documentElement.dataset.theme);
renderDetailPages(null);
readViewFromLocation();
