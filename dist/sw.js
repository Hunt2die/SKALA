'use strict';
// SKALA __SKALA_REVISION__. No private pages, registrations, API results or sign-in responses are cached.
const offlinePage = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#07121c"><title>SKALA · Offline</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#07121c;color:#edf8ff;font:16px/1.65 system-ui}main{max-width:390px;padding:32px}b{font-size:32px;letter-spacing:3px}b span{color:#29c4ff}h1{font-size:25px;margin-top:34px}p{color:#a9c1d2}a{display:inline-block;margin-top:14px;padding:11px 22px;border:1px solid #2680ab;border-radius:8px;color:#d6f4ff;text-decoration:none;background:#113248}</style><main><b>SKALA<span>.</span></b><h1>You’re offline</h1><p>Reconnect to open your workspace and run live diagnostics.</p><p>Scan results and internal server registrations are not stored in the offline cache.</p><a href="/">Try again</a></main></html>';
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('fetch',event=>{
  const request=event.request;
  const url=new URL(request.url);
  if(request.method!=='GET' || request.mode!=='navigate' || url.origin!==self.location.origin ||
    !['/','/index.html'].includes(url.pathname)) return;
  // HTTP errors and authentication redirects pass through unchanged. Only network failures get the offline page.
  event.respondWith(fetch(request).catch(()=>new Response(offlinePage,{
    status:503,headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store'},
  })));
});
