# SKALA Basic 0.5.2 ##

GitHub → Cloudflare deployment and PWA installation: [CLOUDFLARE-SETUP.md](CLOUDFLARE-SETUP.md). Cloudflare's build command is `npm test && npm run build`, with `npx wrangler@latest deploy` as the deploy command. The explicit `wrangler.jsonc` entry uses `dist/server/cloudflare-entry.js`, which checks the runtime-provided Cloudflare Access identity and `SKALA_ALLOWED_EMAILS` before serving any route. The existing Sites entry remains `dist/server/index.js`, for its platform-managed access gate. Do not deploy that unwrapped entry directly to your own account. A standalone GitHub checkout builds without Sites metadata.

The manifest, 192/512px install icons, 180px Apple icon and SVG favicon share the navy/cyan server-and-locator mark. Install controls use the browser prompt when available and show instructions otherwise. The service worker supplies a generic offline navigation page, with no caching of private pages, registrations, scan results or sign-in responses. Offline detection disables new checks without discarding the open snapshot. Device installation and real Cloudflare sign-in still require hosted verification.

Overview is the default home page, with Infrastructure, DNS, HTTP & redirects, and Findings tabs. The detail pages share the current report without additional requests. Hash navigation supports direct links and browser back/forward, and tabs support arrow keys, Home and End. Starting another scan clears the old report across every page.

Dark mode is the first-visit default regardless of OS preference. The header theme button switches the whole workspace, and only that preference is saved locally as `skala.theme`. If storage is unavailable, switching still works for the current page. Reports remain in memory only. The standalone review is `review/SKALA-0.5.2-<revision>-Preview.html`; its interface and theme controls work without a hosted backend. Each export has a content-based revision in its filename to keep downloads identifiable.

Header design update: a white brand panel with a curved lower right edge over a cyan-lit server photograph. The header adapts for mobile and includes a restrained light sweep that respects reduced motion. The user-supplied server photograph (1000040983.jpg, 1020 × 360) is preserved as JPEG and embedded in the Worker build, so loading it needs no external image service. The photograph fits at its original proportions beside the curved brand panel, in a gently taller responsive header. Soft edge fades blend it into the dark background without cropping the top or bottom. Run `node scripts/preview.mjs` to regenerate the standalone design review.

An animated, dark diagnostics interface with a small server-side HTTP/DNS probe.

## Cloudflare and internal registration ##

- An orange shield and compact notification appear when the requested host has Cloudflare proxy signals. A single matching response header is labelled a signal rather than confirmed proxy use.
- DNS addresses are compared against Cloudflare's published IPv4/IPv6 proxy ranges, checked 2026-09-14. The snapshot is in `worker/cloudflare.mjs`; review it when updating the detector. Two recognized Cloudflare headers on one response can also establish detection. Headers can be imitated; WAF settings are never claimed to be verified.
- Cloudflare nameservers alone are labelled DNS hosting, with web proxy use unconfirmed. The probe's use of Cloudflare's resolver does not establish that a checked site uses Cloudflare.
- Cloudflare detected on a different redirect hostname is explicitly attributed to that hostname, not to the requested host. Evidence is retained in the Infrastructure view, inspector and JSON export.
- `worker/registration.mjs` is the source-controlled, owner-supplied directory, shared by the interface and Worker. It matches exact normalized hostnames only; no suffix, www or cross-domain redirect association is guessed.
- Initial registration: `kinglaminaat.nl` → **S01 · Interfile**, reported by the user after checking with a colleague on 2026-09-14. It is labelled a manual record, not a live panel lookup. Review or update it after migrations.
- Registration is displayed beside the input before scanning and remains available even if the backend/DNS is unavailable. Public origin IP and live hosting-panel sync remain unconnected. SKALA's scope is information and diagnosis: it identifies the server; the user authenticates directly on that server and obtains any DB SSO link through DirectAdmin. Work credentials, database access and SSO handling are outside SKALA's scope.
- Do not place passwords, API tokens or SSO URLs in the registration directory. This directory ships with the owner-private interface. A broader directory, editing/import and panel synchronisation need their own access/persistence design.

## DNS runtime fix (0.5.2) ##

The original DNS request used `redirect: 'error'`. In workerd 1.20260914.1 this throws
`Invalid redirect value` before a network request is made. The old generic error handler
hid that exception, producing 0/9 DNS replies and skipping both website probes.
The same failure was reproduced with the original source in the actual Worker runtime.

DNS now uses `redirect: 'manual'`. Resolver redirects are rejected explicitly, with their
status retained, and are never followed. Runtime option errors, resolver HTTP failures,
network failures, invalid JSON and timeouts have separate error codes in the exported
report and DNS view. When DNS prevents both web checks, the overview banner explains
why the checks did not start instead of announcing a completed website check.

`npm test` now also runs four tests in Cloudflare's workerd runtime, using native fetch
with deterministic outbound fixture responses. The runtime suite covers successful DNS
and HTTP/HTTPS redirects, refused resolver redirects, resolver HTTP errors and private
address rejection. workerd is a pinned development dependency; the deployed Worker
still has no third-party runtime dependencies. See [UPGRADE-0.5.2.md](UPGRADE-0.5.2.md).

## Reliability patch ##

- Redirect warnings use normalized destinations from real redirect responses, including uppercase URL schemes. Ordinary response Location headers do not become redirects.
- HTTP and HTTPS entry outcomes are retained separately. A failing secondary entry creates a finding even if the preferred entry succeeds; identical final failures are not duplicated.
- The form displays both normalized homepage URLs before scanning, explicitly noting discarded paths, queries and fragments. Browser and Worker use the same parser.
- Backend availability, resolver replies, and both web entry paths have separate indicators. Starting or failing a scan clears previous observations, and an older health response cannot overwrite a newer scan's connection state.
- A deterministic fingerprint of shipped source identifies the interface, backend, API responses, and exported reports. Mismatched interface/backend builds show a reload notice. No supplied URL path or query is retained in report metadata.

## Implemented ##

- Public-domain homepage checks for both HTTP and HTTPS.
- Status and time to response headers, measured from the SKALA probe.
- Manual redirect handling, with a five-redirect cap and loop detection.
- A, AAAA, CNAME, NS, MX and TXT queries through Cloudflare 1.1.1.1 DNS over HTTPS.
- DNS errors remain unknown; they are not reported as absent records.
- Selected response headers, reported server technology, inspector drawers and JSON export.
- Distinct reachable, HTTP-only, restricted, HTTP error and unverified states.
- Scan and result animations, responsive layout and reduced-motion support.

Live HTTP/DNS observations are never hardcoded. The internal registration directory contains owner-supplied records with explicit provenance. There is no automatic recurring polling or stored scan history.

## Limits ##

- This is a point-in-time HTTP probe, not a browser-rendered application health test.
- CDNs, WAFs, authentication and probe location can affect the observed response.
- Time to headers is not page-load time.
- Certificate issuer, expiry, origin TLS behind proxies, provider, ASN and location are not inspected from the origin. Internal server IDs are shown only from the manual registration directory; they are not inferred from public IPs.
- The endpoint checks the homepage even when the input contains a path or query.
- NS and DMARC queries use the checked base name. Parent delegation and DMARC policy inheritance are not inferred.

## Source and build ##

- `dist/index.html`, `dist/styles.css`, `dist/dark.css`, `dist/app.js`: authored interface.
- `worker/target.mjs`: shared target normalization, also emitted for the browser.
- `worker/diagnostics.mjs`: bounded HTTP/DNS collection and findings.
- `worker/handler.mjs`: same-app JSON API and asset handling.
- `scripts/assets.mjs`: shared asset preparation and deterministic build metadata.
- `scripts/build.mjs`: creates a Cloudflare-compatible ESM Worker in `dist/server/index.js`.
- `tests/`: injected-network tests; these never contact an external website.
- `review/`: self-contained visual previews. Live checks require the hosted backend.

There are no third-party runtime dependencies. Run `npm ci` for development/test dependencies, then `npm test` and `npm run build`.
The existing Sites project owns private hosting and source versions.

## Request boundaries ##

The probe sends clean GET requests and never forwards incoming cookies or authorization headers.
It does not return webpage bodies or Set-Cookie values. Inputs and every redirect are checked
for eligible hostnames, protocols and ports. Public DNS addresses are checked before requesting
each hostname. Private and reserved addresses are excluded. DNS checks and HTTP fetches are
separate resolutions; this is not a general-purpose DNS-pinned proxy.

Incoming scan JSON has a five-second deadline and 4096-byte limit. Timed-out or aborted uploads release their concurrency slot without waiting on stalled stream cancellation. Each subsequent scan has a 22-second budget, per-request deadlines and bounded resolver response bodies.
The API requires a custom same-app request header and does not enable cross-origin requests.
The small concurrency/cooldown guard is per Worker instance, not a distributed rate limiter.
Keep the Site owner-private until broader access and abuse controls are deliberately designed.

## Verification for this revision ##

Forty-seven Node tests and four Worker-runtime tests cover request boundaries, stalled and aborted upload recovery, redirects, entry points, targets, build identity, Cloudflare ranges and evidence attribution, exact registration matches, stale interface state, the Access guard, PWA installation controls and offline behaviour. Interface tests execute the generated
scripts with a DOM harness; they do not assess browser rendering. Network responses are simulated; the Worker suite exercises native fetch and stream APIs. The original DNS failure and corrected successful scan were both reproduced in workerd. A live Kinglaminaat scan on the user-managed Worker still needs confirmation after deploying this patch.

## Runtime references ##

- [Cloudflare Workers Fetch API](https://developers.cloudflare.com/workers/runtime-apis/fetch/)
- [Cloudflare DNS-over-HTTPS JSON format](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)
