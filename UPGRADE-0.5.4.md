# SKALA 0.5.4 — Reverse DNS

Scans now look up PTR records for the public IPv4 and IPv6 addresses they resolve.
For the supplied iClicks example, the live IPv4 lookup returned
`213.159.24.244 → s09.iclicks.nl` on 2026-09-14. IPv6 `2a11:800::414` returned no
PTR record (NXDOMAIN) at that time. These are live observations, not built-in mappings.

## What you will see

- **Server mapping:** reverse DNS for the requested host's public addresses. If there
  is no manual registration, the first returned PTR hostname appears prominently as
  **Public hostname (PTR)**. Internal registration remains separately labelled.
- **Infrastructure:** a Reverse DNS table with IP addresses, associated website
  hostnames, PTR hostnames, outcomes and TTLs.
- **DNS:** the same results plus exact reverse query names, DNS response codes and
  resolver errors. Forward DNS counts remain separate from PTR outcomes.
- **Export report:** a `reverseDNS` section with all of that evidence.

## Apply to your existing 0.5.3 repository

1. Extract `SKALA-0.5.4-Reverse-DNS.zip` and open its `SKALA` folder.
2. Upload the contents to the root of `Hunt2die/SKALA`, retaining the existing
   `dist/`, `worker/` and `tests/` paths. Commit to `main`.
3. Wait for Cloudflare's connected build to deploy the new commit. Build and deploy
   commands remain `npm test && npm run build` and `npx wrangler deploy`.
4. Reload SKALA, verify **Basic 0.5.4** in the footer, and run a fresh `iclicks.nl` scan.
   Open Infrastructure or DNS to inspect both address families.

The overlay excludes `wrangler.jsonc`, credentials, Access settings, dependencies and
generated `dist/server/` output. Your existing configuration remains in place.

## Scope and verification

All 58 Node tests and seven native Worker-runtime tests pass, and the build succeeds.
Live PTR responses were checked independently. A complete local Node scan timed out
at forward DNS, so the full live scan still needs verification on your deployed Worker.

Up to eight distinct public addresses are checked, two at a time, within a shared
4.5-second reverse DNS allowance and the existing scan deadline. Shared addresses
are deduplicated; omitted addresses are counted. Resolver failures stay distinct
from absent PTR records and do not change a completed HTTP status.

A PTR hostname can identify a hosting server or a shared proxy. It does not establish
an internal registration or reveal an origin behind a CDN. SKALA displays the returned
name as text and never requests it or logs into it.

The regression suite covers IPv4/IPv6 query formatting, deduplication, aliases, TTLs,
missing PTRs, resolver failures and redirects, timeouts, lookup caps, private address
exclusion, per-host attribution, UI display, escaping and exports. Native workerd tests
exercise successful IPv4/IPv6 PTR resolution and PTR failure alongside a reachable site.
This patch has not been deployed to your Cloudflare account here.
