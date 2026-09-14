# SKALA 0.5.3 — Cloudflare detection fix

Version 0.5.2 could confirm Cloudflare from any two recognized response headers, even
when DNS returned an address outside Cloudflare's published networks. Multiple headers
on one request path are not independent proof that the target site uses its proxy.

## What changes

- The orange shield requires a DNS address in a published Cloudflare proxy range for
  the exact hostname. Redirect hosts are evaluated and named separately.
- Header-only signals show **Cloudflare unconfirmed** with a neutral info badge.
  They no longer raise the orange banner or assign a confirmed proxy provider.
- Evidence shows public addresses, range matches (or no match), and the original
  headers. Exports include the decision basis. The environment value is labelled
  **Server header**, since it can describe an intermediary.
- Nameservers alone continue to indicate DNS hosting, not web proxy protection.
  Non-matching addresses do not rule out every Cloudflare service or custom IP setup.

## Apply to your existing 0.5.2 repository

1. Extract `SKALA-0.5.3-Cloudflare-Detection-Fix.zip` and open its `SKALA` folder.
2. Upload the contents into `Hunt2die/SKALA` at the repository root, preserving the
   `dist/`, `worker/` and `tests/` folders. Commit to `main`.
3. Wait for the connected Cloudflare build to deploy that new commit. Existing build
   commands remain `npm test && npm run build` and `npx wrangler deploy`.
4. Reload SKALA and check the footer says **Basic 0.5.3**. Run a fresh scan of
   `www.sandwichshopamsterdam.com` and open its Cloudflare evidence.

If DNS still returns `185.107.91.213` and only the headers suggest Cloudflare, the result
should now be **Cloudflare unconfirmed**, with no orange shield. If no Cloudflare
headers are observed either, no Cloudflare badge appears. Reachability still depends
on the actual HTTP response. The domain and IP are not special-cased in the detector.

This overlay excludes `wrangler.jsonc`, Access settings, credentials, installed
dependencies and generated `dist/server/` output. Cloudflare rebuilds that output.

## Verification

All 51 Node tests and five native Worker-runtime tests pass; the production build succeeds.

Regression tests cover the reported address with three Cloudflare headers, a genuine
network match, IPv6, base/www separation, redirect attribution, UI state and export
evidence. The native workerd test uses controlled outbound responses and preserves
the raw headers while leaving proxy detection unconfirmed.

An independent live GET returned `server: nginx`, and public DNS returned
`185.107.91.213` with no AAAA record on 2026-09-14. This supports the reported false
positive; it does not establish which intermediary supplied the Worker's headers.
This patch has not been deployed to your Cloudflare account here.
