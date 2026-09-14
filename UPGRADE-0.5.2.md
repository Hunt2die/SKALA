# SKALA 0.5.2 — DNS Worker fix

The DNS requests used `redirect: "error"`, which Cloudflare's Worker runtime rejected
before sending them. The old error handler hid that exception. This caused 0/9 DNS
replies and prevented HTTP/HTTPS checks. The fix uses manual redirect handling and
explicitly refuses resolver redirects. DNS failures now retain meaningful error codes.

## Update your existing GitHub deployment

1. Extract `SKALA-0.5.2-DNS-Fix.zip` and open its `SKALA` folder.
2. Copy its contents into the root of your existing GitHub checkout, preserving the
   `dist/`, `worker/` and `tests/` paths. Commit the updates to the branch Cloudflare builds.
   You can also use GitHub's **Add file → Upload files** at the repository root; upload
   the contents of `SKALA`, without nesting another `SKALA` folder.
3. Wait for the Cloudflare build and deployment to succeed. Its existing commands remain
   `npm test && npm run build` and `npx wrangler@latest deploy`. The new lockfile includes
   a pinned workerd development dependency for runtime tests; allow dev dependencies
   during the build (the default).
4. Reload SKALA and check that its footer reports **Basic 0.5.2**. Run a new
   `kinglaminaat.nl` scan. DNS should now reach the resolver, allowing web checks when
   public addresses are returned. A real server may still restrict the probe; SKALA
   will show the response or resolver failure it actually observes.

This is an overlay patch. It intentionally does not include `wrangler.jsonc`, Access
settings or credentials. Your existing Worker name, email allowlist and sign-in
configuration stay in your repository. The generated `dist/server/` output is rebuilt
by Cloudflare and is not included.

## Verification

- Reproduced the original source's 0/9 DNS failure in workerd 1.20260914.1, with the
  native exception identifying the unsupported redirect option.
- The patched source completes all nine fixture DNS queries, HTTPS 200 and HTTP →
  HTTPS redirect tracing in the same runtime.
- 47 Node tests and four native Worker-runtime tests pass. Resolver redirects, failed
  resolvers and private target addresses remain blocked without fabricated site status.
- Tests use controlled network responses. The patch has not been deployed to your
  Cloudflare account here, and live Kinglaminaat results still need the scan above.

If it still fails after the footer shows 0.5.2, use **Export report** and share the JSON.
It includes each resolver's error code, DNS evidence and the deployed build ID.
