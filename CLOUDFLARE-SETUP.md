# SKALA 0.5.4 — GitHub → Cloudflare testing setup

This package contains the dashboard, live DNS/HTTP probe, PWA installation support and SKALA icons. It is ready to deploy; it has not been published to your Cloudflare account.

For an existing 0.5.3 installation, follow [UPGRADE-0.5.4.md](UPGRADE-0.5.4.md); keep your configured `wrangler.jsonc` and Access policy. Older installations should first apply [UPGRADE-0.5.2.md](UPGRADE-0.5.2.md) and [UPGRADE-0.5.3.md](UPGRADE-0.5.3.md) as needed.

## Deploy from GitHub

1. Create a private GitHub repository for SKALA, or use an existing empty one. Put the project contents at its root: `package.json`, `wrangler.jsonc`, `scripts/`, `worker/`, `dist/` and `tests/`. The generated `dist/server/` folder is rebuilt in Cloudflare and does not need committing. Existing Sites metadata is optional and can be omitted from GitHub.
2. In `wrangler.jsonc`, set `SKALA_ALLOWED_EMAILS` to the email address you will use for testing. Keep it inside quotes. Commit the change to `main`.
3. In Cloudflare **Workers & Pages**, create a Worker from the GitHub repository. Authorize Cloudflare's GitHub integration for this repository and name the Worker `skala`, matching `wrangler.jsonc`.
4. Use these build settings:

| Setting | Value |
| --- | --- |
| Production branch | `main` |
| Root directory | Repository root |
| Build command | `npm test && npm run build` |
| Deploy command | `npx wrangler@latest deploy` |
| Builds for other branches | Disabled for the first test |

Cloudflare runs the tests, builds and deploys on each push to the connected branch. Set the build command explicitly: Workers Builds does not honor the custom build command inside `wrangler.jsonc`. Node/Wrangler run in Cloudflare; you do not need to install them on your PC for this route. [Workers Builds configuration](https://developers.cloudflare.com/workers/ci-cd/builds/configuration/)

Use the Worker address Cloudflare supplies, then configure private sign-in below. Installing the Cloudflare GitHub integration in your Cloudflare account is separate from any ChatGPT plugin. Nothing has been pushed to GitHub or deployed to your Cloudflare account by this package.

## Optional: deploy from your computer

1. Unzip the package. Open a terminal in its `SKALA` folder. Install the current Node.js LTS release if `node` and `npm` are unavailable. Node is only needed on your computer for building and deploying; there is no Node server to maintain.
2. In `wrangler.jsonc`, replace the empty `SKALA_ALLOWED_EMAILS` value with the email address you will use to sign in. Keep it inside quotes. The Worker is named `skala`; change that name if it would overwrite another application in your account.
3. Run these commands, signing in to the intended Cloudflare account when prompted:

```sh
npm ci
npm test
npx wrangler@latest login
npx wrangler@latest deploy
```

Wrangler builds and uploads the Worker and prints its address. You can start with the supplied `workers.dev` address; buying a domain is optional. [Cloudflare deployment guide](https://developers.cloudflare.com/workers/get-started/guide/)

SKALA initially refuses access until the next step is complete.

## Restrict sign-in

Enable Cloudflare Zero Trust in your account if needed. In **Workers & Pages → skala → Access**, select **Protect this Worker behind Access → All traffic**. Use an Access **Allow** policy with **Include → Emails** restricted to your sign-in email, then apply it. If necessary, create/edit that policy in **Zero Trust → Access → Applications**. [Cloudflare Access setup](https://developers.cloudflare.com/workers/configuration/cloudflare-access/)

The Worker additionally checks the authenticated email against `SKALA_ALLOWED_EMAILS`. Its dashboard, APIs and assets all use that guard. A missing sign-in context, missing allowlist, different account or failed identity lookup leaves the application unavailable. Keep the supplied `cloudflare-entry.js` entrypoint and configuration: an `assets` binding would prevent the runtime identity check from working. [Access runtime limitations](https://developers.cloudflare.com/workers/configuration/cloudflare-access/#ctxaccess-limitations)

## Open and install

Open the address Wrangler printed and sign in. Select **Install SKALA**, or follow its browser-specific instructions. On iPhone/iPad, open the address in Safari and use **Share → Add to Home Screen**. Installation needs the hosted HTTPS address, not a downloaded HTML preview. [PWA installation guide](https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/Guides/Making_PWAs_installable)

For the first hosted check: scan `kinglaminaat.nl`, confirm the result timestamp changes, then reopen SKALA from its installed icon. A private/incognito window should require sign-in. Live checks need internet access; offline launches show a reconnect page. Reports stay in the open tab, so export any you need to retain.

## If something does not open

| Message | Fix |
| --- | --- |
| SKALA setup… | Set `SKALA_ALLOWED_EMAILS` in `wrangler.jsonc` and redeploy. |
| Sign in through Cloudflare Access… | Protect the Worker’s **All traffic**, then open its address and sign in. |
| This account is not allowed… | Use the same email configured in both the Access policy and SKALA allowlist. |
| Sign-in could not be verified… | Reload and check your Cloudflare Access application. |
| No installation prompt | Use the browser menu or SKALA’s install instructions. You can also use the normal browser tab. |

For later code changes, run the deploy command again. Keep the email allowlist in your local configuration so later deployments preserve it.

The Node and native Worker-runtime suites use simulated outbound responses and authentication. The 0.5.2 patch fixes an unsupported DNS redirect option that previously stopped every DNS request in the Worker runtime. Version 0.5.3 removes overconfident header-only Cloudflare detection and retains the raw evidence. Version 0.5.4 adds bounded IPv4/IPv6 reverse DNS lookups. The request upload has a five-second deadline; expired and cancelled uploads release their scan slot. A local build does not deploy the patch to your Cloudflare account; verify the version and run a new hosted scan after updating.

Internal mapping currently includes the manual `kinglaminaat.nl → S01 · Interfile` record; hosting-panel sync is not connected. SKALA's role ends at diagnosis and identifying the server. You sign in on the real server and obtain any DB SSO link through DirectAdmin there. SKALA does not handle your work credentials, database access or SSO links.
