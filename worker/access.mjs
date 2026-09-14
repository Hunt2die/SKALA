// Cloudflare-only entrypoint guard. ctx.access is supplied by the Workers runtime,
// not trusted request headers. Assets are embedded; do not add an ASSETS binding.
// https://developers.cloudflare.com/workers/configuration/cloudflare-access/
export function withCloudflareAccess(handle) {
  return async (request, env = {}, ctx = {}) => {
    const headers = { 'content-type':'text/plain; charset=utf-8', 'cache-control':'no-store', 'x-content-type-options':'nosniff' };
    const allowed = String(env.SKALA_ALLOWED_EMAILS || '').split(',').map(email=>email.trim().toLowerCase()).filter(Boolean);
    if (!allowed.length) return new Response('SKALA setup: set SKALA_ALLOWED_EMAILS and protect this Worker with Cloudflare Access.',{status:503,headers});
    if (!ctx?.access || typeof ctx.access.getIdentity !== 'function') {
      return new Response('Sign in through Cloudflare Access to open SKALA.',{status:403,headers});
    }
    try {
      const identity = await ctx.access.getIdentity();
      if (typeof identity?.email !== 'string' || !allowed.includes(identity.email.toLowerCase())) {
        return new Response('This account is not allowed to open SKALA.',{status:403,headers});
      }
    } catch {
      return new Response('Your sign-in could not be verified. Reload SKALA to try again.',{status:503,headers});
    }
    return handle(request, env, ctx);
  };
}
