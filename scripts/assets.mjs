import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

export const root = new URL('../', import.meta.url);
export const styles = ['styles.css', 'dark.css', 'workspace.css', 'light.css'];
export const scripts = ['target.js', 'registration.js', 'app.js', 'workspace.js', 'pwa.js'];

// The same source fingerprint identifies the Worker and the standalone review.
export async function createAssets() {
  const names = ['index.html', ...styles, 'app.js', 'workspace.js', 'pwa.js', 'sw.js',
    'manifest.webmanifest', 'icon.svg', 'icon-180.png', 'icon-192.png', 'icon-512.png', 'server-header.jpg'];
  const paths = [...names.map(name => 'dist/' + name), 'worker/target.mjs',
    'worker/diagnostics.mjs', 'worker/handler.mjs', 'worker/registration.mjs', 'worker/cloudflare.mjs', 'scripts/assets.mjs',
    'worker/access.mjs', 'scripts/build.mjs', 'scripts/preview.mjs', 'package.json', 'wrangler.jsonc'];
  const files = new Map(await Promise.all(paths.map(async name => [name, await readFile(new URL(name, root))])));
  const hash = createHash('sha256');
  for (const [name, bytes] of files) hash.update(name + '\0' + bytes.length + '\0').update(bytes);
  const revision = hash.digest('hex').slice(0, 12);
  const { version } = JSON.parse(files.get('package.json').toString());
  const build = { version, revision, id: version + '+' + revision };
  const assets = {};
  for (const name of names) {
    const extension = name.split('.').at(-1);
    const type = { html: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8',
      js: 'text/javascript; charset=utf-8', svg: 'image/svg+xml', jpg: 'image/jpeg', png: 'image/png',
      webmanifest: 'application/manifest+json' }[extension];
    const encoding = ['jpg', 'png'].includes(extension) ? 'base64' : 'utf8';
    assets['/' + name] = { type, encoding, body: files.get('dist/' + name).toString(encoding) };
  }
  // This small dependency-free module is also emitted as a classic browser script.
  const target = files.get('worker/target.mjs').toString().replace(/^export /gm, '');
  assets['/target.js'] = { type: 'text/javascript; charset=utf-8',
    body: 'const SkalaTarget = (() => {\n' + target + '\nreturn { parseTarget };\n})();\n' };
  assets['/registration.js'] = { type: 'text/javascript; charset=utf-8',
    body: 'const SkalaRegistration = (() => {\n' + files.get('worker/registration.mjs').toString().replace(/^export /gm, '') +
      '\nreturn { lookupRegistration };\n})();\n' };
  const html = assets['/index.html'];
  if (!html.body.includes('id="buildMetadata"') || !html.body.includes('__SKALA_BUILD_LABEL__')) {
    throw new Error('The interface is missing its build metadata markers.');
  }
  html.body = html.body.replace(/(<script id="buildMetadata" type="application\/json">)[\s\S]*?(<\/script>)/,
    (_, open, close) => open + JSON.stringify(build) + close)
    .replaceAll('__SKALA_BUILD_LABEL__', 'Basic ' + version + ' · ' + revision);
  for (const asset of Object.values(assets)) {
    if (asset.encoding !== 'base64') asset.body = asset.body.replaceAll('__SKALA_REVISION__', revision);
  }
  return { assets, build };
}
