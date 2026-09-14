import { writeFile, mkdir, copyFile, readFile, rm } from 'node:fs/promises';
import { createAssets, root } from './assets.mjs';

const { assets, build } = await createAssets();
const output = new URL('dist/server/', root);
await mkdir(output, { recursive: true });
for (const name of ['target.mjs', 'diagnostics.mjs', 'handler.mjs', 'registration.mjs', 'cloudflare.mjs', 'access.mjs']) {
  await copyFile(new URL('worker/' + name, root), new URL(name, output));
}
await writeFile(new URL('dist/target.js', root), assets['/target.js'].body);
await writeFile(new URL('dist/registration.js', root), assets['/registration.js'].body);
// Keep the existing Sites metadata when present; a GitHub/Cloudflare checkout needs none.
let hostingMetadata;
try { hostingMetadata = await readFile(new URL('.openai/hosting.json', root)); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
if (hostingMetadata) {
  await mkdir(new URL('dist/.openai/', root), { recursive: true });
  await writeFile(new URL('dist/.openai/hosting.json', root), hostingMetadata);
} else {
  await rm(new URL('dist/.openai/hosting.json', root), { force: true });
}
await writeFile(new URL('index.js', output),
  'import { createHandler } from "./handler.mjs";\n' +
  'const assets = ' + JSON.stringify(assets) + ';\n' +
  'for (const asset of Object.values(assets)) if (asset.encoding === "base64") asset.body = Uint8Array.from(atob(asset.body), c => c.charCodeAt(0));\n' +
  'export default { fetch: createHandler(assets, undefined, ' + JSON.stringify(build) + ') };\n');
// The existing Sites host supplies its own access gate. Direct Cloudflare deployments require this wrapper.
await writeFile(new URL('cloudflare-entry.js', output),
  'import app from "./index.js";\nimport { withCloudflareAccess } from "./access.mjs";\n' +
  'export default { fetch: withCloudflareAccess(app.fetch) };\n');
console.log('Built SKALA ' + build.id + '.');
