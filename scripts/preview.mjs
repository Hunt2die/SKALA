import { writeFile } from 'node:fs/promises';
import { createAssets, root, styles, scripts } from './assets.mjs';

// A self-contained design review. Live probes still require the hosted backend.
const { assets, build } = await createAssets();
let html = assets['/index.html'].body;
html = html.replace(/<link rel="manifest"[^>]*>\s*/, '');
for (const name of styles) {
  html = html.replace(new RegExp('<link rel="stylesheet" href="' + name.replace('.', '\\.') + '\\?[^\"]+">'),
    () => '<style>' + assets['/' + name].body + '</style>');
}
for (const name of scripts) {
  html = html.replace(new RegExp('<script src="' + name.replace('.', '\\.') + '\\?[^\"]+" defer></script>'), '');
  html = html.replace('</body>', () => '<script>' + assets['/' + name].body.replace(/<\/script/gi, '<\\/script') + '</script></body>');
}
for (const name of ['icon.svg', 'icon-180.png', 'server-header.jpg']) {
  const asset = assets['/' + name];
  const base64 = asset.encoding === 'base64' ? asset.body : Buffer.from(asset.body).toString('base64');
  html = html.replace('"' + name + '"', () => '"data:' + asset.type + ';base64,' + base64 + '"');
}
const filename = 'SKALA-' + build.version + '-' + build.revision + '-Preview.html';
await writeFile(new URL('review/' + filename, root), html);
console.log('Saved review/' + filename);
