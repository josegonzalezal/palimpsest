import { readFile, writeFile } from 'node:fs/promises';
import { join, dirname }       from 'node:path';
import { fileURLToPath }       from 'node:url';

const root   = dirname(dirname(fileURLToPath(import.meta.url)));
const argon2 = await readFile(join(root, 'node_modules/hash-wasm/dist/argon2.umd.min.js'), 'utf8');
const tmpl   = await readFile(join(root, 'src/client.template.html'), 'utf8');

// Use the function form of String.replace so special-character sequences in
// argon2 (e.g. $& $` $') are not interpreted as substitution patterns.
const html = tmpl.replace('{{ARGON2_UMD}}', () => argon2);

if (html === tmpl) throw new Error('{{ARGON2_UMD}} placeholder not found in template');

await writeFile(join(root, 'index.html'), html, 'utf8');
const kb = (Buffer.byteLength(html, 'utf8') / 1024).toFixed(1);
console.log(`index.html written (${kb} KB)`);
