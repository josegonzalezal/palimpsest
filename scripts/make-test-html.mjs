// Generate test/argon2-browser-test.html — verifies that hash-wasm's argon2
// UMD bundle works when a page is opened via file://, with a restrictive CSP
// that includes 'wasm-unsafe-eval' (required for WebAssembly.compile from a
// Uint8Array under a script-src CSP).
import { readFile, writeFile } from 'node:fs/promises';
import { join, dirname }       from 'node:path';
import { fileURLToPath }       from 'node:url';

const root   = dirname(dirname(fileURLToPath(import.meta.url)));
const argon2 = await readFile(join(root, 'node_modules/hash-wasm/dist/argon2.umd.min.js'), 'utf8');

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Argon2 file:// compatibility test</title>
  <meta http-equiv="Content-Security-Policy"
    content="default-src 'none'; script-src 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'unsafe-inline';">
  <script>${argon2}</script>
  <style>
    body { font-family: monospace; padding: 2rem; background: #111; color: #ddd; }
    h1   { font-size: 1rem; margin-bottom: 1rem; color: #fff; }
    pre  { white-space: pre-wrap; word-break: break-all; line-height: 1.6; }
    .pass { color: #7f7; }
    .fail { color: #f77; }
  </style>
</head>
<body>
  <h1>Argon2id / hash-wasm &mdash; file:// compatibility test</h1>
  <pre id="out">Running Argon2id (m=8192, t=1, p=1)&#x2026;</pre>
  <script>
  'use strict';
  (async () => {
    const out = document.getElementById('out');
    try {
      const hash = await hashwasm.argon2id({
        password:   new Uint8Array([112, 97, 115, 115]),     // "pass"
        salt:       new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]),
        memorySize: 8192,
        iterations: 1,
        parallelism: 1,
        hashLength:  32,
        outputType: 'hex',
      });
      out.className = 'pass';
      out.textContent =
        'PASS\\n\\n' +
        'hashwasm.argon2id is available and produced a hash.\\n' +
        'hash: ' + hash + '\\n\\n' +
        'The UMD bundle works under file:// with wasm-unsafe-eval CSP.';
    } catch (err) {
      out.className = 'fail';
      out.textContent = 'FAIL\\n\\n' + err.message + '\\n\\n' + err.stack;
    }
  })();
  </script>
</body>
</html>`;

await writeFile(join(root, 'test', 'argon2-browser-test.html'), html, 'utf8');
const bytes = Buffer.byteLength(html, 'utf8');
console.log(`test/argon2-browser-test.html written (${(bytes / 1024).toFixed(1)} KB)`);
