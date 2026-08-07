// scripts/demo.mjs — exercise the crypto core by hand before there is a UI.
//
// Usage:
//   node scripts/demo.mjs [message] [password] [pepper]
//
// Defaults: "Hello from Palimpsest" / "demo-password" / "demo-pepper"
// Output:   message.ptx (raw binary payload) in the current directory.
//
// Note: uses production Argon2 parameters (m=64 MB, t=3). Expect ~5–15 s per
// KDF call on a laptop; that is the point — it proves the production config works.

import { readFile, writeFile } from 'node:fs/promises';
import { encryptPayload, decryptPayload } from '../src/crypto-core.mjs';

const message  = process.argv[2] ?? 'Hello from Palimpsest';
const password = process.argv[3] ?? 'demo-password';
const pepper   = process.argv[4] ?? 'demo-pepper';
const outFile  = 'message.ptx';

console.log(`Message:   "${message}"`);
console.log(`Encrypting (Argon2id m=64 MB, ~5–15 s)…`);

const payload = await encryptPayload({ type: 'text', data: message }, password, pepper);
await writeFile(outFile, payload);
console.log(`Written:   ${outFile}  (${payload.length} bytes)`);

console.log(`Decrypting…`);
try {
  const loaded = new Uint8Array(await readFile(outFile));
  const result = await decryptPayload(loaded, password, pepper);
  console.log(`Decrypted: "${result.data}"`);
} catch (err) {
  console.error(`Decryption failed: ${err.message}`);
  process.exit(1);
}
