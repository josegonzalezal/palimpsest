// scripts/demo.mjs — exercise the crypto core by hand before there is a UI.
//
// Usage:
//   node scripts/demo.mjs encrypt <password> <pepper> "<message>"
//   node scripts/demo.mjs decrypt <password> <pepper>
//
// encrypt  Writes the armored payload to message.ptx and exits.
// decrypt  Reads message.ptx, prints the plaintext. On failure prints one line
//          and exits with code 1 — no stack trace.
//
// Argon2 params: m=8 MB, t=1 (fast enough to iterate with).
// Production is m=64 MB, t=3 — expect ~5–15 s per KDF call there.

import { readFile, writeFile } from 'node:fs/promises';
import { encryptPayload, decryptPayload, armorPayload, unarmorPayload } from '../src/crypto-core.mjs';

const DEMO_PARAMS = { m: 8192, t: 1, p: 1 };
const OUT = 'message.ptx';

const [cmd, password, pepper, ...rest] = process.argv.slice(2);

function usage() {
  console.error('Usage:');
  console.error('  node scripts/demo.mjs encrypt <password> <pepper> "<message>"');
  console.error('  node scripts/demo.mjs decrypt <password> <pepper>');
  process.exit(1);
}

if (cmd === 'encrypt') {
  if (!password || !pepper || rest.length === 0) usage();
  const message = rest.join(' ');
  console.log(`Encrypting (Argon2id m=8 MB — production is m=64 MB, ~15 s)…`);
  const payload = await encryptPayload({ type: 'text', data: message }, password, pepper, null, DEMO_PARAMS);
  await writeFile(OUT, armorPayload(payload), 'utf8');
  console.log(`Written: ${OUT}`);

} else if (cmd === 'decrypt') {
  if (!password || !pepper || rest.length > 0) usage();
  const armored = await readFile(OUT, 'utf8').catch(() => {
    console.error(`Cannot read ${OUT} — run encrypt first`);
    process.exit(1);
  });
  const bytes = unarmorPayload(armored);
  if (!bytes) { console.error('No armor block found in message.ptx'); process.exit(1); }
  try {
    const result = await decryptPayload(bytes, password, pepper, null);
    console.log(result.data);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }

} else {
  usage();
}
