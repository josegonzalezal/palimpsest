// Palimpsest headless test suite — node test/crypto.test.mjs
// Tests 1, 6–9 require LSB steganography (milestone 2) and are marked PENDING.
// Tests 2–5 cover the crypto core and must all pass before the UI is built.

import assert from 'node:assert/strict';
import {
  encryptPayload,
  decryptPayload,
  armorPayload,
  unarmorPayload,
  ARGON2_DEFAULTS,
} from '../src/crypto-core.mjs';

// Lighter KDF params for test speed — logic is identical, only cost differs.
const FAST = { m: 1024, t: 1, p: 1 };

let passed = 0, failed = 0, pending = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓  ${name}`);
    passed++;
  } catch (err) {
    if (err.pending) {
      console.log(`  –  ${name} (PENDING: ${err.message})`);
      pending++;
    } else {
      console.error(`  ✗  ${name}`);
      console.error(`       ${err.message}`);
      failed++;
    }
  }
}

function pendingError(reason) {
  return Object.assign(new Error(reason), { pending: true });
}

// ─── Test 1: round-trip through a PNG carrier ─────────────────────────────────
// Requires LSB steganography. Implemented in milestone 2.

await test('1. Round-trip: encrypt → embed in PNG → extract → decrypt', async () => {
  throw pendingError('LSB steganography not yet implemented (milestone 2)');
});

// ─── Test 2: round-trip through the armored text format ───────────────────────

await test('2. Round-trip: armored text format', async () => {
  const original = 'Hello, Palimpsest! Unicode: 🔒';
  const payload = await encryptPayload(
    { type: 'text', data: original },
    'correct-password', 'correct-pepper', null, FAST,
  );
  const armored = armorPayload(payload);

  // Armored block must have the right delimiters.
  assert.ok(armored.includes('-----BEGIN PALIMPSEST MESSAGE-----'));
  assert.ok(armored.includes('-----END PALIMPSEST MESSAGE-----'));
  assert.ok(armored.includes('Version: 1'));

  const recovered = unarmorPayload(armored);
  assert.ok(recovered instanceof Uint8Array, 'unarmorPayload returned non-Uint8Array');

  // Also accept pasted text with surrounding whitespace.
  const padded = `\n\n  ${armored}  \n\n`;
  const recoveredPadded = unarmorPayload(padded);
  assert.ok(recoveredPadded instanceof Uint8Array, 'unarmorPayload rejected padded input');

  const result = await decryptPayload(recovered, 'correct-password', 'correct-pepper', null);
  assert.equal(result.type, 'text');
  assert.equal(result.data, original);
});

// ─── Test 3: wrong password is rejected ──────────────────────────────────────

await test('3. Wrong password rejected', async () => {
  const payload = await encryptPayload(
    { type: 'text', data: 'secret' },
    'correct-password', 'pepper', null, FAST,
  );
  await assert.rejects(
    decryptPayload(payload, 'wrong-password', 'pepper', null),
    /could not be decrypted/,
  );
});

// ─── Test 4: wrong pepper is rejected ────────────────────────────────────────

await test('4. Wrong pepper rejected', async () => {
  const payload = await encryptPayload(
    { type: 'text', data: 'secret' },
    'password', 'correct-pepper', null, FAST,
  );
  await assert.rejects(
    decryptPayload(payload, 'password', 'wrong-pepper', null),
    /could not be decrypted/,
  );
});

// ─── Test 5: tampered ciphertext is rejected ─────────────────────────────────
// AES-GCM authentication tag covers the ciphertext. Flipping any bit must throw.

await test('5. Tampered ciphertext rejected (bit flip)', async () => {
  const payload = await encryptPayload(
    { type: 'text', data: 'secret' },
    'password', 'pepper', null, FAST,
  );
  const tampered = new Uint8Array(payload);
  // Flip a bit near the end of the ciphertext (well past the header).
  tampered[tampered.length - 5] ^= 0x01;
  await assert.rejects(
    decryptPayload(tampered, 'password', 'pepper', null),
    /could not be decrypted/,
  );
});

// ─── Test 6: tampered carrier rejected ───────────────────────────────────────
// Requires LSB steganography. Implemented in milestone 2.

await test('6. Tampered carrier rejected', async () => {
  throw pendingError('LSB steganography not yet implemented (milestone 2)');
});

// ─── Test 7: capacity overflow caught before any work ────────────────────────
// Requires a carrier to overflow. Implemented in milestone 2.

await test('7. Capacity overflow caught before any work begins', async () => {
  throw pendingError('LSB steganography not yet implemented (milestone 2)');
});

// ─── Test 8: large payload near carrier capacity round-trips ─────────────────
// Requires a carrier. Implemented in milestone 2.

await test('8. Large payload near capacity round-trips correctly', async () => {
  throw pendingError('LSB steganography not yet implemented (milestone 2)');
});

// ─── Test 9: carrier with no payload takes the "not found" path ──────────────
// Requires a carrier. Implemented in milestone 2.

await test('9. Carrier with no payload: "not found" path, no crash', async () => {
  throw pendingError('LSB steganography not yet implemented (milestone 2)');
});

// ─── Summary ─────────────────────────────────────────────────────────────────

console.log('');
console.log(`Results: ${passed} passed, ${pending} pending, ${failed} failed`);
if (failed > 0) process.exit(1);
