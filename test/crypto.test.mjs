// Palimpsest headless test suite — node test/crypto.test.mjs
//
// Exit criteria: all 9 brief tests + tests 10–11 green before the UI (milestone 3).
// Current status: 4 of 9 brief tests green (tests 2–5). Tests 1, 6–9 are blocked
// on LSB steganography (milestone 2). Tests 10–11 are new additions below.
//
// Run:  node test/crypto.test.mjs
// Note: test 11 uses production Argon2 params (m=64 MB) and takes ~5–15 s.

import assert from 'node:assert/strict';
import {
  encryptPayload,
  decryptPayload,
  armorPayload,
  unarmorPayload,
  ARGON2_DEFAULTS,
} from '../src/crypto-core.mjs';

// Lighter KDF params for test speed — logic is identical, only cost differs.
// m must be >= ARGON2_LIMITS.m.min (8 MB = 8192 KiB) or decodeKdfParams rejects
// the payload header on decryption, causing tests to pass for the wrong reason.
const FAST = { m: 8192, t: 1, p: 1 };

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

// ─── Test 10: getPrfSecret callback — end-to-end with a stubbed secret ───────
// The real callback drives a WebAuthn PRF round-trip: it receives the prfSalt
// stored in the header and returns the secret the hardware key derives from it.
// Here we stub it with a fixed secret to test the key-material path in isolation.

await test('10. getPrfSecret callback: round-trip and rejection', async () => {
  const prfSecret  = crypto.getRandomValues(new Uint8Array(32));
  const wrongSecret = crypto.getRandomValues(new Uint8Array(32));

  // Stub: ignores the salt and always returns the same secret.
  // A real implementation would pass the salt to navigator.credentials.get().
  const correctCb = async (_prfSalt) => prfSecret;
  const wrongCb   = async (_prfSalt) => wrongSecret;

  const payload = await encryptPayload(
    { type: 'text', data: 'hardware-key-protected' },
    'password', 'pepper', correctCb, FAST,
  );

  // Same callback (same secret) decrypts.
  const result = await decryptPayload(payload, 'password', 'pepper', correctCb);
  assert.equal(result.data, 'hardware-key-protected');

  // No callback → prfSecret absent from key material → must fail.
  await assert.rejects(
    decryptPayload(payload, 'password', 'pepper', null),
    /could not be decrypted/,
  );

  // Different secret → wrong key material → must fail.
  await assert.rejects(
    decryptPayload(payload, 'password', 'pepper', wrongCb),
    /could not be decrypted/,
  );
});

// ─── Test 11: production Argon2 parameters — single round-trip ───────────────
// Verifies that the real KDF configuration (m=64 MB, t=3, p=1) actually works.
// Without this, the parameters we ship could silently be wrong or rejected by
// hash-wasm (e.g. out-of-range value) and only a user would ever find out.
// Expected runtime: 5–15 s depending on the machine.

await test('11. Production Argon2 parameters round-trip (m=64 MB, t=3, p=1)', async () => {
  const result = await encryptPayload(
    { type: 'text', data: 'production-params-test' },
    'password', 'pepper', null, ARGON2_DEFAULTS,
  ).then(payload => decryptPayload(payload, 'password', 'pepper', null));

  assert.equal(result.data, 'production-params-test');
});

// ─── Summary ─────────────────────────────────────────────────────────────────

const total = passed + pending + failed;
console.log('');
console.log(`Results: ${passed} passed, ${pending} pending, ${failed} failed  (${total} total)`);
console.log('');
if (pending > 0) {
  console.log(`Milestone exit gate: ${passed} of 9 brief tests green. Tests 1, 6–9 blocked on milestone 2 (LSB stego).`);
}
if (failed > 0) process.exit(1);
