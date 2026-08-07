// Palimpsest headless test suite — node test/crypto.test.mjs
//
// Exit criteria: all 9 brief tests + tests 10–11 green before the UI (milestone 3).
// Current status: all 11 green (milestone 2 complete).
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
  ErrorCodes,
  PalimpsestError,
} from '../src/crypto-core.mjs';
import {
  embedInPng,
  extractFromPng,
  StegoCodes,
  StegoError,
} from '../src/stego-png.mjs';
import pngjsPkg from 'pngjs';

const { PNG } = pngjsPkg;

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

// ─── Helpers ─────────────────────────────────────────────────────────────────

// Create a fully opaque, black PNG of the given dimensions using pngjs.
// All R/G/B channels are 0, alpha is 255. The all-zero LSBs make length
// prefix reads return 0x00000000 → len=0 → NO_PAYLOAD_FOUND on a fresh carrier.
function makePng(width, height) {
  return new Promise((resolve, reject) => {
    const png = new PNG({ width, height, filterType: -1 });
    const buf = Buffer.alloc(width * height * 4);
    for (let i = 3; i < buf.length; i += 4) buf[i] = 255; // alpha = 255, RGB = 0
    png.data = buf;
    const chunks = [];
    png.pack()
      .on('data',  c => chunks.push(c))
      .on('end',   () => resolve(new Uint8Array(Buffer.concat(chunks))))
      .on('error', reject);
  });
}

// Flip the first bit (MSB) of the given byte offset in the LSB stream.
// Stream bit index si = streamByteOffset*8. Each bit occupies LSB of channel
// (si%3) of pixel floor(si/3). Decoding and re-encoding via pngjs is lossless;
// the flipped bit survives the round-trip and corrupts the ciphertext region.
async function tamperStegoStream(pngBytes, streamByteOffset) {
  const { data, width, height } = await new Promise((resolve, reject) => {
    const png = new PNG();
    png.on('parsed', function () {
      resolve({ data: new Uint8Array(this.data), width: this.width, height: this.height });
    });
    png.on('error', reject);
    png.parse(Buffer.from(pngBytes));
  });

  const si      = streamByteOffset * 8;
  const rgba    = Math.floor(si / 3) * 4 + (si % 3);
  data[rgba]   ^= 0x01;

  return new Promise((resolve, reject) => {
    const png = new PNG({ width, height, filterType: -1 });
    png.data = Buffer.from(data);
    const chunks = [];
    png.pack()
      .on('data',  c => chunks.push(c))
      .on('end',   () => resolve(new Uint8Array(Buffer.concat(chunks))))
      .on('error', reject);
  });
}

// ─── Test 1: round-trip through a PNG carrier ─────────────────────────────────

await test('1. Round-trip: encrypt → embed in PNG → extract → decrypt', async () => {
  const original = 'Hello from a PNG carrier! 🔒';
  const payload  = await encryptPayload({ type: 'text', data: original }, 'password', 'pepper', null, FAST);
  const carrier  = await makePng(200, 200);
  const stego    = await embedInPng(carrier, payload);
  const extracted = await extractFromPng(stego);
  const result   = await decryptPayload(extracted, 'password', 'pepper', null);
  assert.equal(result.type, 'text');
  assert.equal(result.data, original);
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

  // Positive control: correct password decrypts.
  const ok = await decryptPayload(payload, 'correct-password', 'pepper', null);
  assert.equal(ok.data, 'secret');

  // Negative: wrong password → DECRYPTION_FAILED.
  const err = await decryptPayload(payload, 'wrong-password', 'pepper', null).then(() => null, e => e);
  assert.ok(err instanceof PalimpsestError, `expected PalimpsestError, got ${err?.constructor?.name}`);
  assert.equal(err.code, ErrorCodes.DECRYPTION_FAILED);
  assert.match(err.message, /could not be decrypted/);
});

// ─── Test 4: wrong pepper is rejected ────────────────────────────────────────

await test('4. Wrong pepper rejected', async () => {
  const payload = await encryptPayload(
    { type: 'text', data: 'secret' },
    'password', 'correct-pepper', null, FAST,
  );

  // Positive control: correct pepper decrypts.
  const ok = await decryptPayload(payload, 'password', 'correct-pepper', null);
  assert.equal(ok.data, 'secret');

  // Negative: wrong pepper → DECRYPTION_FAILED.
  const err = await decryptPayload(payload, 'password', 'wrong-pepper', null).then(() => null, e => e);
  assert.ok(err instanceof PalimpsestError, `expected PalimpsestError, got ${err?.constructor?.name}`);
  assert.equal(err.code, ErrorCodes.DECRYPTION_FAILED);
  assert.match(err.message, /could not be decrypted/);
});

// ─── Test 5: tampered ciphertext is rejected ─────────────────────────────────
// AES-GCM authentication tag covers the ciphertext. Flipping any bit must throw.

await test('5. Tampered ciphertext rejected (bit flip)', async () => {
  const payload = await encryptPayload(
    { type: 'text', data: 'secret' },
    'password', 'pepper', null, FAST,
  );

  // Positive control: untampered payload decrypts.
  const ok = await decryptPayload(payload, 'password', 'pepper', null);
  assert.equal(ok.data, 'secret');

  // Negative: flip a bit near the end of the ciphertext → DECRYPTION_FAILED.
  const tampered = new Uint8Array(payload);
  tampered[tampered.length - 5] ^= 0x01;
  const err = await decryptPayload(tampered, 'password', 'pepper', null).then(() => null, e => e);
  assert.ok(err instanceof PalimpsestError, `expected PalimpsestError, got ${err?.constructor?.name}`);
  assert.equal(err.code, ErrorCodes.DECRYPTION_FAILED);
  assert.match(err.message, /could not be decrypted/);
});

// ─── Test 6: tampered carrier rejected ───────────────────────────────────────
// The outer header (81 B) and the stream length prefix (4 B) are at stream
// bytes 0–84. Tampering at stream byte 100 (ciphertext byte 15) leaves the
// magic / length prefix intact so extractFromPng succeeds, but AES-GCM rejects
// the corrupted ciphertext and decryptPayload throws DECRYPTION_FAILED.

await test('6. Tampered carrier rejected', async () => {
  const original = 'tamper-test-message';
  const payload  = await encryptPayload({ type: 'text', data: original }, 'pw', 'pp', null, FAST);
  const carrier  = await makePng(200, 200);
  const stego    = await embedInPng(carrier, payload);

  // Positive control: untampered stego round-trips.
  const extracted = await extractFromPng(stego);
  const ok = await decryptPayload(extracted, 'pw', 'pp', null);
  assert.equal(ok.data, original);

  // Negative: flip a bit in the ciphertext region (stream byte 100).
  // Stream byte 100 = payload byte 96 = ciphertext byte 15 (outer header is 81 B).
  const tampered = await tamperStegoStream(stego, 100);
  const tamperedPayload = await extractFromPng(tampered); // extraction still succeeds
  const err = await decryptPayload(tamperedPayload, 'pw', 'pp', null).then(() => null, e => e);
  assert.ok(err instanceof PalimpsestError, `expected PalimpsestError, got ${err?.constructor?.name}`);
  assert.equal(err.code, ErrorCodes.DECRYPTION_FAILED);
});

// ─── Test 7: capacity overflow caught before any work ────────────────────────
// capacity(5, 5) = floor(75/8) = 9 B. The stream prefix alone is 4 B, so any
// real payload (outer header = 81 B alone) overflows immediately.

await test('7. Capacity overflow caught before any work begins', async () => {
  const payload     = await encryptPayload({ type: 'text', data: 'hi' }, 'pw', 'pp', null, FAST);
  const bigCarrier  = await makePng(200, 200); // capacity 15 000 B — fits easily
  const smallCarrier = await makePng(5, 5);    // capacity 9 B — nowhere near enough

  // Positive control: large carrier accepts the payload.
  const stego  = await embedInPng(bigCarrier, payload);
  const result = await decryptPayload(await extractFromPng(stego), 'pw', 'pp', null);
  assert.equal(result.data, 'hi');

  // Negative: 5×5 carrier overflows; error must name both sizes.
  const err = await embedInPng(smallCarrier, payload).then(() => null, e => e);
  assert.ok(err instanceof StegoError, `expected StegoError, got ${err?.constructor?.name}: ${err?.message}`);
  assert.equal(err.code, StegoCodes.CAPACITY_EXCEEDED);
  assert.match(err.message, /need \d+ B/, 'message must state required bytes');
  assert.match(err.message, /capacity is \d+ B/, 'message must state available bytes');
});

// ─── Test 8: large payload near carrier capacity round-trips ─────────────────
// Compute the minimum number of pixels (in a 1-row PNG) that exactly fits the
// payload: minPixels = ceil((4 + payload.length) * 8 / 3).
// capacity(minPixels, 1) = floor(minPixels * 3 / 8) >= 4 + payload.length by
// construction, so embedInPng must accept and extractFromPng must return the
// original bytes intact.

await test('8. Large payload near capacity round-trips correctly', async () => {
  const original = 'near-capacity-message';
  const payload  = await encryptPayload({ type: 'text', data: original }, 'pw', 'pp', null, FAST);
  const required = 4 + payload.length;
  const minPx    = Math.ceil(required * 8 / 3);
  const carrier  = await makePng(minPx, 1);

  const stego    = await embedInPng(carrier, payload);
  const result   = await decryptPayload(await extractFromPng(stego), 'pw', 'pp', null);
  assert.equal(result.data, original);
});

// ─── Test 9: carrier with no payload takes the "not found" path ──────────────
// A fresh black PNG has all R/G/B LSBs = 0. readBits returns a length prefix
// of 0x00000000 → len = 0 → NO_PAYLOAD_FOUND. The positive control embeds a
// real payload first and verifies extraction still works.

await test('9. Carrier with no payload: "not found" path, no crash', async () => {
  const original = 'positive-control';
  const payload  = await encryptPayload({ type: 'text', data: original }, 'pw', 'pp', null, FAST);
  const carrier  = await makePng(200, 200);

  // Positive control: carrier with embedded payload extracts correctly.
  const stego    = await embedInPng(carrier, payload);
  const extracted = await extractFromPng(stego);
  const result   = await decryptPayload(extracted, 'pw', 'pp', null);
  assert.equal(result.data, original);

  // Negative: fresh (unmodified) carrier has no payload → NO_PAYLOAD_FOUND.
  const fresh = await makePng(200, 200);
  const err = await extractFromPng(fresh).then(() => null, e => e);
  assert.ok(err instanceof StegoError, `expected StegoError, got ${err?.constructor?.name}`);
  assert.equal(err.code, StegoCodes.NO_PAYLOAD_FOUND);
  assert.match(err.message, /No payload found/);
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
  const err1 = await decryptPayload(payload, 'password', 'pepper', null).then(() => null, e => e);
  assert.ok(err1 instanceof PalimpsestError);
  assert.equal(err1.code, ErrorCodes.DECRYPTION_FAILED);

  // Different secret → wrong key material → must fail.
  const err2 = await decryptPayload(payload, 'password', 'pepper', wrongCb).then(() => null, e => e);
  assert.ok(err2 instanceof PalimpsestError);
  assert.equal(err2.code, ErrorCodes.DECRYPTION_FAILED);
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
  // Brief tests are 1–9. Tests 10–11 are additions; they don't count toward the
  // 9-test gate but do count toward the total and must also be green.
  const briefGreen = passed - 2; // subtract tests 10 and 11
  console.log(`Milestone exit gate: ${briefGreen} of 9 brief tests green, ${passed} of 11 total. Tests 1, 6–9 blocked on milestone 2 (LSB stego).`);
}
if (failed > 0) process.exit(1);
