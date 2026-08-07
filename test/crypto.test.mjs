// Palimpsest headless test suite — node test/crypto.test.mjs
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
  FLAGS_KEYFILE,
  FLAGS_PRF,
  VERSION,
} from '../src/crypto-core.mjs';
import {
  embedInPng,
  extractFromPng,
  StegoCodes,
  StegoError,
} from '../src/stego-png.mjs';
import pngjsPkg from 'pngjs';

const { PNG } = pngjsPkg;

// m must be >= ARGON2_LIMITS.m.min (8192 KiB) or decodeKdfParams rejects on decrypt.
const FAST = { m: 8192, t: 1, p: 1 };

let passed = 0, failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓  ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗  ${name}`);
    console.error(`       ${err.message}`);
    if (err.stack) console.error(err.stack.split('\n').slice(1, 3).join('\n'));
    failed++;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makePng(width, height) {
  return new Promise((resolve, reject) => {
    const png = new PNG({ width, height, filterType: -1 });
    const buf = Buffer.alloc(width * height * 4);
    for (let i = 3; i < buf.length; i += 4) buf[i] = 255;
    png.data = buf;
    const chunks = [];
    png.pack()
      .on('data',  c => chunks.push(c))
      .on('end',   () => resolve(new Uint8Array(Buffer.concat(chunks))))
      .on('error', reject);
  });
}

async function tamperStegoStream(pngBytes, streamByteOffset) {
  const { data, width, height } = await new Promise((resolve, reject) => {
    const png = new PNG();
    png.on('parsed', function () {
      resolve({ data: new Uint8Array(this.data), width: this.width, height: this.height });
    });
    png.on('error', reject);
    png.parse(Buffer.from(pngBytes));
  });

  const si    = streamByteOffset * 8;
  const rgba  = Math.floor(si / 3) * 4 + (si % 3);
  data[rgba] ^= 0x01;

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

// Read the flags byte out of a raw payload (version 2 header, byte 5).
function readFlags(payload) { return payload[5]; }

// ─── Test 1: round-trip through a PNG carrier ─────────────────────────────────

await test('1. Round-trip: encrypt → embed in PNG → extract → decrypt', async () => {
  const original = 'Hello from a PNG carrier! 🔒';
  const payload  = await encryptPayload({ type: 'text', data: original }, 'password', null, FAST);
  const carrier  = await makePng(200, 200);
  const stego    = await embedInPng(carrier, payload);
  const extracted = await extractFromPng(stego);
  const result   = await decryptPayload(extracted, 'password', null);
  assert.equal(result.type, 'text');
  assert.equal(result.data, original);
});

// ─── Test 2: round-trip through the armored text format ───────────────────────

await test('2. Round-trip: armored text format', async () => {
  const original = 'Hello, Palimpsest! Unicode: 🔒';
  const payload  = await encryptPayload({ type: 'text', data: original }, 'correct-password', null, FAST);
  const armored  = armorPayload(payload);

  assert.ok(armored.includes('-----BEGIN PALIMPSEST MESSAGE-----'));
  assert.ok(armored.includes('-----END PALIMPSEST MESSAGE-----'));
  assert.ok(armored.includes(`Version: ${VERSION}`));

  const recovered = unarmorPayload(armored);
  assert.ok(recovered instanceof Uint8Array, 'unarmorPayload returned non-Uint8Array');

  // Also accept pasted text with surrounding whitespace.
  const padded = `\n\n  ${armored}  \n\n`;
  assert.ok(unarmorPayload(padded) instanceof Uint8Array, 'unarmorPayload rejected padded input');

  const result = await decryptPayload(recovered, 'correct-password', null);
  assert.equal(result.type, 'text');
  assert.equal(result.data, original);
});

// ─── Test 3: wrong password is rejected ──────────────────────────────────────

await test('3. Wrong password rejected', async () => {
  const payload = await encryptPayload({ type: 'text', data: 'secret' }, 'correct-password', null, FAST);

  // Positive control: correct password decrypts.
  const ok = await decryptPayload(payload, 'correct-password', null);
  assert.equal(ok.data, 'secret');

  // Negative: wrong password → DECRYPTION_FAILED.
  const err = await decryptPayload(payload, 'wrong-password', null).then(() => null, e => e);
  assert.ok(err instanceof PalimpsestError);
  assert.equal(err.code, ErrorCodes.DECRYPTION_FAILED);
  assert.match(err.message, /could not be decrypted/);
});

// ─── Test 4: tampered header is rejected (AAD integrity) ─────────────────────
// The salt (bytes 18–33, inside the AAD) is authenticated. Flipping any bit
// changes the AAD, causing the GCM tag check to fail on decryption.
// We tamper the salt rather than the flags byte because flipping FLAGS_KEYFILE
// triggers KEYFILE_REQUIRED before the tag check, which is correct but hides
// the AAD-integrity property we are testing here.

await test('4. Tampered header rejected (salt in AAD)', async () => {
  const payload = await encryptPayload({ type: 'text', data: 'secret' }, 'password', null, FAST);

  // Positive control: unmodified payload decrypts.
  const ok = await decryptPayload(payload, 'password', null);
  assert.equal(ok.data, 'secret');

  // Negative: flip a bit in the salt region (byte 20) → AAD mismatch → DECRYPTION_FAILED.
  // Header layout: magic(4)+version(1)+flags(1)+kdfParamsLen(2)+kdfParams(10)+salt(16) = bytes 18–33.
  const tampered = new Uint8Array(payload);
  tampered[20] ^= 0x01;
  const err = await decryptPayload(tampered, 'password', null).then(() => null, e => e);
  assert.ok(err instanceof PalimpsestError);
  assert.equal(err.code, ErrorCodes.DECRYPTION_FAILED);
  assert.match(err.message, /could not be decrypted/);
});

// ─── Test 5: tampered ciphertext is rejected ─────────────────────────────────

await test('5. Tampered ciphertext rejected (bit flip)', async () => {
  const payload = await encryptPayload({ type: 'text', data: 'secret' }, 'password', null, FAST);

  // Positive control.
  const ok = await decryptPayload(payload, 'password', null);
  assert.equal(ok.data, 'secret');

  // Negative: flip a bit near the end of the ciphertext.
  const tampered = new Uint8Array(payload);
  tampered[tampered.length - 5] ^= 0x01;
  const err = await decryptPayload(tampered, 'password', null).then(() => null, e => e);
  assert.ok(err instanceof PalimpsestError);
  assert.equal(err.code, ErrorCodes.DECRYPTION_FAILED);
  assert.match(err.message, /could not be decrypted/);
});

// ─── Test 6: tampered carrier rejected ───────────────────────────────────────
// Header (v2, no keyfile, no PRF) = 84 B. Stego stream byte 100 → payload
// byte 96 → ciphertext byte 12 (96 − 84). Extraction still succeeds; AES-GCM
// rejects the corrupted ciphertext and decryptPayload throws DECRYPTION_FAILED.

await test('6. Tampered carrier rejected', async () => {
  const original = 'tamper-test-message';
  const payload  = await encryptPayload({ type: 'text', data: original }, 'pw', null, FAST);
  const carrier  = await makePng(200, 200);
  const stego    = await embedInPng(carrier, payload);

  // Positive control: untampered stego round-trips.
  const ok = await decryptPayload(await extractFromPng(stego), 'pw', null);
  assert.equal(ok.data, original);

  // Negative: flip a bit in the ciphertext region (stream byte 100).
  const tampered = await tamperStegoStream(stego, 100);
  const err = await decryptPayload(await extractFromPng(tampered), 'pw', null).then(() => null, e => e);
  assert.ok(err instanceof PalimpsestError);
  assert.equal(err.code, ErrorCodes.DECRYPTION_FAILED);
});

// ─── Test 7: capacity overflow caught before any work ────────────────────────

await test('7. Capacity overflow caught before any work begins', async () => {
  const payload     = await encryptPayload({ type: 'text', data: 'hi' }, 'pw', null, FAST);
  const bigCarrier  = await makePng(200, 200);
  const smallCarrier = await makePng(5, 5);

  // Positive control: large carrier accepts the payload.
  const result = await decryptPayload(await extractFromPng(await embedInPng(bigCarrier, payload)), 'pw', null);
  assert.equal(result.data, 'hi');

  // Negative: 5×5 carrier overflows; error must name both sizes.
  const err = await embedInPng(smallCarrier, payload).then(() => null, e => e);
  assert.ok(err instanceof StegoError);
  assert.equal(err.code, StegoCodes.CAPACITY_EXCEEDED);
  assert.match(err.message, /need \d+ B/);
  assert.match(err.message, /capacity is \d+ B/);
});

// ─── Test 8: large payload near carrier capacity round-trips ─────────────────

await test('8. Large payload near capacity round-trips correctly', async () => {
  const original = 'near-capacity-message';
  const payload  = await encryptPayload({ type: 'text', data: original }, 'pw', null, FAST);
  const required = 4 + payload.length; // 4 = stego length-prefix bytes
  const minPx    = Math.ceil(required * 8 / 3);
  const carrier  = await makePng(minPx, 1);

  const result = await decryptPayload(await extractFromPng(await embedInPng(carrier, payload)), 'pw', null);
  assert.equal(result.data, original);
});

// ─── Test 9: carrier with no payload takes the "not found" path ──────────────

await test('9. Carrier with no payload: "not found" path, no crash', async () => {
  const original = 'positive-control';
  const payload  = await encryptPayload({ type: 'text', data: original }, 'pw', null, FAST);
  const carrier  = await makePng(200, 200);

  // Positive control.
  const result = await decryptPayload(await extractFromPng(await embedInPng(carrier, payload)), 'pw', null);
  assert.equal(result.data, original);

  // Negative: fresh carrier has no payload → NO_PAYLOAD_FOUND.
  const err = await extractFromPng(await makePng(200, 200)).then(() => null, e => e);
  assert.ok(err instanceof StegoError);
  assert.equal(err.code, StegoCodes.NO_PAYLOAD_FOUND);
  assert.match(err.message, /No payload found/);
});

// ─── Test 10: WebAuthn PRF callback round-trip (stubbed) ─────────────────────
// getPrfResult (encrypt): (prfSalt) => { credId, prfSecret }
// getPrfSecret (decrypt): (credId, prfSalt) => prfSecret
// The stub ignores the salt and returns a fixed secret; a real implementation
// would drive navigator.credentials.create/get with the PRF extension.

await test('10. WebAuthn PRF callback: round-trip and rejection', async () => {
  const prfSecretValue = crypto.getRandomValues(new Uint8Array(32));
  const wrongSecret    = crypto.getRandomValues(new Uint8Array(32));
  const mockCredId     = crypto.getRandomValues(new Uint8Array(32));

  const correctPrfResult = async (_prfSalt) => ({ credId: mockCredId, prfSecret: prfSecretValue });
  const correctPrfSecret = async (_credId, _prfSalt) => prfSecretValue;
  const wrongPrfSecret   = async (_credId, _prfSalt) => wrongSecret;

  const payload = await encryptPayload(
    { type: 'text', data: 'hardware-key-protected' },
    'password', { getPrfResult: correctPrfResult }, FAST,
  );

  // FLAGS_PRF must be set.
  assert.ok(readFlags(payload) & FLAGS_PRF, 'FLAGS_PRF not set in header');

  // Positive: same PRF secret → decrypts.
  const result = await decryptPayload(payload, 'password', { getPrfSecret: correctPrfSecret });
  assert.equal(result.data, 'hardware-key-protected');

  // Negative: no PRF callback → PRF_REQUIRED (not DECRYPTION_FAILED).
  const err1 = await decryptPayload(payload, 'password', null).then(() => null, e => e);
  assert.ok(err1 instanceof PalimpsestError);
  assert.equal(err1.code, ErrorCodes.PRF_REQUIRED);

  // Negative: wrong PRF secret → DECRYPTION_FAILED.
  const err2 = await decryptPayload(payload, 'password', { getPrfSecret: wrongPrfSecret }).then(() => null, e => e);
  assert.ok(err2 instanceof PalimpsestError);
  assert.equal(err2.code, ErrorCodes.DECRYPTION_FAILED);
});

// ─── Test 11: production Argon2 parameters — single round-trip ───────────────
// Expected runtime: 5–15 s.

await test('11. Production Argon2 parameters round-trip (m=64 MB, t=3, p=1)', async () => {
  const result = await encryptPayload(
    { type: 'text', data: 'production-params-test' }, 'password', null, ARGON2_DEFAULTS,
  ).then(payload => decryptPayload(payload, 'password', null));
  assert.equal(result.data, 'production-params-test');
});

// ─── Test 12: keyfile round-trip ─────────────────────────────────────────────
// Encrypting with a keyfile and decrypting with the same keyfile must succeed.
// FLAGS_KEYFILE must be set in the header.

await test('12. Keyfile round-trip (password + keyfile)', async () => {
  const keyfile = crypto.getRandomValues(new Uint8Array(32));
  const payload = await encryptPayload(
    { type: 'text', data: 'keyfile-protected' }, 'password', { keyfileBytes: keyfile }, FAST,
  );

  // Flags check.
  assert.ok(readFlags(payload) & FLAGS_KEYFILE, 'FLAGS_KEYFILE not set in header');
  assert.ok(!(readFlags(payload) & FLAGS_PRF),   'FLAGS_PRF should not be set');

  // Positive: correct keyfile decrypts.
  const result = await decryptPayload(payload, 'password', { keyfileBytes: keyfile });
  assert.equal(result.type, 'text');
  assert.equal(result.data, 'keyfile-protected');
});

// ─── Test 13: wrong keyfile is rejected ──────────────────────────────────────

await test('13. Wrong keyfile rejected', async () => {
  const correctKeyfile = crypto.getRandomValues(new Uint8Array(32));
  const wrongKeyfile   = crypto.getRandomValues(new Uint8Array(32));
  const payload = await encryptPayload(
    { type: 'text', data: 'secret' }, 'password', { keyfileBytes: correctKeyfile }, FAST,
  );

  // Positive control: correct keyfile decrypts.
  const ok = await decryptPayload(payload, 'password', { keyfileBytes: correctKeyfile });
  assert.equal(ok.data, 'secret');

  // Negative: wrong keyfile → DECRYPTION_FAILED.
  const err = await decryptPayload(payload, 'password', { keyfileBytes: wrongKeyfile }).then(() => null, e => e);
  assert.ok(err instanceof PalimpsestError);
  assert.equal(err.code, ErrorCodes.DECRYPTION_FAILED);
  assert.match(err.message, /could not be decrypted/);
});

// ─── Test 14: KEYFILE_REQUIRED when flag set but no keyfile provided ──────────
// Omitting the keyfile on decrypt must give KEYFILE_REQUIRED, not the generic
// DECRYPTION_FAILED. This lets the UI prompt for the keyfile specifically.

await test('14. KEYFILE_REQUIRED when keyfile omitted on decrypt', async () => {
  const keyfile = crypto.getRandomValues(new Uint8Array(32));
  const payload = await encryptPayload(
    { type: 'text', data: 'x' }, 'pw', { keyfileBytes: keyfile }, FAST,
  );

  // Positive control: with keyfile → decrypts.
  const ok = await decryptPayload(payload, 'pw', { keyfileBytes: keyfile });
  assert.equal(ok.data, 'x');

  // Negative: no keyfile → KEYFILE_REQUIRED (not DECRYPTION_FAILED).
  const err = await decryptPayload(payload, 'pw', null).then(() => null, e => e);
  assert.ok(err instanceof PalimpsestError);
  assert.equal(err.code, ErrorCodes.KEYFILE_REQUIRED);
});

// ─── Test 15: keyfile on decrypt when none was used during encrypt ────────────
// Supplying a keyfile when the original payload was password-only changes the
// key material, causing AES-GCM tag verification to fail.

await test('15. Unexpected keyfile on decrypt → DECRYPTION_FAILED', async () => {
  const keyfile = crypto.getRandomValues(new Uint8Array(32));
  const payload = await encryptPayload(
    { type: 'text', data: 'no-keyfile-encrypted' }, 'pw', null, FAST,
  );

  // Positive control: no keyfile → decrypts.
  const ok = await decryptPayload(payload, 'pw', null);
  assert.equal(ok.data, 'no-keyfile-encrypted');

  // Negative: supplying an unrequested keyfile → DECRYPTION_FAILED.
  const err = await decryptPayload(payload, 'pw', { keyfileBytes: keyfile }).then(() => null, e => e);
  assert.ok(err instanceof PalimpsestError);
  assert.equal(err.code, ErrorCodes.DECRYPTION_FAILED);
});

// ─── Test 16: keyfile + password + PRF combined ───────────────────────────────
// All three factors together must round-trip. Removing any one factor must fail.

await test('16. Keyfile + password + PRF (all three factors)', async () => {
  const keyfile        = crypto.getRandomValues(new Uint8Array(32));
  const prfSecretValue = crypto.getRandomValues(new Uint8Array(32));
  const mockCredId     = crypto.getRandomValues(new Uint8Array(16));

  const getPrfResult  = async (_s) => ({ credId: mockCredId, prfSecret: prfSecretValue });
  const getPrfSecret  = async (_id, _s) => prfSecretValue;
  const wrongPrf      = async (_id, _s) => crypto.getRandomValues(new Uint8Array(32));

  const payload = await encryptPayload(
    { type: 'text', data: 'three-factor' },
    'password',
    { keyfileBytes: keyfile, getPrfResult },
    FAST,
  );

  // Both flags set.
  assert.ok(readFlags(payload) & FLAGS_KEYFILE);
  assert.ok(readFlags(payload) & FLAGS_PRF);

  // Positive: all three factors → decrypts.
  const result = await decryptPayload(payload, 'password', { keyfileBytes: keyfile, getPrfSecret });
  assert.equal(result.data, 'three-factor');

  // Missing keyfile → KEYFILE_REQUIRED.
  const e1 = await decryptPayload(payload, 'password', { getPrfSecret }).then(() => null, e => e);
  assert.equal(e1.code, ErrorCodes.KEYFILE_REQUIRED);

  // Missing PRF → PRF_REQUIRED.
  const e2 = await decryptPayload(payload, 'password', { keyfileBytes: keyfile }).then(() => null, e => e);
  assert.equal(e2.code, ErrorCodes.PRF_REQUIRED);

  // Wrong PRF → DECRYPTION_FAILED.
  const e3 = await decryptPayload(payload, 'password', { keyfileBytes: keyfile, getPrfSecret: wrongPrf }).then(() => null, e => e);
  assert.equal(e3.code, ErrorCodes.DECRYPTION_FAILED);
});

// ─── Summary ─────────────────────────────────────────────────────────────────

const total = passed + failed;
console.log('');
console.log(`Results: ${passed} passed, ${failed} failed  (${total} total)`);
console.log('');
if (failed > 0) process.exit(1);
