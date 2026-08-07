// Palimpsest crypto core
// Key derivation: Argon2id via hash-wasm (WASM, no native bindings).
// Symmetric crypto: AES-256-GCM via WebCrypto.
// Runs in Node.js 18+ (tests) and modern browsers (HTML client).

import { argon2id } from 'hash-wasm';

// ─── Constants ────────────────────────────────────────────────────────────────

export const MAGIC          = new Uint8Array([0x50, 0x4c, 0x4d, 0x50]); // "PLMP"
export const VERSION        = 1;
export const KDF_ARGON2ID   = 0x02;
export const CONTENT_TEXT   = 0x00;
export const CONTENT_FILE   = 0x01;

export const MAX_PLAINTEXT_BYTES = 25 * 1024 * 1024; // 25 MB global ceiling

// Benchmark target: ~1 s on a mid-range phone. Tune m/t before locking in.
export const ARGON2_DEFAULTS = { m: 65536, t: 3, p: 1 }; // m in KiB

// Safe ranges for attacker-controlled header fields (fix 2).
const ARGON2_LIMITS = {
  m: { min: 8192,  max: 262144 }, // 8 MB – 256 MB in KiB
  t: { min: 1,     max: 10     },
  p: { min: 1,     max: 4      },
};

const ARMOR_HEADER = '-----BEGIN PALIMPSEST MESSAGE-----';
const ARMOR_FOOTER = '-----END PALIMPSEST MESSAGE-----';

// ─── Buffer helpers ───────────────────────────────────────────────────────────

function concat(...arrays) {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function u16be(n) { return new Uint8Array([(n >> 8) & 0xff, n & 0xff]); }
function u32be(n) { return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]); }
function readU16(b, o) { return (b[o] << 8) | b[o + 1]; }
function readU32(b, o) { return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0; }

// ─── Compression ─────────────────────────────────────────────────────────────

async function compress(data) {
  if (typeof CompressionStream !== 'undefined') {
    const cs = new CompressionStream('deflate-raw');
    const writer = cs.writable.getWriter();
    writer.write(data);
    writer.close();
    return new Uint8Array(await new Response(cs.readable).arrayBuffer());
  }
  const { deflateRaw } = await import('node:zlib');
  const { promisify }  = await import('node:util');
  return new Uint8Array(await promisify(deflateRaw)(data));
}

async function decompress(data) {
  if (typeof DecompressionStream !== 'undefined') {
    const ds = new DecompressionStream('deflate-raw');
    const writer = ds.writable.getWriter();
    writer.write(data);
    writer.close();
    return new Uint8Array(await new Response(ds.readable).arrayBuffer());
  }
  const { inflateRaw } = await import('node:zlib');
  const { promisify }  = await import('node:util');
  return new Uint8Array(await promisify(inflateRaw)(data));
}

// ─── Key derivation ───────────────────────────────────────────────────────────

function buildKeyMaterial(password, pepper, prfSecret) {
  const enc = new TextEncoder();
  const parts = [enc.encode(password), enc.encode(pepper)];
  if (prfSecret) parts.push(prfSecret instanceof Uint8Array ? prfSecret : new Uint8Array(prfSecret));
  return concat(...parts);
}

async function deriveKey(keyMaterial, salt, params) {
  const raw = await argon2id({
    password:    keyMaterial,
    salt,
    memorySize:  params.m,
    iterations:  params.t,
    parallelism: params.p,
    hashLength:  32,
    outputType:  'binary',
  });
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

// ─── KDF params blob ─────────────────────────────────────────────────────────
// [KDF_ID(1)] [m(4)] [t(4)] [p(1)] = 10 bytes for Argon2id

function encodeKdfParams(p) {
  return concat(new Uint8Array([KDF_ARGON2ID]), u32be(p.m), u32be(p.t), new Uint8Array([p.p]));
}

// FIX 2 — validate before use. The kdfParams header is unencrypted and
// attacker-controlled; an m of 4 GB would hang or kill the tab. All out-of-range
// values produce the same generic error to avoid revealing which field was bad.
function decodeKdfParams(blob) {
  if (blob[0] !== KDF_ARGON2ID) throw new Error('unknown KDF');
  const m = readU32(blob, 1);
  const t = readU32(blob, 5);
  const p = blob[9];
  const L = ARGON2_LIMITS;
  if (m < L.m.min || m > L.m.max) throw new Error('kdf param out of range');
  if (t < L.t.min || t > L.t.max) throw new Error('kdf param out of range');
  if (p < L.p.min || p > L.p.max) throw new Error('kdf param out of range');
  return { m, t, p };
}

// ─── Content header (inside the encrypted region) ────────────────────────────
// FIX 4 — add compressed flag byte so decoding does not unconditionally call
// decompress. Always 0x01 in v1; reserved so future callers (tier-2 carriers
// whose files are already compressed) can set 0x00 without a format change.
//
// Layout: [type(1)] [compressed(1)] [nameLen(2)] [name] [mimeLen(2)] [mime] [content...]

function encodeContent(typeFlag, name, mime, content, compressed) {
  const enc = new TextEncoder();
  const nameB = enc.encode(name || '');
  const mimeB = enc.encode(mime || '');
  return concat(
    new Uint8Array([typeFlag, compressed ? 0x01 : 0x00]),
    u16be(nameB.length), nameB,
    u16be(mimeB.length), mimeB,
    content,
  );
}

function decodeContent(buf) {
  const dec = new TextDecoder();
  let o = 0;
  const typeFlag   = buf[o++];
  const compressed = buf[o++] === 0x01;
  const nameLen    = readU16(buf, o); o += 2;
  const name       = dec.decode(buf.slice(o, o + nameLen)); o += nameLen;
  const mimeLen    = readU16(buf, o); o += 2;
  const mime       = dec.decode(buf.slice(o, o + mimeLen)); o += mimeLen;
  return { typeFlag, compressed, name, mime, content: buf.slice(o) };
}

// ─── Payload format ───────────────────────────────────────────────────────────
// Outer header (unencrypted, but authenticated — see FIX 3):
//   [magic(4)] [version(1)] [kdfParamsLen(2)] [kdfParams(N)]
//   [salt(16)] [prfSalt(32)] [iv(12)] [ciphertextLen(4)]
// Followed by:
//   [ciphertext(N)]  AES-256-GCM over compressed content header + content
//
// getPrfSecret signature: async (prfSalt: Uint8Array) => Uint8Array
//   FIX 1 — the hardware key derives its secret FROM the prfSalt stored in the
//   header. The caller cannot know that salt before the header is parsed, so this
//   must be a callback rather than a pre-computed value. Pass null for no key.

export async function encryptPayload(payload, password, pepper, getPrfSecret = null, kdfParams = ARGON2_DEFAULTS) {
  const enc = new TextEncoder();
  const rawData = typeof payload.data === 'string' ? enc.encode(payload.data) : payload.data;

  if (rawData.length > MAX_PLAINTEXT_BYTES) {
    throw new Error(`Payload too large: ${rawData.length} bytes exceeds the ${MAX_PLAINTEXT_BYTES / 1024 / 1024} MB limit`);
  }

  const typeFlag       = payload.type === 'text' ? CONTENT_TEXT : CONTENT_FILE;
  const compressedData = await compress(rawData);
  // Compression applied to content only; flag is always 0x01 in v1.
  const innerContent   = encodeContent(typeFlag, payload.name || '', payload.mime || '', compressedData, true);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));

  // FIX 1 — generate prfSalt FIRST, then pass it to the hardware key callback.
  // The key derives its secret from this salt; storing a different salt in the
  // header would make decryption derive a different key.
  let prfSalt, prfSecret;
  if (getPrfSecret) {
    prfSalt   = crypto.getRandomValues(new Uint8Array(32));
    prfSecret = await getPrfSecret(prfSalt);
  } else {
    prfSalt   = new Uint8Array(32); // zeroed sentinel
    prfSecret = null;
  }

  const kdfBlob       = encodeKdfParams(kdfParams);
  // AES-GCM always appends a 16-byte auth tag; length is deterministic pre-encrypt.
  const ciphertextLen = innerContent.length + 16;

  // FIX 3 — pass the full outer header as AES-GCM additionalData, binding the
  // ciphertext to its header. Any modification to magic, version, kdfParams, salt,
  // prfSalt, or iv causes the auth tag check to fail during decryption.
  const aad = concat(
    MAGIC,
    new Uint8Array([VERSION]),
    u16be(kdfBlob.length),
    kdfBlob,
    salt,
    prfSalt,
    iv,
    u32be(ciphertextLen),
  );

  const keyMat = buildKeyMaterial(password, pepper, prfSecret);
  const key    = await deriveKey(keyMat, salt, kdfParams);

  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    innerContent,
  ));

  // Payload = aad || ciphertext. During decryption buf.slice(0, headerEnd) === aad.
  return concat(aad, ciphertext);
}

export async function decryptPayload(payloadBytes, password, pepper, getPrfSecret = null) {
  const buf = payloadBytes instanceof Uint8Array ? payloadBytes : new Uint8Array(payloadBytes);
  let o = 0;

  // Check magic before the broad try/catch so the two distinct error messages
  // ("not found" vs "found but failed") remain separate without leaking detail.
  const magic = String.fromCharCode(...buf.slice(o, o + 4)); o += 4;
  if (magic !== 'PLMP') throw new Error('No payload found in this carrier');

  let plain;
  try {
    const version = buf[o++];
    if (version !== VERSION) throw new Error('unsupported version');

    const kdfParamsLen = readU16(buf, o); o += 2;
    const kdfBlob      = buf.slice(o, o + kdfParamsLen); o += kdfParamsLen;
    const kdfParams    = decodeKdfParams(kdfBlob); // FIX 2: validates ranges here

    const salt    = buf.slice(o, o + 16); o += 16;
    const prfSalt = buf.slice(o, o + 32); o += 32; // FIX 1: read, not skip
    const iv      = buf.slice(o, o + 12); o += 12;
    const ctLen   = readU32(buf, o);      o += 4;

    // FIX 3 — buf.slice(0, o) is exactly the aad written during encryption.
    const aad = buf.slice(0, o);
    const ct  = buf.slice(o, o + ctLen);

    // FIX 1 — pass the stored prfSalt to the callback so the hardware key can
    // reproduce the same secret it derived during encryption.
    const prfSecret = getPrfSecret ? await getPrfSecret(prfSalt) : null;
    const keyMat    = buildKeyMaterial(password, pepper, prfSecret);
    const key       = await deriveKey(keyMat, salt, kdfParams);

    plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad }, // FIX 3
      key,
      ct,
    ));
  } catch {
    // Wrong password, wrong pepper, tampered header, tampered ciphertext — all
    // produce the same message. Distinguishing them would help an attacker.
    throw new Error('Payload found but could not be decrypted');
  }

  // decodeContent and decompress are outside the try/catch: a failure here is a
  // programming bug (decryption succeeded but content is malformed), not user error.
  const { typeFlag, compressed, name, mime, content } = decodeContent(plain);
  const rawContent = compressed ? await decompress(content) : content; // FIX 4
  const dec = new TextDecoder();

  return {
    type: typeFlag === CONTENT_TEXT ? 'text' : 'file',
    name,
    mime,
    data: typeFlag === CONTENT_TEXT ? dec.decode(rawContent) : rawContent,
  };
}

// ─── Armored text format ──────────────────────────────────────────────────────

function uint8ToBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function base64ToUint8(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function armorPayload(bytes) {
  const b64 = uint8ToBase64(bytes);
  const lines = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return `${ARMOR_HEADER}\nVersion: ${VERSION}\n\n${lines.join('\n')}\n${ARMOR_FOOTER}`;
}

// Returns null if no armor block is found (caller decides whether that is an error).
export function unarmorPayload(text) {
  const s = text.trim();
  const hi = s.indexOf(ARMOR_HEADER);
  const fi = s.indexOf(ARMOR_FOOTER);
  if (hi === -1 || fi === -1) return null;

  const blankLine = s.indexOf('\n\n', hi);
  if (blankLine === -1) return null;

  const b64 = s.slice(blankLine + 2, fi).trim().replace(/\s+/g, '');
  return base64ToUint8(b64);
}
