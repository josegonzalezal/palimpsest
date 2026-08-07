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
// Compress before encrypting, never after.

async function compress(data) {
  if (typeof CompressionStream !== 'undefined') {
    const cs = new CompressionStream('deflate-raw');
    const writer = cs.writable.getWriter();
    writer.write(data);
    writer.close();
    return new Uint8Array(await new Response(cs.readable).arrayBuffer());
  }
  const { deflateRaw } = await import('node:zlib');
  const { promisify } = await import('node:util');
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
  const { promisify } = await import('node:util');
  return new Uint8Array(await promisify(inflateRaw)(data));
}

// ─── Key derivation ───────────────────────────────────────────────────────────

// Concatenate password || pepper || prfSecret (when present) as the Argon2 password.
// The payload salt is fresh per encrypt; the PRF salt lives in the header.
function buildKeyMaterial(password, pepper, prfSecret) {
  const enc = new TextEncoder();
  const parts = [enc.encode(password), enc.encode(pepper)];
  if (prfSecret) parts.push(prfSecret instanceof Uint8Array ? prfSecret : new Uint8Array(prfSecret));
  return concat(...parts);
}

async function deriveKey(keyMaterial, salt, params) {
  const raw = await argon2id({
    password: keyMaterial,
    salt,
    memorySize:   params.m,
    iterations:   params.t,
    parallelism:  params.p,
    hashLength:   32,
    outputType:   'binary',
  });
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

// ─── KDF params blob ─────────────────────────────────────────────────────────
// Layout: [KDF_ID(1)] [m(4)] [t(4)] [p(1)] = 10 bytes for Argon2id

function encodeKdfParams(p) {
  return concat(new Uint8Array([KDF_ARGON2ID]), u32be(p.m), u32be(p.t), new Uint8Array([p.p]));
}

function decodeKdfParams(blob) {
  if (blob[0] !== KDF_ARGON2ID) throw new Error(`Unknown KDF ID 0x${blob[0].toString(16)}`);
  return { m: readU32(blob, 1), t: readU32(blob, 5), p: blob[9] };
}

// ─── Content header (inside the encrypted region) ────────────────────────────
// [type(1)] [nameLen(2)] [name] [mimeLen(2)] [mime] [content...]

function encodeContent(typeFlag, name, mime, data) {
  const enc = new TextEncoder();
  const nameB = enc.encode(name || '');
  const mimeB = enc.encode(mime || '');
  return concat(new Uint8Array([typeFlag]), u16be(nameB.length), nameB, u16be(mimeB.length), mimeB, data);
}

function decodeContent(buf) {
  const dec = new TextDecoder();
  let o = 0;
  const typeFlag = buf[o++];
  const nameLen = readU16(buf, o); o += 2;
  const name = dec.decode(buf.slice(o, o + nameLen)); o += nameLen;
  const mimeLen = readU16(buf, o); o += 2;
  const mime = dec.decode(buf.slice(o, o + mimeLen)); o += mimeLen;
  return { typeFlag, name, mime, content: buf.slice(o) };
}

// ─── Payload format ───────────────────────────────────────────────────────────
// Outer header (all fields unencrypted):
//   [magic(4)] [version(1)] [kdfParamsLen(2)] [kdfParams(N)]
//   [salt(16)] [prfSalt(32)] [iv(12)] [ciphertextLen(4)] [ciphertext(N)]

export async function encryptPayload(payload, password, pepper, prfSecret = null, kdfParams = ARGON2_DEFAULTS) {
  // payload: { type: 'text'|'file', name?, mime?, data: string|Uint8Array }
  const enc = new TextEncoder();
  const rawData = typeof payload.data === 'string' ? enc.encode(payload.data) : payload.data;

  if (rawData.length > MAX_PLAINTEXT_BYTES) {
    throw new Error(`Payload too large: ${rawData.length} bytes exceeds the ${MAX_PLAINTEXT_BYTES / 1024 / 1024} MB limit`);
  }

  const typeFlag = payload.type === 'text' ? CONTENT_TEXT : CONTENT_FILE;
  const innerPlain = encodeContent(typeFlag, payload.name || '', payload.mime || '', rawData);
  const compressed = await compress(innerPlain);

  const salt    = crypto.getRandomValues(new Uint8Array(16));
  const iv      = crypto.getRandomValues(new Uint8Array(12));
  // prfSalt is zeroed when no hardware key is used; stored so the decoder can reconstruct the key.
  const prfSalt = prfSecret ? crypto.getRandomValues(new Uint8Array(32)) : new Uint8Array(32);

  const keyMat = buildKeyMaterial(password, pepper, prfSecret);
  const key = await deriveKey(keyMat, salt, kdfParams);

  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, compressed));

  const kdfBlob = encodeKdfParams(kdfParams);
  return concat(
    MAGIC,
    new Uint8Array([VERSION]),
    u16be(kdfBlob.length),
    kdfBlob,
    salt,
    prfSalt,
    iv,
    u32be(ciphertext.length),
    ciphertext,
  );
}

export async function decryptPayload(payloadBytes, password, pepper, prfSecret = null) {
  const buf = payloadBytes instanceof Uint8Array ? payloadBytes : new Uint8Array(payloadBytes);
  let o = 0;

  // Magic check — not found is a distinct, non-leaking error.
  const magic = String.fromCharCode(...buf.slice(o, o + 4)); o += 4;
  if (magic !== 'PLMP') throw new Error('No payload found in this carrier');

  const version = buf[o++];
  if (version !== VERSION) throw new Error(`Unsupported payload version: ${version}`);

  const kdfParamsLen = readU16(buf, o); o += 2;
  const kdfBlob = buf.slice(o, o + kdfParamsLen); o += kdfParamsLen;
  const kdfParams = decodeKdfParams(kdfBlob);

  const salt    = buf.slice(o, o + 16); o += 16;
  /* prfSalt */ o += 32; // stored in header but passed via caller-supplied prfSecret
  const iv      = buf.slice(o, o + 12); o += 12;
  const ctLen   = readU32(buf, o); o += 4;
  const ct      = buf.slice(o, o + ctLen);

  const keyMat = buildKeyMaterial(password, pepper, prfSecret);
  const key = await deriveKey(keyMat, salt, kdfParams);

  let compressed;
  try {
    compressed = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
  } catch {
    // Do not distinguish wrong password, wrong pepper, or tampering — that leaks info.
    throw new Error('Payload found but could not be decrypted');
  }

  const plain = await decompress(compressed);
  const { typeFlag, name, mime, content } = decodeContent(plain);
  const dec = new TextDecoder();

  return {
    type: typeFlag === CONTENT_TEXT ? 'text' : 'file',
    name,
    mime,
    data: typeFlag === CONTENT_TEXT ? dec.decode(content) : content,
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
