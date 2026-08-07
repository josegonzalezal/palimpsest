// Palimpsest crypto core
// Key derivation: Argon2id via hash-wasm (WASM, no native bindings).
// Symmetric crypto: AES-256-GCM via WebCrypto.
// Runs in Node.js 18+ (tests) and modern browsers (HTML client).

import { argon2id } from 'hash-wasm';

// ─── Error codes ─────────────────────────────────────────────────────────────

export const ErrorCodes = {
  NO_PAYLOAD_FOUND:  'NO_PAYLOAD_FOUND',
  DECRYPTION_FAILED: 'DECRYPTION_FAILED',
  PAYLOAD_TOO_LARGE: 'PAYLOAD_TOO_LARGE',
  // Thrown before attempting decryption when the header flag is set but the
  // caller did not supply the required factor. Separate from DECRYPTION_FAILED
  // so the UI can prompt for the missing item rather than showing a generic error.
  KEYFILE_REQUIRED:  'KEYFILE_REQUIRED',
  PRF_REQUIRED:      'PRF_REQUIRED',
};

export class PalimpsestError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PalimpsestError';
    this.code = code;
  }
}

// ─── Constants ────────────────────────────────────────────────────────────────

export const MAGIC          = new Uint8Array([0x50, 0x4c, 0x4d, 0x50]); // "PLMP"
export const VERSION        = 2;
export const KDF_ARGON2ID   = 0x02;
export const CONTENT_TEXT   = 0x00;
export const CONTENT_FILE   = 0x01;

// Header flag bits (stored in the flags byte; authenticated as part of AAD).
export const FLAGS_KEYFILE  = 0x01; // 32-byte keyfile was mixed into key material
export const FLAGS_PRF      = 0x02; // WebAuthn PRF secret was mixed into key material

export const MAX_PLAINTEXT_BYTES = 25 * 1024 * 1024; // 25 MB ceiling

export const ARGON2_DEFAULTS = { m: 65536, t: 3, p: 1 }; // m in KiB (64 MB)

const ARGON2_LIMITS = {
  m: { min: 8192,  max: 262144 },
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
// Key material = password ‖ keyfileBytes ‖ prfSecret (each part is optional
// after the password). Concatenation is domain-separated by position and fixed
// sizes: keyfileBytes is always exactly 32 bytes, prfSecret is always exactly
// 32 bytes. Leaving either out changes the length and therefore the key.

function buildKeyMaterial(password, keyfileBytes, prfSecret) {
  const enc = new TextEncoder();
  const parts = [enc.encode(password)];
  if (keyfileBytes) parts.push(keyfileBytes instanceof Uint8Array ? keyfileBytes : new Uint8Array(keyfileBytes));
  if (prfSecret)    parts.push(prfSecret    instanceof Uint8Array ? prfSecret    : new Uint8Array(prfSecret));
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

// ─── Payload format (version 2) ───────────────────────────────────────────────
//
// Outer header (unencrypted, but fully authenticated as AES-GCM AAD):
//   magic(4) version(1) flags(1) kdfParamsLen(2) kdfParams(N)
//   salt(16) prfSalt(32) credIdLen(2) credId(M) iv(12) ciphertextLen(4)
//
// flags bits:
//   FLAGS_KEYFILE (0x01) — keyfileBytes was mixed into key material
//   FLAGS_PRF     (0x02) — WebAuthn PRF secret was mixed into key material
//
// prfSalt: 32 bytes, zeroed when FLAGS_PRF is not set.
// credId:  M bytes (M = credIdLen), zero-length when FLAGS_PRF is not set.
//          Identifies the WebAuthn credential for the PRF round-trip.
//
// Followed by: ciphertext (AES-256-GCM over the compressed content header)
//
// encryptPayload options:
//   keyfileBytes?  Uint8Array — exactly 32 bytes; sets FLAGS_KEYFILE
//   getPrfResult?  async (prfSalt: Uint8Array) => { credId: Uint8Array, prfSecret: Uint8Array }
//                  Called once during encrypt to create/use a WebAuthn credential;
//                  both the credential ID and PRF output are returned together.
//
// decryptPayload options:
//   keyfileBytes?  Uint8Array — must match what was used during encryption
//   getPrfSecret?  async (credId: Uint8Array, prfSalt: Uint8Array) => Uint8Array
//                  Called during decrypt; credId comes from the header.

export async function encryptPayload(payload, password, options, kdfParams = ARGON2_DEFAULTS) {
  const { keyfileBytes = null, getPrfResult = null } = options ?? {};
  const enc = new TextEncoder();
  const rawData = typeof payload.data === 'string' ? enc.encode(payload.data) : payload.data;

  if (rawData.length > MAX_PLAINTEXT_BYTES) {
    throw new PalimpsestError(
      ErrorCodes.PAYLOAD_TOO_LARGE,
      `Payload too large: ${rawData.length} bytes exceeds the ${MAX_PLAINTEXT_BYTES / 1024 / 1024} MB limit`,
    );
  }

  const typeFlag       = payload.type === 'text' ? CONTENT_TEXT : CONTENT_FILE;
  const compressedData = await compress(rawData);
  const innerContent   = encodeContent(typeFlag, payload.name || '', payload.mime || '', compressedData, true);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));

  let prfSalt, prfSecret, credId;
  if (getPrfResult) {
    prfSalt = crypto.getRandomValues(new Uint8Array(32));
    const result = await getPrfResult(prfSalt);
    prfSecret = result.prfSecret;
    credId    = result.credId instanceof Uint8Array ? result.credId : new Uint8Array(result.credId);
  } else {
    prfSalt   = new Uint8Array(32); // zeroed sentinel
    prfSecret = null;
    credId    = new Uint8Array(0);
  }

  const flags = (keyfileBytes ? FLAGS_KEYFILE : 0) | (getPrfResult ? FLAGS_PRF : 0);
  const kdfBlob = encodeKdfParams(kdfParams);
  const ciphertextLen = innerContent.length + 16;

  const aad = concat(
    MAGIC,
    new Uint8Array([VERSION, flags]),
    u16be(kdfBlob.length),
    kdfBlob,
    salt,
    prfSalt,
    u16be(credId.length),
    credId,
    iv,
    u32be(ciphertextLen),
  );

  const keyMat = buildKeyMaterial(password, keyfileBytes, prfSecret);
  const key    = await deriveKey(keyMat, salt, kdfParams);

  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    innerContent,
  ));

  return concat(aad, ciphertext);
}

export async function decryptPayload(payloadBytes, password, options) {
  const buf = payloadBytes instanceof Uint8Array ? payloadBytes : new Uint8Array(payloadBytes);
  let o = 0;

  const magic = String.fromCharCode(...buf.slice(o, o + 4)); o += 4;
  if (magic !== 'PLMP') {
    throw new PalimpsestError(ErrorCodes.NO_PAYLOAD_FOUND, 'No payload found in this carrier');
  }

  let plain;
  try {
    const version = buf[o++];
    if (version !== VERSION) throw new Error(`unsupported version ${version}`);

    const flags = buf[o++];

    const kdfParamsLen = readU16(buf, o); o += 2;
    const kdfBlob      = buf.slice(o, o + kdfParamsLen); o += kdfParamsLen;
    const kdfParams    = decodeKdfParams(kdfBlob);

    const salt    = buf.slice(o, o + 16); o += 16;
    const prfSalt = buf.slice(o, o + 32); o += 32;

    const credIdLen = readU16(buf, o); o += 2;
    const credId    = buf.slice(o, o + credIdLen); o += credIdLen;

    const iv    = buf.slice(o, o + 12); o += 12;
    const ctLen = readU32(buf, o);      o += 4;

    const aad = buf.slice(0, o);
    const ct  = buf.slice(o, o + ctLen);

    const { keyfileBytes = null, getPrfSecret = null } = options ?? {};

    // Check required factors BEFORE the expensive key derivation.
    // This gives the caller a specific code to act on rather than a generic failure.
    if ((flags & FLAGS_KEYFILE) && !keyfileBytes) {
      throw new PalimpsestError(ErrorCodes.KEYFILE_REQUIRED, 'This payload was encrypted with a keyfile — please load it');
    }
    if ((flags & FLAGS_PRF) && !getPrfSecret) {
      throw new PalimpsestError(ErrorCodes.PRF_REQUIRED, 'This payload was encrypted with a hardware security key');
    }

    const prfSecret = getPrfSecret ? await getPrfSecret(credId, prfSalt) : null;
    const keyMat    = buildKeyMaterial(password, keyfileBytes, prfSecret);
    const key       = await deriveKey(keyMat, salt, kdfParams);

    plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad },
      key,
      ct,
    ));
  } catch (e) {
    // Re-throw our own errors (KEYFILE_REQUIRED, PRF_REQUIRED) unchanged.
    if (e instanceof PalimpsestError) throw e;
    throw new PalimpsestError(ErrorCodes.DECRYPTION_FAILED, 'Payload found but could not be decrypted');
  }

  const { typeFlag, compressed, name, mime, content } = decodeContent(plain);
  const rawContent = compressed ? await decompress(content) : content;
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
