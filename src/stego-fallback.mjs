// Palimpsest universal fallback carrier — Tier 3.
//
// Appends the encrypted payload and a fixed-width trailer to any host file.
// The host file is byte-for-byte identical at its start and continues to open
// normally in its native application (parsers read from the front and stop at
// the logical file end). The appended data is trivially detectable with a hex
// editor, `strings`, or `binwalk` — this is NOT steganography.
//
// Trailer layout (appended after the last byte of the host file):
//   [payload bytes: N]
//   [payloadLen: u32be, 4 B]
//   [MAGIC: 8 B]  "PLMPFALL"
//
// To extract: verify MAGIC at EOF-8, read payloadLen at EOF-12, slice payload,
// then verify the PLMP header magic inside the payload itself.
//
// Pure byte manipulation — no DOM, no Node.js APIs. Synchronous.

// ─── Error codes ──────────────────────────────────────────────────────────────

export const FallbackCodes = {
  NO_PAYLOAD_FOUND: 'NO_PAYLOAD_FOUND',
};

export class FallbackError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'FallbackError';
    this.code = code;
  }
}

// ─── Constants ────────────────────────────────────────────────────────────────

// 'PLMPFALL' — distinct from the payload magic 'PLMP' so a raw PLMP payload
// appended without the fallback wrapper is not misidentified.
const MAGIC     = new Uint8Array([0x50, 0x4c, 0x4d, 0x50, 0x46, 0x41, 0x4c, 0x4c]);
const MAGIC_LEN = MAGIC.length;   // 8
const LEN_FIELD = 4;              // u32be payload length field, bytes
const TRAILER   = MAGIC_LEN + LEN_FIELD; // 12 bytes minimum to hold a trailer

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeU32be(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function readU32be(b, off) {
  return ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function embedInFallback(fileBytes, payloadBytes) {
  const out = new Uint8Array(fileBytes.length + payloadBytes.length + LEN_FIELD + MAGIC_LEN);
  let off = 0;
  out.set(fileBytes,                     off); off += fileBytes.length;
  out.set(payloadBytes,                  off); off += payloadBytes.length;
  out.set(makeU32be(payloadBytes.length), off); off += LEN_FIELD;
  out.set(MAGIC,                         off);
  return out;
}

export function extractFromFallback(fileBytes) {
  const b = new Uint8Array(fileBytes);

  if (b.length < TRAILER) {
    throw new FallbackError(FallbackCodes.NO_PAYLOAD_FOUND, 'No payload found in this file');
  }

  // Verify MAGIC at the end of the file.
  const magicOff = b.length - MAGIC_LEN;
  for (let i = 0; i < MAGIC_LEN; i++) {
    if (b[magicOff + i] !== MAGIC[i]) {
      throw new FallbackError(FallbackCodes.NO_PAYLOAD_FOUND, 'No payload found in this file');
    }
  }

  // Read the payload length immediately before MAGIC.
  const lenOff    = magicOff - LEN_FIELD;
  const payloadLen = readU32be(b, lenOff);

  // The length field is attacker-controlled; validate before using it.
  if (payloadLen === 0 || payloadLen > lenOff) {
    throw new FallbackError(FallbackCodes.NO_PAYLOAD_FOUND, 'No payload found in this file');
  }

  const payload = b.slice(lenOff - payloadLen, lenOff);

  // Verify PLMP payload magic as a second sanity check.
  if (payload[0] !== 0x50 || payload[1] !== 0x4c ||
      payload[2] !== 0x4d || payload[3] !== 0x50) {
    throw new FallbackError(FallbackCodes.NO_PAYLOAD_FOUND, 'No payload found in this file');
  }

  return payload;
}
