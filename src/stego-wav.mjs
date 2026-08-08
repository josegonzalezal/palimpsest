// Palimpsest LSB steganography over WAV (uncompressed PCM).
//
// Carrier must be PCM format (RIFF fmt audioFormat = 1). Compressed formats
// (ADPCM = 2, IEEE float = 3, WMA, etc.) are rejected — their sample bytes
// carry acoustic structure at every bit position; LSB modification is audible.
//
// Capacity: floor(dataSizeBytes / 8) bytes.
//   Treats the data chunk as a flat byte array: 1 bit per byte (the LSB),
//   with no awareness of sample bit depth. For 16-bit PCM this means both
//   the low byte (~-96 dBFS noise, inaudible) and the high byte (~-48 dBFS,
//   equivalent to 8-bit recording noise floor) of each sample are modified.
//   The -48 dBFS level is inaudible in typical content but may be detectable
//   in very quiet passages with high-quality equipment.
//
// LSB stream layout: [u32be(payloadLen): 4 B] [payload: payloadLen B]
//   Identical to stego-png. extractFromWav verifies the PLMP magic before
//   returning, so a carrier with no payload returns NO_PAYLOAD_FOUND.
//
// Pure byte manipulation — no DOM, no Node.js APIs. Synchronous.

// ─── Error codes ──────────────────────────────────────────────────────────────

export const WavCodes = {
  CAPACITY_EXCEEDED: 'CAPACITY_EXCEEDED',
  NO_PAYLOAD_FOUND:  'NO_PAYLOAD_FOUND',
  WAV_NOT_PCM:       'WAV_NOT_PCM',
  WAV_MALFORMED:     'WAV_MALFORMED',
};

export class WavStegoError extends Error {
  constructor(code, message) {
    super(message);
    this.name  = 'WavStegoError';
    this.code  = code;
  }
}

// ─── Capacity ─────────────────────────────────────────────────────────────────

export function wavCapacity(dataChunkSize) {
  return Math.floor(dataChunkSize / 8);
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

const PREFIX = 4;                          // u32be payload-length prefix, bytes
const PLMP   = [0x50, 0x4c, 0x4d, 0x50]; // 'P','L','M','P'

function makeU32be(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function readU32be(b) {
  return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
}

function readU16le(b, off) {
  return (b[off] | (b[off + 1] << 8)) >>> 0;
}

function readU32le(b, off) {
  return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
}

// ─── WAV parser ───────────────────────────────────────────────────────────────
// Returns { dataStart, dataSize } or throws WavStegoError.
// Scans chunks in order to find 'fmt ' and 'data'. Handles non-standard chunk
// orderings and skips padding chunks (LIST, INFO, etc.). Rejects non-PCM.

function parseWav(b) {
  if (b.length < 12) {
    throw new WavStegoError(WavCodes.WAV_MALFORMED, 'Not a WAV file: file too short');
  }

  const riff = String.fromCharCode(b[0], b[1], b[2], b[3]);
  const wave = String.fromCharCode(b[8], b[9], b[10], b[11]);
  if (riff !== 'RIFF' || wave !== 'WAVE') {
    throw new WavStegoError(WavCodes.WAV_MALFORMED, 'Not a WAV file');
  }

  let pos       = 12;
  let audioFmt  = -1;
  let dataStart = -1;
  let dataSize  =  0;

  while (pos + 8 <= b.length) {
    const id   = String.fromCharCode(b[pos], b[pos + 1], b[pos + 2], b[pos + 3]);
    const size = readU32le(b, pos + 4);
    const body = pos + 8;

    if (id === 'fmt ') {
      if (size < 16) throw new WavStegoError(WavCodes.WAV_MALFORMED, 'fmt chunk too small');
      audioFmt = readU16le(b, body);
    } else if (id === 'data') {
      dataStart = body;
      dataSize  = size;
      break; // found — no need to scan further
    }

    // RIFF spec: chunks must be word-aligned; odd-size chunks have a padding byte.
    pos = body + size + (size & 1);
  }

  if (audioFmt < 0) throw new WavStegoError(WavCodes.WAV_MALFORMED, 'No fmt chunk found');
  if (dataStart < 0) throw new WavStegoError(WavCodes.WAV_MALFORMED, 'No data chunk found');

  if (audioFmt !== 1) {
    throw new WavStegoError(
      WavCodes.WAV_NOT_PCM,
      `WAV audio format ${audioFmt} is not uncompressed PCM (expected 1). ` +
      `Re-export as 16-bit or 24-bit PCM WAV in your audio editor.`,
    );
  }

  return { dataStart, dataSize };
}

// ─── Bit I/O over the PCM data region ────────────────────────────────────────
// stream: Uint8Array to embed. Packs 1 bit per sample byte (LSB), MSB-first.

function writeLsbs(samples, stream) {
  for (let i = 0; i < stream.length; i++) {
    const byte = stream[i];
    for (let bit = 0; bit < 8; bit++) {
      const si = i * 8 + bit;
      samples[si] = (samples[si] & 0xfe) | ((byte >>> (7 - bit)) & 1);
    }
  }
}

function readLsbs(samples, numBytes) {
  const out = new Uint8Array(numBytes);
  for (let i = 0; i < numBytes; i++) {
    let byte = 0;
    for (let bit = 0; bit < 8; bit++) {
      byte |= (samples[i * 8 + bit] & 1) << (7 - bit);
    }
    out[i] = byte;
  }
  return out;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function embedInWav(wavBytes, payloadBytes) {
  const b               = new Uint8Array(wavBytes);
  const { dataStart, dataSize } = parseWav(b);

  const cap      = wavCapacity(dataSize);
  const required = PREFIX + payloadBytes.length;
  if (required > cap) {
    throw new WavStegoError(
      WavCodes.CAPACITY_EXCEEDED,
      `Carrier too small: need ${required} B but capacity is ${cap} B ` +
      `(data chunk is ${dataSize} B). ` +
      `Payload is ${payloadBytes.length} B; ${PREFIX} B length prefix.`,
    );
  }

  const out     = new Uint8Array(b);
  const samples = out.subarray(dataStart, dataStart + dataSize);

  const stream  = new Uint8Array(required);
  stream.set(makeU32be(payloadBytes.length));
  stream.set(payloadBytes, PREFIX);
  writeLsbs(samples, stream);

  return out;
}

export function extractFromWav(wavBytes) {
  const b               = new Uint8Array(wavBytes);
  const { dataStart, dataSize } = parseWav(b);
  const cap     = wavCapacity(dataSize);

  if (cap < PREFIX) {
    throw new WavStegoError(WavCodes.NO_PAYLOAD_FOUND, 'No payload found in this carrier');
  }

  const samples = b.subarray(dataStart, dataStart + dataSize);
  const len     = readU32be(readLsbs(samples, PREFIX));

  // The length prefix is attacker-controlled; validate before using it.
  if (len === 0 || len > cap - PREFIX) {
    throw new WavStegoError(WavCodes.NO_PAYLOAD_FOUND, 'No payload found in this carrier');
  }

  const payload = readLsbs(samples, PREFIX + len).slice(PREFIX);

  if (payload[0] !== PLMP[0] || payload[1] !== PLMP[1] ||
      payload[2] !== PLMP[2] || payload[3] !== PLMP[3]) {
    throw new WavStegoError(WavCodes.NO_PAYLOAD_FOUND, 'No payload found in this carrier');
  }

  return payload;
}
