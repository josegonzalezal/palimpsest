// Palimpsest LSB steganography over PNG.
//
// Capacity: floor(width × height × 3 / 8) bytes.
//   Three bits per pixel: the LSB of each R, G, B channel. Alpha is forced to
//   255 before any pixel read or write — canvas premultiplies RGB when alpha <
//   255 and silently corrupts the low bits with no error.
//
// LSB stream layout: [u32be(payloadLen): 4 B] [payload: payloadLen B]
//   The first 4 bytes of a valid PLMP payload are always the ASCII magic "PLMP".
//   extractFromPng verifies both the length prefix and that magic before returning.
//
// Node.js: pngjs for PNG decode/encode (tests).
// Browser: Canvas API with canvas.toBlob('image/png') — wired in Milestone 3.

const IS_NODE = typeof process !== 'undefined' && Boolean(process.versions?.node);

// ─── Error codes ──────────────────────────────────────────────────────────────

export const StegoCodes = {
  CAPACITY_EXCEEDED: 'CAPACITY_EXCEEDED',
  NO_PAYLOAD_FOUND:  'NO_PAYLOAD_FOUND',
};

export class StegoError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'StegoError';
    this.code = code;
  }
}

// ─── Capacity ─────────────────────────────────────────────────────────────────

export function capacity(width, height) {
  return Math.floor(width * height * 3 / 8);
}

// ─── Core bit I/O ─────────────────────────────────────────────────────────────
// pixelData: Uint8Array of RGBA bytes (width × height × 4).
// Bits are packed MSB-first. Stream bit index N → pixel floor(N/3), channel N%3.

function writeBits(pixelData, bytes) {
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    for (let off = 0; off < 8; off++) {
      const si  = i * 8 + off;
      const pos = Math.floor(si / 3) * 4 + (si % 3); // RGBA byte index
      pixelData[pos] = (pixelData[pos] & 0xfe) | ((b >> (7 - off)) & 1);
    }
  }
}

function readBits(pixelData, numBytes) {
  const out = new Uint8Array(numBytes);
  for (let i = 0; i < numBytes; i++) {
    let b = 0;
    for (let off = 0; off < 8; off++) {
      const si = i * 8 + off;
      b |= (pixelData[Math.floor(si / 3) * 4 + (si % 3)] & 1) << (7 - off);
    }
    out[i] = b;
  }
  return out;
}

// ─── Alpha ────────────────────────────────────────────────────────────────────
// Must run before reading any pixel values. If premultiplication already
// happened (alpha was < 255 at decode time), the R/G/B values are already
// wrong; warn rather than silently embed corrupted bits.

function forceAlpha255(pixelData) {
  let hadTransparency = false;
  for (let i = 3; i < pixelData.length; i += 4) {
    if (pixelData[i] < 255) hadTransparency = true;
    pixelData[i] = 255;
  }
  return hadTransparency;
}

// ─── PNG decode / encode ──────────────────────────────────────────────────────

async function decodePng(pngBytes) {
  if (IS_NODE) {
    const mod = await import('pngjs');
    const PNG = mod.PNG ?? mod.default?.PNG;
    return new Promise((resolve, reject) => {
      const png = new PNG();
      png.on('parsed', function () {
        resolve({ data: new Uint8Array(this.data), width: this.width, height: this.height });
      });
      png.on('error', reject);
      png.parse(Buffer.from(pngBytes));
    });
  }
  // ── Browser (Milestone 3) ─────────────────────────────────────────────────
  const bitmap = await createImageBitmap(new Blob([pngBytes], { type: 'image/png' }));
  const canvas = Object.assign(document.createElement('canvas'),
    { width: bitmap.width, height: bitmap.height });
  const ctx = canvas.getContext('2d');
  ctx.drawImage(bitmap, 0, 0);
  const id = ctx.getImageData(0, 0, bitmap.width, bitmap.height);
  return { data: new Uint8Array(id.data.buffer), width: bitmap.width, height: bitmap.height };
}

async function encodePng(pixelData, width, height) {
  if (IS_NODE) {
    const mod = await import('pngjs');
    const PNG = mod.PNG ?? mod.default?.PNG;
    return new Promise((resolve, reject) => {
      const png = new PNG({ width, height, filterType: -1 });
      png.data = Buffer.from(pixelData);
      const chunks = [];
      png.pack()
        .on('data',  c => chunks.push(c))
        .on('end',   () => resolve(new Uint8Array(Buffer.concat(chunks))))
        .on('error', reject);
    });
  }
  // ── Browser (Milestone 3) ─────────────────────────────────────────────────
  const canvas = Object.assign(document.createElement('canvas'), { width, height });
  canvas.getContext('2d').putImageData(
    new ImageData(new Uint8ClampedArray(pixelData), width, height), 0, 0,
  );
  // Must use toBlob + 'image/png'. toDataURL is synchronous and may follow a
  // lossy code path in some browsers for certain image sizes.
  return new Promise((resolve, reject) => {
    canvas.toBlob(blob => {
      if (!blob) return reject(new Error('canvas.toBlob returned null'));
      blob.arrayBuffer().then(b => resolve(new Uint8Array(b))).catch(reject);
    }, 'image/png');
  });
}

// ─── LSB stream helpers ───────────────────────────────────────────────────────

const PREFIX = 4; // bytes for the u32be length prefix
const PLMP   = [0x50, 0x4c, 0x4d, 0x50];

function makeU32be(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function readU32be(b) {
  return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function embedInPng(pngBytes, payloadBytes) {
  const { data, width, height } = await decodePng(pngBytes);

  const cap      = capacity(width, height);
  const required = PREFIX + payloadBytes.length;
  if (required > cap) {
    throw new StegoError(
      StegoCodes.CAPACITY_EXCEEDED,
      `Carrier too small: need ${required} B but capacity is ${cap} B ` +
      `(${width}×${height} PNG). ` +
      `Payload is ${payloadBytes.length} B; ${PREFIX} B length prefix.`,
    );
  }

  // forceAlpha255 BEFORE reading any channel values: premultiplied reads are
  // already wrong and cannot be un-premultiplied after the fact.
  const hadTransparency = forceAlpha255(data);
  if (hadTransparency) {
    // Transparency was present: values may already be premultiplied at decode
    // time by the platform. We forced alpha to 255 but the R/G/B damage is
    // done. Log rather than throw so callers can decide.
    console.warn(
      'stego-png: carrier had transparency. ' +
      'Pixels with alpha < 255 may have been premultiplied at decode time; ' +
      'embed is proceeding but round-trip fidelity is not guaranteed. ' +
      'Use an opaque PNG carrier to avoid this.',
    );
  }

  const stream = new Uint8Array(PREFIX + payloadBytes.length);
  stream.set(makeU32be(payloadBytes.length));
  stream.set(payloadBytes, PREFIX);
  writeBits(data, stream);

  return encodePng(data, width, height);
}

export async function extractFromPng(pngBytes) {
  const { data, width, height } = await decodePng(pngBytes);
  const cap = capacity(width, height);

  if (cap < PREFIX) {
    throw new StegoError(StegoCodes.NO_PAYLOAD_FOUND, 'No payload found in this carrier');
  }

  // The length prefix lives in the unencrypted LSB stream and is attacker-
  // controlled. Validate bounds before using it to avoid reading past the image.
  const len = readU32be(readBits(data, PREFIX));
  if (len === 0 || len > cap - PREFIX) {
    throw new StegoError(StegoCodes.NO_PAYLOAD_FOUND, 'No payload found in this carrier');
  }

  const payload = readBits(data, PREFIX + len).slice(PREFIX);

  if (payload[0] !== PLMP[0] || payload[1] !== PLMP[1] ||
      payload[2] !== PLMP[2] || payload[3] !== PLMP[3]) {
    throw new StegoError(StegoCodes.NO_PAYLOAD_FOUND, 'No payload found in this carrier');
  }

  return payload;
}
