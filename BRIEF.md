> **Note:** The pepper backend (Milestone 4 in this brief) was replaced by a
> local second factor — keyfile or WebAuthn PRF. See DECISIONS.md for the
> rationale. The rest of this brief reflects the original design intent and
> is kept for reference.

# Build brief — Palimpsest

## What we're building

Palimpsest is a client-side encryption and steganography tool. A user encrypts a
message or a file with a password, and the ciphertext is either exported as text
or hidden inside a carrier file. All cryptography happens in the browser; the
server never sees plaintext.

Security model: recovering a payload requires (1) the correct password, (2) access
to the live service, which holds a server-side secret called the pepper, and
optionally (3) a registered hardware security key.

Be honest about the limits of this. The pepper raises the cost of an offline
attack; it does not make decryption impossible for someone who can authenticate
against the API and pull it. Never write "unbreakable" or "military-grade"
anywhere in the code, UI, or docs.

## How I want you to work

Do NOT generate the whole application in one pass. Build it in milestones, and
stop after each one so I can review:

1. Crypto core only, no UI. Key derivation, AES-GCM, payload format, plus a
   headless Node test script. All nine tests green before moving on.
2. LSB steganography over PNG, with round-trip and capacity tests.
3. The self-contained HTML client on top of 1 and 2.
4. Pepper backend: Next.js route handler, Supabase auth, rate limiting, schema.sql.
5. Everything else, one feature at a time: arbitrary files, extra carrier formats,
   WebAuthn, ephemeral state.

Run `git init` and commit before writing the second file. A previous version of
this project was lost because it was never in version control.

Four decisions are mine to make, not yours. Ask me before assuming:
- PBKDF2 with 600,000 iterations, or Argon2id (adds a WASM dependency)
- Payload header layout
- Pepper: global or per-user
- Maximum file size for v1

## Crypto

Use the WebCrypto API. No third-party crypto libraries.

    keyMaterial = password || pepper || prfSecret (if hardware key registered)
    salt        = 16 random bytes, fresh per payload
    key         = KDF(keyMaterial, salt, params) -> 256 bits
    iv          = 12 random bytes
    ciphertext  = AES-256-GCM(key, iv, plaintext)

Payload header, prepended to the ciphertext:

    magic       4 bytes  ASCII "PLMP"
    version     1 byte
    kdfParams   variable (iteration count or Argon2 parameters)
    salt       16 bytes
    prfSalt    32 bytes  (zeroed when no hardware key is used)
    iv         12 bytes
    length      4 bytes  uint32 BE
    ciphertext  N bytes  (includes the 16-byte GCM tag)

Content header, inside the encrypted region, so the decoder knows what it holds:

    type        1 byte   0x00 = UTF-8 text, 0x01 = file
    nameLen     2 bytes  uint16
    name        N bytes  original filename, UTF-8
    mimeLen     2 bytes  uint16
    mime        M bytes  MIME type
    content     ...      raw bytes

## Inputs

Text messages, and any file type: documents, images, audio, video, archives.

Compress before encrypting, never after. Enforce the size limit before doing any
work — `crypto.subtle.encrypt` takes the whole buffer in memory and a large video
will crash the tab. Chunked encryption is out of scope for v1; do not attempt it,
because doing it badly causes nonce reuse.

## Outputs

Four ways to save an encrypted payload:

1. Armored text block, copy to clipboard:

       -----BEGIN PALIMPSEST MESSAGE-----
       Version: 1

       <base64, wrapped at 64 chars>
       -----END PALIMPSEST MESSAGE-----

2. Download as `.ptx`
3. Download as plain `.txt` (same armored content)
4. Embedded inside a carrier file

The decoder must accept all four, plus pasted text with or without surrounding
whitespace.

## Carrier files

There is no single universal technique. Implement three tiers and tell the user
in plain language which one they are getting.

**Tier 1 — real steganography.** PNG, BMP, TIFF: LSB over the R/G/B channels,
three bits per pixel. WAV and FLAC: LSB over PCM sample values. Label as "hidden".

**Tier 2 — structural embedding.** JPEG (after the FFD9 marker or an APPn
segment), MP4/MOV (a free atom), PDF (after %%EOF), DOCX/XLSX/PPTX/ZIP (these are
ZIP archives — add an entry or use the archive comment), MP3 (ID3v2 private
frame). The file still opens normally, but the payload is trivially findable with
binwalk or strings. Label as "attached, but findable" — never call this hidden.

**Tier 3 — universal fallback.** Append payload plus trailing magic and length to
any file. Weakest option; label it as such.

Ship tier 1 and tier 3 in v1. Add tier 2 formats one at a time, each with its own
round-trip test.

Critical constraints:
- Stego output must stay PNG. Warn loudly in the UI that re-saving as JPEG,
  screenshotting, or sending through most chat apps destroys the payload silently.
- Force alpha to 255 on every pixel before LSB embedding, or reject images with
  transparency. Canvas premultiplies RGB when alpha < 255 and will corrupt the
  low bits without any error.
- Use `canvas.toBlob(..., 'image/png')`, not `toDataURL`.
- Check capacity `floor(width * height * 3 / 8)` before starting, and report both
  required and available size on failure.

## Hardware key support

WebAuthn with the `prf` extension. The security key deterministically derives a
stable secret from a registered credential plus a salt; mix that secret into key
derivation. It never leaves the device, so this is a genuine third factor.

- Requires YubiKey 5 or newer (CTAP 2.1 hmac-secret). Feature-detect and fall
  back to password + pepper where unsupported.
- Store the prf salt in the payload header or decryption will derive a different key.
- Force the user to acknowledge, in a blocking dialog, that losing the key with no
  registered backup means the data is permanently unrecoverable. Prompt them to
  register a second key.

## Ephemeral state

An inactivity timer (default 5 minutes, configurable) and an always-visible wipe
button, both doing the same thing:

- Clear localStorage, sessionStorage, IndexedDB, Cache Storage for this origin
- Clear cookies set by this origin
- Overwrite key material and plaintext buffers with zeros, drop references, reload

Label the control "Clear all data this tool created". Do NOT claim it erases
everything — it cannot touch the browser's HTTP disk cache, history, address bar
autocomplete, memory already released to the OS, swap, or hibernation images.
Zeroing JS buffers is best-effort because the engine may have copied values during
garbage collection. Say all of this in the UI, briefly and plainly.

## UI

English throughout.

- Password strength meter with a blocking confirmation: a weak password requires
  active acknowledgement before proceeding, not a passive warning.
- Encode and decode modes, each accepting a carrier file, `.ptx`, `.txt`, or
  pasted text.
- Two distinct failure messages: "no payload found in this carrier" and "payload
  found but could not be decrypted". Do NOT distinguish between wrong password,
  wrong pepper, and tampering — that leaks information to an attacker.

## Backend

Next.js App Router route handler serving the pepper, backed by Supabase.

- Verify the Supabase session server-side. No session, no pepper.
- Rate limit per user and per IP. This is the only thing between an attacker and
  an offline brute-force, so it matters more here than in a normal API.
- Read the pepper with the service role key inside the handler only. Never expose
  that key to the client.
- schema.sql: pepper table plus RLS policies denying direct client reads.

## Tests

Write a headless Node script, not manual clicking. Required checks:

1. Round-trip: encrypt, embed, extract, decrypt returns the original
2. Round-trip for the armored text format
3. Wrong password rejected
4. Wrong pepper rejected
5. Tampered ciphertext rejected (flip one bit, expect a throw)
6. Tampered carrier rejected
7. Capacity overflow caught before any work is done
8. Large payload near capacity round-trips correctly
9. Carrier with no payload takes the "not found" path, does not crash

Test the crypto and stego logic in isolation before wiring any UI. A previous
version had a redundant helper composition that produced correct output by
accident while being logically wrong; only isolated testing caught it.

## Do not do these things

These were requested and are either impossible or counterproductive. Do not
implement them, and do not silently approximate them either.

**Do not try to prevent the user from reading the source.** Anything the browser
executes, the user can read. Do not block F12, detect DevTools, disable
right-click, or obfuscate. Kerckhoffs's principle: the system must stay secure
when everything except the key is public. If security depends on nobody reading
the code, it is already broken. Note the underlying trade-off — client-side
encryption means the server cannot read the data, and the price is that the user
can read the code. That is the correct trade.

**Do not add decoy steps, junk data, fake equations, or homemade layers around
AES.** The intent behind this request is already satisfied: AES-256-GCM is
authenticated encryption, so a wrong key or a modified payload makes decryption
fail outright rather than return garbage. Extra layers add zero bits of security,
make the design unauditable, and are the standard way to introduce nonce reuse,
padding oracles, and timing side channels.

If more resistance is wanted, these are the real versions and are welcome:
- Argon2id instead of PBKDF2 (memory-hard, defeats GPU and ASIC attacks)
- Length padding to fixed-size buckets, so ciphertext size stops leaking
  information about the content
- Deniable volumes: two payloads in one carrier under different passwords,
  computationally indistinguishable, one a decoy

**Do not strip comments from the source.** Minification handles that at build
time. Keep the repository fully commented and source-mapped in development; ship
a minified production bundle without published source maps, and document that as
a size optimisation, not a security control.

**Do not use the phrase "military grade".** It has no technical meaning. State the
primitives instead: AES-256-GCM, Argon2id, WebAuthn PRF.

## Deliverables

- `palimpsest.html` — self-contained client, no build step, auditable in one read
- `app/api/pepper/route.ts`
- `schema.sql`
- `test/crypto.test.mjs` — the headless test script
- `README.md` — states the threat model honestly, including the pepper limitation