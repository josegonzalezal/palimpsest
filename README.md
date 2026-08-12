# Palimpsest

Client-side encryption and steganography. Encrypt a message or a file with a
password, then export it as an armored text block or hide it inside a carrier
image. All cryptography runs in the browser — no server sees plaintext, no
server is required.

## Status

**Work in progress. Not audited. Not safe for real secrets yet.**

| Milestone | State |
|---|---|
| 1 — Crypto core | Done |
| 2 — LSB steganography over PNG | Done |
| 3 — Self-contained HTML client | Done |
| 4 — Local second factor (keyfile + WebAuthn PRF) + GitHub Pages | Done |
| 5a — Arbitrary file encryption (documents, images, audio, video, archives) | Done |
| 5b — Ephemeral state (inactivity timer + wipe button) | Done |
| 5c — WAV carrier (LSB over PCM samples, Tier 1 — hidden) | Done |
| 5d — Universal fallback carrier (append to any file, Tier 3 — attached, findable) | Done |

Test suite: 23 of 23 green.

## Security notice

This is a personal project written to learn applied cryptography. It has not
been audited by anyone. Use `age`, `VeraCrypt`, or `Signal` for anything that
actually matters.

## Threat model

Recovering a payload requires:

1. the correct **password**,
2. optionally, the correct **keyfile** (a 32-byte random file you generate and
   keep; encrypted payloads record a flag indicating whether a keyfile was used),
3. optionally, a registered **hardware security key** (WebAuthn PRF; only on
   HTTPS, requires FIDO2 with PRF extension).

There is no server, no account, no service dependency. The server delivers one
file and sees nothing.

### What this does and does not give you

**Without a keyfile or hardware key this is single-factor.** Your password is
the only secret. Argon2id makes each password guess expensive, but a weak
password remains a weak secret — it raises the cost of brute force, it does
not eliminate the risk.

**With a keyfile:** an attacker needs both the password and the file. The file
is 32 bytes of cryptographic-quality randomness, so it carries its own entropy
regardless of how the password was chosen. Losing the keyfile with no backup
makes decryption permanently impossible.

**With a hardware key (WebAuthn PRF):** the authenticator contributes a
credential-bound secret to key derivation. An attacker needs the physical
device. Losing the device with no second key registered makes decryption
permanently impossible.

Key material is `password ‖ keyfileBytes ‖ prfSecret` where each part is
a fixed-length domain (32 bytes each). Mixing in fewer factors changes the
concatenation length, so password-only, password+keyfile, and all-three are
cryptographically distinct.

## Cryptography

| Layer | Choice |
|---|---|
| Key derivation | Argon2id (`m=64 MB, t=3, p=1`), via `hash-wasm` |
| Encryption | AES-256-GCM, WebCrypto |
| Key material | `password ‖ keyfileBytes ‖ prfSecret` |
| Header integrity | Full outer header passed as AES-GCM `additionalData` |
| Header flags | `FLAGS_KEYFILE (0x01)`, `FLAGS_PRF (0x02)` — part of AAD |

No hand-rolled primitives, no additional layers wrapped around the AEAD.
AES-GCM is authenticated, so a wrong password, wrong keyfile, or a single
flipped bit makes decryption fail outright rather than return garbage.

Decryption failures return a generic message for wrong password and wrong
keyfile. `KEYFILE_REQUIRED` and `PRF_REQUIRED` are returned before key
derivation when the header flag is set but the factor is missing — this lets
the UI prompt for the right thing without leaking which factor is wrong.

### Payload format (version 2)

```
magic        4 B   "PLMP"
version      1 B   0x02
flags        1 B   FLAGS_KEYFILE (0x01) | FLAGS_PRF (0x02)
kdfParamsLen 2 B   uint16
kdfParams    N B   [KDF ID][params...] (0x02 = Argon2id)
salt        16 B
prfSalt     32 B   random when FLAGS_PRF is not set (random to avoid leaking PRF absence)
credIdLen    2 B   uint16
credId       M B   WebAuthn credential ID; zero-length when FLAGS_PRF not set
iv          12 B
ciphertextLen 4 B  uint32
ciphertext   N B   includes the 16-byte GCM tag
```

Everything from `magic` through `ciphertextLen` is authenticated as AAD.
Tampering with any header field — including the flags byte — causes GCM
authentication to fail.

## Carriers

Not every container hides data equally well, and the UI says which tier you
are getting rather than implying they are all steganography.

| Tier | Formats | What it means |
|---|---|---|
| 1 — hidden | PNG, BMP, TIFF, WAV, FLAC | LSB embedding. Requires statistical analysis to detect. |
| 2 — attached | JPEG, MP4, PDF, DOCX/ZIP, MP3 | File opens normally, but `binwalk` finds the payload immediately. |
| 3 — fallback | any | Appended after the file's logical end. Weakest option. |

Steganographic output must stay PNG. Re-saving as JPEG, screenshotting, or
sending through a service that re-encodes will silently destroy the payload.

**Alpha premultiplication:** `canvas.drawImage` pre-multiplies alpha before
`getImageData`. A pixel with partial transparency gets its RGB channels scaled
and LSBs permanently corrupted. The carrier must be fully opaque (all alpha=255)
or the tool rejects it.

## Running it

```bash
npm install
npm test          # headless crypto suite (23 tests, Node.js)
npm run build     # compile index.html from src/client.template.html
```

Open `index.html` directly — no server needed. The file runs under `file://`
without any network requests.

**WebAuthn PRF** requires HTTPS with a real origin. Under `file://` the option
is hidden rather than showing a broken control. It is available on the
[GitHub Pages build](https://josegonzalezal.github.io/Encryption-Website/).

## Design notes

**The source is deliberately readable.** Kerckhoffs's principle: a cryptosystem
must remain secure when everything except the key is public. There is no
obfuscation, no DevTools blocking, no minification presented as a security
control. Client-side encryption means the server cannot read your data; the
price is that you can read the code. That is the correct trade.

**No decoy layers or junk steps.** AES-256-GCM already fails closed. Wrapping
it in homemade obfuscation adds zero bits of security while introducing real
risks — nonce reuse, padding oracles, timing side channels — and makes the
design impossible to audit.

**`connect-src 'none'` is the real protection in the single-file client, not
`script-src`.** A self-contained HTML file cannot avoid `script-src 'unsafe-inline'`
— there is nowhere else for the inline `<script>` block to come from. Inline
scripts are not in themselves a problem: the threat `unsafe-inline` opens is
exfiltration (injected code reads the plaintext and phones home). That path is
closed at the network layer. `default-src 'none'` sets `connect-src 'none'`,
which means the page cannot make any outbound request — no `fetch`, no XHR, no
WebSocket, no beacon, no image load. Even if an attacker injected arbitrary
JavaScript, it could not leave the page.

**No service dependency.** There is no pepper, no server-side secret, no
account. The server delivers one file and sees nothing else. There is no
"if the service goes away your data is gone" caveat. Anyone who can run a web
server can self-host this.

## License

MIT
