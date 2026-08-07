# Palimpsest

Client-side encryption and steganography. Encrypt a message or a file with a
password, then export it as an armored text block or hide it inside a carrier
file. All cryptography runs in the browser — the server never sees plaintext.

## Status

**Work in progress. Not usable yet, and not safe for real secrets.**

| Milestone | State |
|---|---|
| 1 — Crypto core | Done |
| 2 — LSB steganography over PNG | Done |
| 3 — Self-contained HTML client | Done |
| 4 — Pepper backend (Next.js + Supabase) | Not started |
| 5 — Arbitrary files, extra carriers, WebAuthn, ephemeral state | Not started |

Test suite: 11 of 11 green.

## Security notice

This is a personal project written to learn applied cryptography. It has not
been audited by anyone. Use `age`, `VeraCrypt` or `Signal` for anything that
actually matters.

## Threat model

Recovering a payload requires:

1. the correct **password**,
2. access to the **live service**, which holds a server-side secret (the *pepper*),
3. optionally, a registered **hardware security key** (WebAuthn PRF).

### What this does not give you

The pepper raises the cost of an offline attack. It does not make decryption
impossible for an attacker who can authenticate against the API, retrieve the
pepper, and then brute-force the password offline. The accurate claim is:
*ciphertext alone is not enough.*

Two consequences worth stating plainly:

- Because the pepper is per-user, **only the account that encrypted a payload can
  decrypt it**. Palimpsest is a personal vault, not a messaging tool.
- If the service goes away, everything encrypted with it becomes permanently
  unrecoverable, correct password or not. There is no offline decryption path.

## Cryptography

| Layer | Choice |
|---|---|
| Key derivation | Argon2id (`m=64 MB, t=3, p=1`), via `hash-wasm` |
| Encryption | AES-256-GCM, WebCrypto |
| Key material | `password ‖ pepper ‖ prfSecret` |
| Header integrity | Full outer header passed as AES-GCM `additionalData` |

No hand-rolled primitives, no additional layers wrapped around the AEAD. AES-GCM
is authenticated, so a wrong password, a wrong pepper or a single flipped bit
makes decryption fail outright rather than return garbage.

Decryption failures return one generic message. Wrong password, wrong pepper and
tampering are deliberately indistinguishable to the caller.

### Payload format

```
magic        4 B   "PLMP"
version      1 B
kdfParamsLen 2 B   uint16
kdfParams    N B   [KDF ID][params...] (0x01 PBKDF2, 0x02 Argon2id)
salt        16 B
prfSalt     32 B   zeroed when no hardware key is used
iv          12 B
ciphertextLen 4 B  uint32
ciphertext   N B   includes the 16-byte GCM tag
```

Everything from `magic` through `ciphertextLen` is authenticated as AAD.

## Carriers

Not every container hides data equally well, and the UI says which tier you are
getting rather than implying they are all steganography.

| Tier | Formats | What it means |
|---|---|---|
| 1 — hidden | PNG, BMP, TIFF, WAV, FLAC | LSB embedding. Requires statistical analysis to detect. |
| 2 — attached | JPEG, MP4, PDF, DOCX/ZIP, MP3 | File opens normally, but `binwalk` finds the payload immediately. |
| 3 — fallback | any | Appended after the file's logical end. Weakest option. |

Steganographic output must stay PNG. Re-saving as JPEG, screenshotting, or
sending through a service that re-encodes will silently destroy the payload.

## Running it

```bash
npm install
npm test          # headless crypto suite (Node.js, pngjs)
npm run build     # compile index.html from src/client.template.html
```

Open `index.html` directly — no server needed. The file runs under
`file://` without any network requests.

`scripts/demo.mjs` exercises the crypto core from the command line:

```bash
node scripts/demo.mjs encrypt <password> <pepper> "secret message"
node scripts/demo.mjs decrypt <password> <pepper>
```

## Design notes

Three decisions worth explaining, since they came up more than once:

**The source is deliberately readable.** Kerckhoffs's principle: a cryptosystem
must remain secure when everything except the key is public. There is no
obfuscation, no DevTools blocking, no minification presented as a security
control. Client-side encryption means the server cannot read your data; the price
is that you can read the code. That is the correct trade.

**No decoy layers or junk steps.** AES-256-GCM already fails closed. Wrapping it
in homemade obfuscation adds zero bits of security while introducing real risks —
nonce reuse, padding oracles, timing side channels — and makes the design
impossible to audit.

**`connect-src 'none'` is the real protection in the single-file client, not
`script-src`.** A self-contained HTML file cannot avoid `script-src 'unsafe-inline'`
— there is nowhere else for the inline `<script>` block to come from. Inline
scripts are not in themselves a problem: the threat `unsafe-inline` opens is
exfiltration (injected code reads the plaintext and phones home). That path is
closed at the network layer. `default-src 'none'` sets `connect-src 'none'`,
which means the page cannot make *any* outbound request — no `fetch`, no XHR, no
WebSocket, no beacon, no image load. Even if an attacker injected arbitrary
JavaScript, it could not leave the page. The single-file design and
the network lockdown are the same property stated two ways: no network means
both no dependency and no exfiltration.

**The pepper is per-user but encrypted at rest** with a master key held only in an
environment variable. A per-user pepper alone does not survive a database dump; a
global pepper alone is retroactive. The hybrid makes a DB dump useless without the
env var, and an env var leak useless without the DB.

## License

MIT
