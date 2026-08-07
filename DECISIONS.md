# Decisions

The four open decisions in BRIEF.md are resolved. Do not ask again.

## 1. Key derivation function

**Argon2id**, embedded as a base64 WASM blob inside the HTML so the client stays
a single self-contained, auditable file.

Rationale: the threat model is an offline attack after the pepper has been pulled
from the API. PBKDF2 parallelises well on GPU, so iteration count buys less than
it appears. Argon2id forces memory cost per attempt, which is what breaks that
parallelisation.

**[DECIDE at implementation]** Argon2 parameters (m/t/p). Start from
m=64 MB, t=3, p=1 and benchmark on a mid-range phone before fixing them.

## 2. kdfParams encoding

**Length-prefixed** (uint16 length + variable blob).

Required by the Argon2id choice — three parameters do not fit in one byte.

The blob must begin with a **KDF identifier byte**: `0x01` = PBKDF2,
`0x02` = Argon2id, followed by that KDF's parameters. Without it the decoder
knows how many bytes to read but not how to interpret them.

## 3. Pepper

**Per-user pepper, encrypted at rest with a global master key held in an
environment variable.**

Each user gets a random pepper stored in a Supabase table, but the stored value
is encrypted (AES-GCM) with a master key that lives only in an env var, never in
the database. The route handler decrypts it in memory after verifying the session.

Rationale: a per-user pepper alone does not help against a database dump, which
hands the attacker every pepper at once. A global pepper alone is retroactive —
one leak compromises every payload ever created. The hybrid makes a DB dump
useless without the env var, and an env var leak useless without the DB.

Store a **master key version identifier** alongside each encrypted pepper, so the
master key can be rotated later without re-encrypting the table blindly.

RLS must deny all direct client reads on that table. The pepper is only reachable
through the authenticated route handler.

## 4. Size limits

**25 MB global ceiling, plus a per-carrier limit computed at runtime.**

The global ceiling is a memory guard: the browser holds the original, the
ciphertext and the base64 simultaneously, roughly 3-4x the file size.

The binding limit in practice is carrier capacity:

- Tier 1 PNG: `floor(width * height * 3 / 8)` bytes
- Tier 1 WAV: `floor(sampleCount * channels / 8)` bytes
- Tier 3 fallback and `.ptx` export: no carrier limit, only the 25 MB ceiling

Enforce both before any crypto work begins. On failure, report required and
available sizes.

The UI must show the selected carrier's capacity as soon as it is loaded, before
the user picks what to hide — turning the most common error into information
shown up front rather than a message afterwards.