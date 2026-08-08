# Manual browser checks

The automated test suite runs in Node.js against pngjs. The checks below require
a real browser and cannot be covered without one.

Perform each check after any change to the steganography path, the WebAuthn flow,
or the wipe/clear-data path. Mark the date and browser when passing.

---

## 1. Canvas PNG round-trip — text payload

**Why it exists:** the Node.js tests use pngjs to decode PNG files. The browser
uses `canvas.getContext('2d').drawImage` + `getImageData`, which is a different
implementation. A bug that only affects the canvas path (e.g. colour-space
handling) would pass all automated tests.

**Steps:**

1. Open `index.html` directly (`file://` URL) or the GitHub Pages build.
2. Select *Encrypt* → *Text message* → type a short message.
3. Select *Output* → *Embed in PNG carrier* → pick a large opaque PNG.
4. Click *Encrypt*. Download the stego PNG.
5. Reload the page.
6. Select *Decrypt* → *PNG carrier* → upload the stego PNG.
7. Enter the same password. Click *Decrypt*.
8. Confirm the message matches exactly.

**Pass criteria:** exact text recovery, no error messages.

---

## 1b. Canvas PNG round-trip — binary file payload

**Why it exists:** covers the file-encryption path through the canvas codec.
A regression in the compressed-flag logic or the content-header decode would
fail here but not in the text test.

**Steps:**

1. Open `index.html` (or the GitHub Pages build).
2. Select *Encrypt* → *File* → pick a **PDF or a photo** (any binary file ≤ 25 MB).
3. Note the file's SHA-256 hash before encrypting:
   - Windows: `certutil -hashfile <file> SHA256`
   - macOS/Linux: `shasum -a 256 <file>`
4. Select *Output* → *Embed in PNG carrier* → pick a large opaque PNG carrier.
5. Click *Encrypt*. Download the stego PNG.
6. Reload the page.
7. Select *Decrypt* → *PNG carrier* → upload the stego PNG. Enter the same password.
8. Download the decrypted file. Compute its SHA-256 hash.

**Pass criteria:** the two hashes are **identical**. A file that "opens fine" is
not sufficient — a truncated or partially-corrupt binary can still open while
failing the hash check.

---

## 2. Transparency rejection

The carrier must be fully opaque. `canvas.drawImage` premultiplies alpha before
`getImageData`; a pixel with alpha < 255 gets its RGB channels scaled, corrupting
the LSBs permanently.

**Case A — transparent PNG as carrier:**

1. Open the tool. Select *Encrypt*, type a short message, select *PNG carrier*.
2. Load a PNG that has any transparent pixels (e.g. a logo with a transparent
   background; confirm with `file` or any image viewer that shows alpha).
3. Click *Encrypt*.
4. **Expected:** error message mentioning transparency. No output file.

**Case B — transparent PNG as input file to hide:**

(This should pass through fine — the input file is encrypted as opaque bytes;
only the *carrier* PNG is decoded via canvas.)

1. Load a transparent PNG as the *file to hide* (not as the carrier).
2. Use a large opaque PNG as the carrier.
3. Encrypt, download, decrypt.
4. **Expected:** round-trip succeeds; the output file is the original transparent PNG.

**Case C — stego output that has somehow acquired transparency:**

This should not happen in normal use because `toBlob('image/png')` with opaque
input stays opaque, but test it if you ever modify the canvas encoding path.

---

## 3. WebAuthn PRF — register, encrypt, reload, decrypt

**Requires:** HTTPS origin (GitHub Pages build), a FIDO2 authenticator with the
PRF extension (YubiKey 5+, passkey platform authenticator).

**Why it exists:** WebAuthn is entirely unavailable under `file://` and cannot be
stubbed meaningfully in Node.js tests. The credential ID and PRF output live only
inside the authenticator.

**Steps:**

1. Open the GitHub Pages build over HTTPS.
2. Select *Encrypt*, enter a password.
3. Expand *Use hardware security key* → click *Register key*. Touch the key when
   it blinks. Confirm "Hardware key registered." appears.
4. Type a short message or pick a file. Click *Encrypt*. Download or copy the output.
5. **Hard reload the page** (Ctrl+Shift+R / Cmd+Shift+R) to clear all JS state.
6. Select *Decrypt*. Enter the same password. Check *Use hardware security key*.
7. Load the stego PNG or paste the armored block. Click *Decrypt*. Touch the key.
8. **Expected:** decryption succeeds and recovers the original content.

**Negative check:**

9. Repeat steps 1–5 but decrypt without checking *Use hardware security key*.
10. **Expected:** error "This payload was encrypted with a hardware key…" and the
    hardware-key section auto-expands.

**Second-key backup check:**

11. Register a second authenticator while the first is still registered and re-run
    the decrypt flow with only the second key present.
12. **Expected:** decryption succeeds (the second credential ID is stored in the
    header; the first key is not required).

---

## 5. WAV carrier round-trip with a real-world file (Milestone 5c)

**Why it exists:** the automated test suite uses a synthetic minimal WAV built by
hand. Real-world WAV files exported from DAWs and audio editors often contain
extra chunks before the data chunk — `fact`, `LIST`, `JUNK`, `bext`, `cue `,
`smpl`, etc. — in non-standard orderings. The parser is supposed to skip these,
but the test fixture does not exercise this path.

**Steps:**

1. Export or obtain a real-world PCM WAV file from an audio editor (Audacity,
   GarageBand, Logic, Reaper). Prefer one that is likely to have extra chunks:
   - Audacity: File → Export → WAV (Microsoft); opens with a `LIST` chunk
   - Any DAW that embeds metadata: will add `bext`, `JUNK`, or `smpl`
2. Inspect the file in a hex editor or with `ffprobe`/`mediainfo` to confirm
   it has chunks other than `fmt ` and `data` (or note that it does not — that
   is also valid input, just less thorough).
3. Open the tool. Encrypt a short text message. Select *Output → Embed in WAV
   carrier*. Load the real-world WAV. Note the capacity shown.
4. Click *Encrypt*. Download the stego WAV.
5. Reload the page.
6. Select *Decrypt → WAV carrier*. Load the stego WAV. Enter the same password.
7. Click *Decrypt*. Confirm the message matches exactly.

**Pass criteria:** decryption succeeds regardless of which extra chunks were
present in the original WAV. If the parser assumed `data` is always the second
chunk, it would throw `WAV_MALFORMED` at step 4 instead.

**Note on bit depth and noise:** the implementation embeds 1 bit per *sample*,
always in the sample's least-significant byte (stride = bytesPerSample). For
16-bit PCM only bytes at even positions in the data chunk are touched; the high
byte is never modified. Noise stays at the ~-96 dBFS floor and is inaudible even
in very quiet passages. The output WAV should sound identical to the original.
If any audible difference is detected, report it — that would indicate a bug in
the stride logic.

---

## 6. Fallback carrier round-trip (Milestone 5d)

**Why it exists:** the fallback appender is a different code path with no
steganography. The host file must survive intact at its start, the payload must
be recoverable, and the tool must make unmistakably clear to the user that this
mode is not hidden.

**Steps:**

1. Open the tool. Encrypt a short text message. Select *Output → Append to any
   file (Tier 3 — attached, findable)*. Load any file — a PDF, a JPEG, a text
   file, anything.
2. Click *Encrypt*. Download the output file.
3. Open the output file in its native application (e.g. the PDF reader). Confirm
   it opens and displays normally — the appended data must not break the host
   format's parser.
4. Inspect the output file in a hex editor. Confirm the last 8 bytes are
   `50 4C 4D 50 46 41 4C 4C` (PLMPFALL) and the payload is visible in plain
   bytes before them. This is the expected "findable" behaviour.
5. Reload the page. Select *Decrypt → Fallback carrier*. Load the output file.
   Enter the same password. Click *Decrypt*.
6. **Expected:** the original message is recovered.

**Negative check:**

7. Select *Decrypt → Fallback carrier*. Load a plain file with no payload (the
   original host file before encryption). Click *Decrypt*.
8. **Expected:** error "No payload found in this file" — no crash, no garbage
   output.

---

## 4. Wipe / clear-data button (Milestone 5b)

**Why it exists:** the wipe is a best-effort cleanup of browser-held state. It
cannot be verified by inspecting return values alone — the check is whether the
expected storages are actually empty afterward.

**Steps:**

1. Open the tool. Decrypt something so plaintext is on screen. Load a keyfile
   so key material is in memory.
2. Open browser DevTools → Application tab. Note any entries under:
   - Local Storage
   - Session Storage
   - IndexedDB
   - Cache Storage
   (Palimpsest does not currently write to these, but third-party tooling might;
   confirm the stores are empty or note what is there.)
3. Click *Clear all data this tool created* in the footer bar. Confirm the modal.
4. **Expected:** the page reloads. All storage entries for this origin are gone.
   The decrypted plaintext is no longer visible. The keyfile state is gone.
5. Open DevTools → Memory tab → *Take heap snapshot*. Search for the password
   string you used. It **will** appear — JS strings are immutable and the engine
   may hold multiple copies across GC generations; the wipe cannot reach them.
   This is expected and is stated plainly in the UI. What the wipe does zero are
   the typed-array buffers holding keyfile bytes and the WebAuthn credential ID.
   Closing the browser tab (or the whole browser) is the stronger guarantee for
   string secrets.

**Inactivity timer:**

6. Open the tool. Expand *Settings & limits* in the footer. Set timeout to 1 minute.
7. Do not interact with the page for 1 minute.
8. **Expected:** the page reloads automatically without any user action.
9. Confirm the timer resets when you move the mouse or press a key.

**What the wipe cannot touch (verify these remain as claimed):**

- Browser HTTP cache: `index.html` is still served from cache after wipe.
- Browser history: the URL still appears in the history list.
- Address bar autocomplete: the URL still appears as a suggestion.
- Memory released to the OS before the wipe ran.
- Swap files or hibernation images captured before the wipe.
- Clipboard contents or files in the downloads folder.
