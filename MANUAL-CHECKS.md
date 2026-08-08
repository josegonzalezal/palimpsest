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
   or plaintext string you used. It should not appear in live string objects
   (note: it may still appear in the snapshot infrastructure itself; that is
   acceptable).

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
