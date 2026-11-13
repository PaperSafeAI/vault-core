# Threat model

What `@papersafeailabs/vault-core` protects, against whom, and what it assumes.
The formats are in [SPEC.md](SPEC.md); the trade-offs we know about are in
[SPEC.md §12](SPEC.md#12-known-limitations). If a claim here and the code
disagree, that is a bug: please report it ([SECURITY.md](SECURITY.md)).

## What is protected

| Asset | Where it lives | Protected by |
|---|---|---|
| Documents (scans, PDFs) | Encrypted files on the desktop and phone | A random key per document, wrapped under a key derived from the vault key (§5) |
| Saved passwords, cards, notes | Database rows | Two halves, each AES-256-GCM bound to vault, item and half (§4) |
| Document content and metadata | Database | SQLCipher under a key derived from the vault key (§3), and sensitive columns sealed again per row (§3) |
| The vault key | `auth.json` | Wrapped under Argon2id of the master password, and separately of the recovery key (§2) |
| Backups (`.psbak`) | Wherever the user keeps them | AES-256-GCM under Argon2id of a backup passphrase; header authenticated (§6) |
| Folder and collection sync | LAN between paired devices | Records sealed under catalogue keys bound to vault, record and generation (§7) |
| Phone ↔ desktop traffic | Local network | Pairing secret from a QR code; signed requests; bodies sealed under per-session X25519 keys that also need each device's pinned identity key (§8) |
| Browser autofill traffic | Same machine | ECDH session between a pinned extension key and the desktop (§9) |

## Who we defend against

**1. Someone who gets the files but not the password.** A stolen laptop or
phone, a copied data folder, a backup left on a shared drive, a cloud
provider holding the user's backup.
*Goal:* nothing readable without the master password, the recovery key or the
backup passphrase, and each guess costs one Argon2id run (64 MiB, t=3).
*Relies on:* the strength of the password the user chose.

**2. Someone on the same network.** A hostile or compromised Wi-Fi, another
device on the LAN, a recorder of traffic.
*Goal:* they cannot read, alter, replay or redirect sync traffic, and cannot
wipe a phone with a forged "revoked" notice. With protocol 8.2, traffic they
record stays unreadable even if they learn the pairing secret later.
*Not covered:* they can stop sync (drop packets, answer 409/404), and they can
see that two devices are syncing, how often and roughly how much.

**3. Someone who tampers with stored data.** Editing database rows, swapping
ciphertexts between items, documents, columns or vaults, editing a backup
header.
*Goal:* moved or altered ciphertext fails authentication rather than being read
as another item's data; altered backup headers make the archive refuse to open.
*Not covered:* rolling back to an older copy of the whole database or file.

**4. A crafted input.** A backup, QR code, sync body or bridge frame built to
crash or mislead the reader.
*Goal:* rejected with an error, never accepted as data; no path traversal on
restore; key-derivation cost bounded both ways. Tested with seeded fuzzing
(`test/fuzz.test.js`).

**5. Someone who learns the pairing secret** (a photo of the QR code, a copy
of either side's pairing row).
*Goal (8.2):* past sync sessions stay unreadable.
*Goal (8.3):* they cannot pose as either device, once that device's identity key
is pinned (from the QR code, or on first use), because sessions need the
device's identity private key, which never leaves it.
*Not covered:* a desktop with no OS keychain (8.2), and a pairing made before
8.3 whose secret had already leaked when the keys were first pinned.

## Out of scope

- **Malware running as the user, or with root, on an unlocked device.** It can
  read the screen, the keyboard and process memory. The Windows bridge pipe can
  be claimed by such a process before the desktop starts.
- **Someone who knows the master password, recovery key or backup passphrase.**
- **A user's device that was paired and copied the vault.** A password change
  re-wraps the vault key but does not replace it, so that copy stays readable
  by whoever holds the old password (SPEC.md §12).
- **The apps around this package**: UI, storage of the pairing secret,
  biometric prompts, the licensing service and the optional cloud reading
  service. They are closed source; the privacy policy lists every network
  connection they make (SPEC.md §10).
- **Side channels** (timing of AES or Argon2 in the platform libraries, power,
  electromagnetic). Signature and tag checks in this package compare in
  constant time; the primitives come from Node's OpenSSL,
  react-native-quick-crypto and WebCrypto.
- **Keys in JavaScript memory.** The code overwrites keys it is done with, but
  the runtime may have copied them.

## Trust boundaries

```
 user's password ──Argon2id──▶ wrapping key ──AES-GCM──▶ vault key
                                                           │ HKDF, one label each
          ┌──────────────┬────────────────┬────────────────┼──────────────┬─────────────┐
       database key   field key   document wrap key   credential key   catalogue keys
       (SQLCipher)    (columns)     → per-doc keys     → reuse/note      (sync records)
                                                         digests

 QR code ──pairing secret──▶ request signatures, session open ──X25519──▶ session keys (per sync)
 extension identity key (non-extractable) ──ECDH with desktop ephemeral──▶ bridge session key
 backup passphrase ──Argon2id──▶ archive key (independent of the vault key)
```

- Everything this package does runs on the user's own device. Nothing in it
  talks to a server.
- The platform supplies the primitives (an adapter: `src/node/`,
  `src/platform/react-native.js`). The package checks what it can about them:
  AES-GCM must bind associated data (a self-test before first use), nonces must
  be 12 bytes and tags 16, HKDF and HMAC outputs must have the right length.
- Inputs that cross a boundary — a backup file, a sync body, a QR code, a
  bridge frame, a stored row — are untrusted until authenticated.

## Assumptions

- The operating system's random number generator is sound.
- AES-256-GCM, HKDF-SHA256, HMAC-SHA256, SHA-256, Argon2id, X25519 and ECDH
  P-256 are implemented correctly by the platform libraries.
- A random 96-bit GCM nonce never repeats under one key in practice: the
  longest-lived keys (vault-derived keys, the pairing transport key) seal far
  fewer than 2³² messages.
- The QR code is seen only by the user pairing their own devices.

## Changes from the internal review (before the external audit)

- Backups: a path appearing twice in an archive is refused, and only files the
  manifest lists (and the integrity check verified) are ever written, by the
  CLI and both apps.
- Backups: Argon2id/scrypt parameters are bounded from above as well as below,
  so a crafted archive cannot hang the reader.
- Sync: per-session X25519 keys (protocol 8.2), so recorded traffic does not
  open with a pairing secret learned later; device identity keys (8.3), so
  the pairing secret alone no longer lets anyone pose as a device.
- Documentation of the bridge's one-sided forward secrecy, the vault key's
  lifetime and the backup decompression limit (SPEC.md §12).
- After an automated scan (2026-10-30): a path check that ran before `./` was
  dropped (`./C:/x`), backup decompression without a cap (now 8 GiB), the CLI
  showing the passphrase and writing into an existing directory, unescaped
  commit text in the CI sign-off check, and a temporary-directory race in the
  type check. All fixed, with tests.
