# PaperSafeAI vault-core — format specification

Version 1 · covers vault-core 1.x · normative

This document describes every place PaperSafeAI turns your data into
ciphertext, precisely enough to write an independent implementation. The code
in `src/` is the implementation the app runs; `test/test-vectors.test.js`
re-implements each section below with nothing but `node:crypto` and checks it
against [`test-vectors/vault-core-v1.json`](test-vectors/vault-core-v1.json). If
this document and the code ever disagree, that test fails.

Conventions: AES-256-GCM always uses a 12-byte random nonce and a full 16-byte
tag (shorter tags are refused). HKDF is HKDF-SHA256 (RFC 5869). Strings are
UTF-8. `||` is byte concatenation.

## 1. Model

- **Your vault lives on your devices, and PaperSafeAI runs no server that stores
  it.** The vault lives on your desktop; a paired phone holds a replica; both
  talk directly over your local network. The one opt-in exception, phone cloud
  reading, is described in §10.
- **Everything hangs off one random 32-byte vault key.** It is generated on the
  device when the vault is created, is never derived from your password, and is
  stored only wrapped (encrypted) under keys derived from your master password
  and from your recovery key. Each use gets its own key derived from it (§3–§5).
- **Ciphertext is bound to its place.** Every seal carries associated data
  (AAD) naming the vault, the kind of record, the record and, where a record has
  several, the part. A value copied to another row, another half of a row,
  another record type or another vault fails authentication instead of
  decrypting.
- **Formats are versioned and self-describing.** A reader that meets a version
  it does not know refuses with "update the app"; it never guesses.

What this protects against: theft of the device's disk or of a backup file,
someone with the database file but not your password, tampering with stored
rows. What it does not: malware running as you while the vault is unlocked, or
a weak master password (the KDF slows guessing; it cannot make a guessable
password safe).

### Associated data

([`src/crypto/aad.js`](src/crypto/aad.js).) The AAD for every seal under a key
derived from the vault key is the canonical JSON — keys sorted, no whitespace,
strict string escaping ([`src/sync/catalog/canonical-json.js`](src/sync/catalog/canonical-json.js)) — of

```
{ component, vaultId, recordType, primaryKey, part?, generation? }
```

- `component` — the scheme and its version: `vault-v3` (vault data, cipher
  suite 3) or `catalogue-v1` (§7).
- `vaultId` — the vault's identity, a UUID stored inside the encrypted database,
  so every copy of a vault (pairing snapshot, backup) carries the same one.
- `recordType` — a name registered for the component: this package registers
  `credential` and `document_key`; the app registers its own (its encrypted
  columns and catalogue records) with `registerRecordTypes`, which fixes each
  name's rule (parts, generation) and refuses to change it.
- `primaryKey` — the record's key, a non-empty array of non-empty strings.
- `part` — only for records with several parts (a credential's `open` and
  `secret` halves); forbidden otherwise.
- `generation` — only for catalogue history records; forbidden otherwise.

Canonical JSON is injective and optional fields are present or absent, never
empty, so two AADs are equal only when every field is equal. An unknown
component, record type or part is a programming error and throws. Before its
first seal, the code checks that the platform's AES-GCM really binds AAD.

## 2. Master password → vault key

Scheme `argon2id-v1` ([`src/kdf/vault-kdf.js`](src/kdf/vault-kdf.js)):
Argon2id, time cost 3, memory 64 MiB (65536 KiB), parallelism 1, 32-byte output.

At vault creation:

```
vaultKey        = random(32)
passwordSalt    = random(16)
passwordKey     = Argon2id(password, passwordSalt)               # 32 bytes, raw
wrappedByPwd    = AES-256-GCM(key=passwordKey, nonce=random(12), plaintext=vaultKey)   # no AAD
recoveryKey     = random recovery code shown once to the user
recoverySalt    = random(16)
recoveryDerived = Argon2id(recoveryKey, recoverySalt)
wrappedByRecov  = AES-256-GCM(key=recoveryDerived, nonce=random(12), plaintext=vaultKey)
```

The auth record stores the salts, the wrapped keys (`encrypted`, `iv`, `tag`),
an Argon2id verifier of the password, and `kdfScheme` + `kdfParams`, so a later
cost increase is a new scheme id applied on the next successful unlock, never a
reinterpretation of an existing file.

**Unlock** ([`src/kdf/auth-record.js`](src/kdf/auth-record.js)):

```
params      = KDF_SCHEMES[record.kdfScheme ?? "argon2id-v1"]     # unknown id → refuse: "update the app"
wrappingKey = Argon2id(secret, base64decode(salt), params)          # raw 32 bytes
vaultKey    = AES-256-GCM-open(wrappingKey, iv, encrypted, tag)     # wrong secret → tag fails
```

The parameters always come from the record, never from the reader's defaults,
so an old vault keeps opening after a cost increase and a tampered record
cannot ask for a weaker one than any scheme defines. The GCM tag is what
proves the secret right; the recovery path deliberately does not consult
`recoveryHash` first, so there is no second oracle to probe. A recovery key is
read the way people retype it: everything but its 24 hex digits is ignored,
and it is derived over the canonical `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` form.
The app keeps its failed-attempt lockout around this.

**Biometric unlock** ([`src/crypto/hardware-wrap.js`](src/crypto/hardware-wrap.js)).
Touch ID or Windows Hello does not unlock a stored copy of the vault key. The
vault key is wrapped under a secret that only the device's security hardware
can produce, and only after a live fingerprint or face check:

```
challenge   = random(32)                                   # stored
secret      = hardware(challenge)                          # never stored; see below
salt        = random(32)
wrappingKey = HKDF-SHA256(ikm=secret, salt, info="papersafeai-vault-key-wrap-v1", L=32)
blob        = { version: 1, provider, challenge, salt, iv, tag, ciphertext = AES-256-GCM(wrappingKey, iv, vaultKey) }
```

On Windows the secret is a Windows Hello RSA PKCS#1 v1.5 signature of the
challenge (deterministic by construction). On macOS it is
`SHA-256(storedSecret || challenge)`, where `storedSecret` is random bytes in a
Keychain item that releases them only after a biometric check against the
currently enrolled fingerprints. The blob opens nothing on its own, and it stops
opening if the enrolled fingerprints change; the master password is then
needed again.

A separate random 32-byte **credential master key** is wrapped the same two
ways. It is deliberately random rather than derived from the vault key, so a
stored password's secret half cannot be decrypted from session state alone.

## 3. Database key

The desktop's SQLite database is encrypted with SQLCipher under:

```
dbKey = HKDF(ikm=vaultKey, salt="papersafeai:db-key", info="papersafeai:db-key:v1", L=32)
```

[`src/crypto/db-key.js`](src/crypto/db-key.js). Passed to SQLCipher as a raw hex key.

**Encrypted fields** ([`src/crypto/field-cipher.js`](src/crypto/field-cipher.js)).
Columns the app chooses (the most sensitive ones) are encrypted a second time
inside that database, each with its own registered record type:

```
fieldKey = HKDF(ikm=vaultKey, salt="papersafeai:local-vault", info="papersafeai:field-cipher:v3", L=32)
AAD      = §1 { component:"vault-v3", vaultId, recordType:<one per column>, primaryKey:<the row's key> }
stored   = "\x00pse\x03" || b64(iv) || "." || b64(tag) || "." || b64(AES-256-GCM(fieldKey, iv, utf8(value), AAD))
```

A value copied to another row, column or vault fails its tag. A non-empty value
without the `\x00pse` marker is refused rather than read as plaintext, and so
is any other version byte, including an old `\x00pse\x01` value (raw vault
key, no AAD): only suite 3 is read.

## 4. Stored credentials (cipher suite 3)

Each credential row is split into an **open** half (username, URL — what
autofill matches on) and a **secret** half (password, notes).

```
openKey   = HKDF(ikm=vaultKey, salt="papersafeai:local-vault", info="papersafeai:credentials:v1", L=32)
secretKey = credential master key (§2)
AAD       = §1 { component:"vault-v3", vaultId, recordType:"credential", primaryKey:[itemId], part:"open"|"secret" }
nonce     = random(12)
stored iv = 0x03 || nonce                              # 13 bytes; 0x03 = suite 3
```

`ciphertext` and `tag` are stored in their own columns
([`src/crypto/vault-cipher.js`](src/crypto/vault-cipher.js)). Only suite 3 is
read: an older iv (12 bytes for suite 1, `0x02 || nonce` for suite 2) is refused
as "an older format this build no longer reads", and any other shape as "update
the app".

Two digests let the app work with saved passwords without decrypting them
([`src/crypto/credential-keys.js`](src/crypto/credential-keys.js)). Both sit in
the open half, so any unlocked session can read them:

```
reuseKey        = HKDF(ikm=openKey, salt="papersafeai:credentials:reuse-digest", info="papersafeai:credentials:v1", L=32)
passwordDigest  = hex(HMAC-SHA256(reuseKey, utf8(password)))          # equal passwords → equal digest, in this vault only
noteIndexKey    = HKDF(ikm=openKey, salt="papersafeai:credentials:note-index", info="papersafeai:credentials:v1", L=32)
noteTokenDigest = hex(HMAC-SHA256(noteIndexKey, utf8(lowercase(word))))[0..12]   # per word of a secure note, ≥ 3 chars, at most 120
```

The labels sit in the salt position, the reverse of the usual HKDF convention;
that is how every existing vault was written. The note digests let notes be
searched by word without storing the words, at the cost of showing how many
distinct words a note has and letting an unlocked session test a guessed word.

## 5. Documents

Every document has its own random 32-byte **document key** (DEK); the document
bytes are AES-256-GCM under it. The DEK is stored wrapped
([`src/crypto/document-key.js`](src/crypto/document-key.js)):

```
wrapKey    = HKDF(ikm=vaultKey, salt="papersafeai:local-vault", info="papersafeai:document-key-wrap:v3", L=32)
AAD        = §1 { component:"vault-v3", vaultId, recordType:"document_key", primaryKey:[documentId] }
wrappedDek = base64( 0x03 || nonce(12) || tag(16) || AES-256-GCM(wrapKey, nonce, DEK, AAD) )
```

A leading `0x01` or `0x02` (older wraps under the raw vault key) is refused, as
is a document with no wrapped key at all: only a suite-3 wrap opens. The phone's
thumbnail cache is sealed the same way under
`HKDF(vaultKey, "papersafeai:local-vault", "papersafeai:thumbnail-cache:v1")`
with a record type the app registers for it.

## 6. Encrypted backups (`.psbak`, envelope v3)

A backup is a JSON envelope around the whole vault (database + document blobs),
sealed under a key derived from a **backup passphrase** you choose.

```json
{
  "format": "papersafe-encrypted-backup-v3", "version": 3,
  "createdAt": "<ISO>", "fileCount": 42, "totalBytes": 12345678,
  "kdf":    { "name": "argon2id", "timeCost": 3, "memoryCost": 65536, "parallelism": 1, "keyLength": 32, "salt": "<b64 16B>" },
  "cipher": { "name": "aes-256-gcm", "iv": "<b64 12B>", "tag": "<b64 16B>", "aad": "header-v1" },
  "ciphertext": "<b64 of AES-256-GCM(gzip(bundle))>"
}
```

- Key: Argon2id(passphrase, salt) with the parameters **recorded in the file**,
  after checking them against a minimum (time ≥ 2, memory ≥ 32 MiB) so a
  tampered file cannot make the reader do less work, and against a maximum
  (time ≤ 10, memory ≤ 256 MiB, parallelism ≤ 4, key length exactly 32; scrypt
  N ≤ 2^18, r ≤ 8, p ≤ 4) so a crafted file cannot make the reader hang or run
  out of memory before the passphrase is tried. No PaperSafeAI build has
  written an archive outside these bounds.
- AAD (v3): these fields joined with a NUL byte, in this order: `"header-v1"`,
  format, version, createdAt, fileCount, totalBytes, kdf.name, kdf.salt,
  kdf.timeCost, kdf.memoryCost, kdf.parallelism, kdf.keyLength, cipher.name,
  cipher.iv. Editing any header byte makes the archive fail to open.
- The bundle inside is either v1 (JSON with each file base64-encoded, what is
  written today) or v2 (a magic prefix, a 4-byte header length, a JSON header,
  then the files' raw bytes in manifest order — read today, written later). Its
  manifest lists each file's size and SHA-256; every file is checked before a
  restore touches anything.
- Decompression stops at 8 GiB of output (`MAX_EXPANDED_BACKUP_BYTES`), enforced
  while inflating, not read from the archive.
- File paths are relative: a path that is absolute, has a drive (`C:`), a `:`
  or a NUL in any part, or a `..` part is refused, checked after `.` and empty
  parts are dropped.
- v2 envelopes (scrypt, no AAD) remain readable forever.

[`src/backup/`](src/backup/). The CLI `papersafe-open-backup` opens one without the app,
into a new owner-only directory it creates (an existing one is refused), creating
each file exclusively, and reads the passphrase without echoing it.

## 7. Phone ↔ desktop catalogue sync

Folder and collection records sent between paired devices are sealed with keys
derived from the vault key, which both devices hold:

```
key(label) = HKDF(ikm=vaultKey, salt="papersafe/catalogue", info=label, L=32)
labels     : "payload/v1" (record encryption), "name-index/v1" (HMAC name index),
             "receipt-digest/v1" (desktop only)
envelope   = 0x01 || nonce(12) || tag(16) || AES-256-GCM(key=payload key, plaintext=canonicalJSON(value), AAD)
AAD        = §1 { component:"catalogue-v1", vaultId, recordType, primaryKey[, generation] }
```

([`src/sync/catalog/`](src/sync/catalog/).) Names are looked up by HMAC under
the name-index key, so the index reveals no names.

Those sealed records travel inside the request and response bodies of §8.

## 8. Pairing and phone ↔ desktop transport

A phone is paired by scanning a QR code on the desktop. The QR carries a fresh
random 32-byte **pairing secret**; it never crosses the network, so someone on
the same Wi-Fi who did not see the screen cannot learn it.

```json
{ "v": 2, "id": "<device id>", "secret": "<64 hex>", "fp": "<32 hex>", "ip": "<desktop LAN IP>", "port": 39501 }
```

```
transportKey = HMAC-SHA256(key=secret, "papersafe-transport-v2")
fingerprint  = hex(HMAC-SHA256(key=secret, "papersafe-fp-v1"))[0..32]   # advertised over mDNS; reveals nothing of the secret
```

The desktop refuses a pairing that is not completed within its invitation
window, and a revoked phone erases its copy only when the revocation notice
authenticates under its own transport key (so a hostile network cannot wipe
it).

**Every request is signed** with the pairing secret:

```
Authorization: PapersafeHMAC ts=<unix seconds>,nonce=<32 hex>,sig=<64 hex>,id=<device id>[,inst=<install id>]
sig = HMAC-SHA256(key=secret,
        "PSHMAC-v3\n" || METHOD || "\n" || path+query || "\n" || ts || "\n" || nonce || "\n" || hex(SHA-256(body)))
```

The signature binds the method, exact target and body, so a captured header
cannot be replayed onto another route. The desktop compares it in constant
time, refuses a `ts` outside its window, and refuses any nonce it has already
seen (remembered across restarts). `inst` names the phone install so the desktop
can tie a pairing to the first install that uses it; it is outside the
signature and is not a security boundary.

**Every body**, both directions, is sealed under the transport key:

```
body = nonce(12) || tag(16) || AES-256-GCM(key=transportKey, nonce, plaintext[, AAD])
```

with no AAD, except where the phone asks for **response binding**: a desktop
that advertises `capabilities.responseBinding: 1` and receives
`x-papersafe-bind: 1` seals that request's answer with

```
AAD = "psai-resp-v1\n" || METHOD || "\n" || path+query || "\n" || nonce     # the request's HMAC nonce
```

so a recorded answer cannot be replayed to a different request. The signature
covers the sealed bytes, as sent. A fresh random nonce is used for every body; a
nonce must never repeat under one transport key.
([`src/pairing/transport.js`](src/pairing/transport.js),
[`src/pairing/response-binding.js`](src/pairing/response-binding.js).)

### Sync sessions (forward secrecy)

A desktop that advertises protocol feature `sessionKeys` (protocol 8.2) runs a
fresh X25519 exchange (RFC 7748) before a sync, so a body recorded on the
network stays unreadable even if the pairing secret leaks later.

```
phone   → POST /session/open      {"v":1,"pub":"<hex E_p>"}         # signed and sealed as above, response binding asked
desktop → {"v":1,"id":"<hex sessionId(16)>","pub":"<hex E_d>","expiresIn":<seconds>}
                                     # sealed under transportKey with the request's response-binding AAD

shared = X25519(e_p, E_d)            # refused if the exchange fails or yields all zeros
th     = SHA-256("psai-sess-v1\n" || fingerprint || "\n" || deviceId || "\n" || hex(sessionId) || "\n" || hex(E_p) || "\n" || hex(E_d))
k_p2d  = HKDF-SHA256(ikm=shared, salt=th, info="papersafe-session-v1 phone->desktop", 32)
k_d2p  = HKDF-SHA256(ikm=shared, salt=th, info="papersafe-session-v1 desktop->phone", 32)
```

Both sides drop the ephemeral private keys once the keys exist and keep the
session in memory only. Every later request, except the few the app must
answer without a session (liveness, the version handshake, the hello and the
open itself), carries `x-papersafe-session: <hex sessionId>`; it is
**still signed with the pairing secret** exactly as above. Its body is sealed
under `k_p2d` (no AAD; the signature already binds it to the request) and the
answer under `k_d2p` with

```
AAD = "psai-resp-v2\n" || METHOD || "\n" || path+query || "\n" || nonce || "\n" || hex(sessionId)
```

Two directional keys mean a request can never be reflected back as an answer.
The desktop drops a session after 15 minutes unused or an hour in all, and on
lock, unpair and restart; a request naming an unknown session gets
a plain-JSON `409 {"code":"session_expired"}` (forging one only makes the phone
open a new session), and the phone opens a new one. A phone that has once seen `sessionKeys` from a desktop refuses to
sync with it without a session (a downgrade). Protocol 9 will make sessions
mandatory. ([`src/pairing/session.js`](src/pairing/session.js); vectors in
`pairingSession`.)

**Device identity keys (session version 2, protocol 8.3 `identityKeys`).** Each
device keeps a long-term X25519 identity key: the phone in its Keychain /
Keystore (this device only), the desktop one per install, sealed by the OS
keychain outside the vault folder (so no database copy or backup holds it). A
desktop with no keychain has none and offers 8.2. Each side pins the other's
public key: the phone from a v3 QR code (`"spk": "<64 hex>"`, so even the
first contact is authenticated) or at its first identity session; the desktop
at the phone's first identity session after the user allowed the pairing.
Both refuse any other key from then on, and a pinned desktop refuses a
version-1 open. The open carries both keys and the keys need all three
exchanges:

```
phone   → {"v":2,"pub":"<hex E_p>","spk":"<hex S_p>"}
desktop → {"v":2,"id":"<hex sessionId>","pub":"<hex E_d>","spk":"<hex S_d>","expiresIn":<seconds>}

ikm   = X25519(e_p, E_d) || X25519(s_p, E_d) || X25519(e_p, S_d)     # each refused if it fails or is all zeros
th    = SHA-256("psai-sess-v2\n" || fingerprint || "\n" || deviceId || "\n" || hex(sessionId) || "\n"
                || hex(E_p) || "\n" || hex(E_d) || "\n" || hex(S_p) || "\n" || hex(S_d))
k_p2d = HKDF-SHA256(ikm, salt=th, info="papersafe-session-v2 phone->desktop", 32)
k_d2p = HKDF-SHA256(ikm, salt=th, info="papersafe-session-v2 desktop->phone", 32)
```

Someone holding the pairing secret but not a device's identity private key
derives other keys, so its first sealed body fails to open. The first exchange
is ephemeral on both sides, so forward secrecy is unchanged. A desktop that
pinned another phone key answers `409 {"ok":false,"code":"identity_mismatch"}`
under the transport key, bound to the request; the phone tells the person to
pair again. Vectors in `pairingSession.identity`.

## 9. Browser extension ↔ desktop bridge

The browser extension talks to the desktop app on the same machine through
native messaging and a local socket (no network port). Each message is
end-to-end encrypted between the extension and the desktop, so the messaging
shim in between only ever sees ciphertext. The browser never holds vault keys:
this protects the channel, and each autofill still needs the vault unlocked and
the user's consent on the desktop.

- **Identity.** The extension generates a non-extractable ECDH P-256 key pair
  once and keeps it in IndexedDB. Its fingerprint is
  `hex(SHA-256(raw uncompressed public key))`.
- **Pairing.** On first contact the desktop asks the user to approve that
  fingerprint and pins it. A different or modified extension has a different
  key and needs a new approval.
- **Session.** The extension sends its public key and a random nonce. The
  desktop answers with a fresh ephemeral P-256 key and its own random nonce,
  so a stored-key compromise on the desktop cannot open past sessions. The
  extension side is not ephemeral: its identity key takes part in every
  session (see §12).

```
shared     = ECDH-P256(extension identity key, desktop ephemeral key)
sessionKey = HKDF-SHA256(ikm=shared, salt=clientNonce || serverNonce, info="papersafeai-bridge-v1", L=32)
frame      = { "t": "enc", "seq": n, "iv": b64(random 12), "ct": b64(AES-256-GCM(sessionKey, iv, plaintext, AAD) || tag16) }
AAD        = "papersafeai-bridge-v1|" || direction || "|" || seq          # direction: "c2s" or "s2c"
plaintext  = JSON { "payload": <message>, "ts": <ms since epoch> }
```

The receiver accepts only the next sequence number for that direction (no
replay, no reordering, no reflecting a frame back to its sender) and rejects a
`ts` more than 60 seconds from its clock. Both handshake messages carry
`protocolVersion` and `minSupportedProtocol` (version 2 adds an optional `pro`
flag to the handshake reply; frames are unchanged); a peer that is too old is
told to update. [`src/bridge/bridge-crypto.mjs`](src/bridge/bridge-crypto.mjs) —
WebCrypto only, so the same file runs in the desktop and in the extension's
service worker.

## 10. Network behaviour

Nothing in this package opens a network connection. The apps that use it keep
the vault on the user's devices; phone sync goes directly between paired
devices on the local network (§8). Which services the apps contact, when, and
what they send is listed in PaperSafeAI's privacy policy, including the one
opt-in path that sends document content off the device (phone cloud reading:
the pages the user chooses to send, and nothing else). To check the apps
yourself, run them with networking switched off, or watch their connections
with a tool such as Little Snitch, LuLu or Wireshark.

## 11. Versioning

Every format above carries a version (a leading byte, an `iv` length, a scheme
id, an AAD component or an envelope `version`). Changing a format means a new
version that old readers refuse loudly, while new readers keep reading the old
one. The test vectors are regenerated only for a new version, never edited in
place.

## 12. Known limitations

These are trade-offs we know about and have chosen, or not yet fixed. They are
listed so you do not have to find them.

- **No independent audit yet.** The formats and code have been reviewed
  internally only.
- **The app builds are not verifiable.** The apps are closed source and their
  builds are not reproducible; see the README.
- **Forward secrecy depends on both apps being current (§8 (sync sessions)).** Sync
  sessions give each sync fresh X25519 keys, but until protocol 9 a desktop
  that predates them still syncs under the pairing's one fixed key, and the
  version handshake and hello always do (they carry versions and licence state,
  not documents). The pairing secret alone no longer lets anyone pose as a
  device once identity keys are pinned (8.3), but until then, and with a
  desktop that has no OS keychain (8.2), it still does. A pairing made before
  8.3 pins each side's key on first use, so whoever already held the secret
  at that moment could pin theirs instead. Outside a session (the handshake
  and hello, and everything sent to an 8.0 or 8.1 desktop) binding an answer
  to its request is still opt-in; inside a session every answer is bound.
- **A reinstalled or restored phone must pair again.** Its identity key stays
  on the device it was made on, so a desktop that pinned the old key refuses
  the new one. The same holds for a desktop whose keychain item is lost.
- **The transport key is `HMAC-SHA256(secret, label)`, not HKDF.** HMAC is a
  PRF and the secret is 32 uniformly random bytes, so this is sound; it is kept
  because both apps in the field derive it this way.
- **The wrapped vault key carries no associated data (§2).** It is not bound to
  its record or scheme. That is enough because nothing in the record can make
  the unwrap weaker or point it elsewhere: the KDF parameters come from a fixed
  table by scheme id, never from the record, and an unknown id is refused (so
  editing the id cannot lower the cost); the salt and nonce only change which
  key is derived, and a wrong one fails the GCM tag. Someone able to rewrite
  `auth.json` can swap in a different vault's record entirely, which AAD would
  not prevent either; the result opens only with that other vault's password.
- **Backup passphrases need only 10 characters (§6), and nothing checks their
  strength.** The same rule gates restore, so raising it would lock people out
  of backups they already hold. Neither this library nor the apps judge a
  passphrase beyond its length today, so a 10-character dictionary phrase is
  accepted; each guess still costs one Argon2id run (64 MiB, t=3).
- **Secure-note search leaks a little (§4).** Each indexed word is a 48-bit
  keyed digest in the open half of the row. An unlocked session can count the
  distinct words in a note and test whether a guessed word is in it.
- **The browser bridge is forward secret on the desktop side only (§9).** The
  extension's identity key (non-extractable, but usable by code running inside
  the extension) takes part in every session, so such code plus recorded frames
  could recompute past session keys. The desktop has no identity key of its
  own: the extension relies on the operating system (the registered native
  messaging host, a socket only the user can open) to know it reached the real
  desktop. On Windows the named pipe can be claimed first by another process of
  the same user; same-user malware is outside this design's protection.
- **One vault key for life.** Every key in §2–§8 derives from the vault key,
  which a password change re-wraps but never replaces. A device that once held
  it can read whatever it copied, and a password reset does not revoke that.
- **A backup is held in memory whole.** Decompression is capped at 8 GiB (§6),
  so a crafted archive cannot expand without bound, but a device with less
  memory than an archive's real size cannot open it. On the phone the cap
  applies when the app hands the adapter fflate's streaming `Gunzip`.
- **Keys live in JavaScript memory.** The code overwrites keys it no longer
  needs, but a JavaScript runtime may have copied them; this cannot be
  guaranteed.
- **This is not a general-purpose library.** It encodes PaperSafeAI's formats,
  with app-supplied table and record names registered by the caller.

