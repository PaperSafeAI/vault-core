# Audit scope

The brief for an independent security review of `@papersafeailabs/vault-core`.
Read it with [THREAT_MODEL.md](THREAT_MODEL.md) (what we claim to protect) and
[SPEC.md](SPEC.md) (every format, precise enough to reimplement).

## In scope

About 4,100 lines of JavaScript, no runtime dependencies except the optional
`argon2` package.

| Area | Files | Lines | What to look at |
|---|---|---|---|
| Vault unlock | `src/kdf/` | ~190 | Argon2id parameters from a fixed scheme table, never from the record; recovery-key handling |
| Vault-derived keys and record sealing | `src/crypto/` | ~1,090 | HKDF labels and their separation; the AAD builder (`aad.js`); cipher suite 3 and the refusal of anything older; document key wrapping; column cipher; biometric wrap |
| Backups | `src/backup/`, `bin/` | ~1,400 | Envelope v2/v3, header AAD, KDF bounds, bundle v1/v2 parsing, path handling on restore, the offline CLI |
| Catalogue sync sealing | `src/sync/catalog/` | ~370 | Canonical JSON (strict parser and encoder), catalogue keys, record sealing |
| Phone ↔ desktop transport | `src/pairing/` | ~520 | Pairing QR, request signatures and replay rules, body sealing, response binding, X25519 sync sessions |
| Browser bridge | `src/bridge/` | ~180 | WebCrypto ECDH P-256 session, frame AAD, sequence and time checks |
| Platform adapters | `src/node/`, `src/platform/` | ~290 | That each primitive is used correctly: GCM nonce/tag length checks, AAD passed through, raw X25519 key import |

Weaknesses in a format itself are in scope even when the code implements it
faithfully.

## Optional extension (app code that calls the package)

If budget allows, the places where the closed-source apps call the session and
restore code. We give the auditor read access to the files for this part:

- the desktop's sync service: how it picks keys per request and keeps sessions;
- the phone's sync client: how it opens sessions, pins them and refuses a
  downgrade;
- the desktop's and the phone's restore: what a restore writes, and where.

## Out of scope

The apps' UI, the licensing service, the optional cloud reading service, the
native helpers (Secure Enclave, Windows Hello, OCR), the platform crypto
libraries themselves, and denial of service by someone on the same network.

## How to run it

Node 22 or later.

```sh
npm ci                 # the locked versions, incl. argon2 (prebuilt) for the Argon2id tests
npm run lint           # ESLint
npm test               # unit tests, fuzz suite, independent vector reader
npm run vectors:check  # fails if any format changed
npm run types:check    # declarations match src/
```

- `test-vectors/vault-core-v1.json` holds fixed inputs and the exact output
  bytes of every format. `test/test-vectors.test.js` opens all of them with only
  `node:crypto`, written from SPEC.md rather than from the package's code.
- `test/fuzz.test.js` is seeded: `FUZZ_SEED=<n> FUZZ_CASES=<n> npx vitest run test/fuzz.test.js`.
- `bin/papersafe-open-backup.js` opens a backup offline.

## Questions we would most like answered

1. **Key separation.** Is every HKDF use from the vault key (database, fields,
   document wrapping, credentials, catalogue, thumbnails) separated by its
   salt/info pair, and does any key ever serve two purposes?
2. **AAD.** Is canonical JSON injective as used in `aad.js`, and can any two
   record contexts produce the same AAD?
3. **Older formats.** Suites 1 and 2 are not read at all. Can an attacker who
   can write a database row get any other format, or a relabelled one,
   accepted where suite 3 is expected?
4. **Backups.** Can a crafted archive escape the restore directory, have one
   set of bytes verified and another used, or make the reader run unbounded
   work before the passphrase is checked?
5. **Sync sessions (§8).** Is the X25519 handshake sound as specified: transcript
   binding, low-order points, reflection between directions, replay of an open
   or of its answer, downgrade from a pinned phone, and what a stolen pairing
   secret allows? With identity keys (version 2): is the three-exchange
   schedule sound, is trust on first use for existing pairings acceptable, and
   can a pinned key be replaced or bypassed?
6. **Request signing.** Are signature, timestamp window and nonce replay rules
   enough to stop a captured request being reused on another route or later?
7. **Bridge (§9).** Given that the desktop has no identity key, what can a
   same-machine attacker do that is not already listed in SPEC.md §12?
8. **Adapters.** Any misuse of Node `crypto`, react-native-quick-crypto or
   WebCrypto: GCM tag length, nonce generation, key import, buffer aliasing.

## What we already know

SPEC.md §12 lists the limitations we have chosen or not yet fixed. Please do
not spend time re-deriving those, but do tell us if one is worse than we say.

An internal review before this audit changed: duplicate paths in a backup are
refused; only manifest-listed (verified) files are written on restore; KDF
parameters are bounded from above; sync gained per-session keys. See
[THREAT_MODEL.md](THREAT_MODEL.md#changes-from-the-internal-review-before-the-external-audit).

## What we would like back

- Findings with severity, a reproduction or argument, and a suggested fix.
- A short public summary we can publish with the report and link from the
  README, after fixes ship.
- A retest of the fixes.
