# Using vault-core in another application

vault-core is a security-format library, not the PaperSafeAI application or a
complete vault SDK. It provides inspectable formats, key handling and adapters
that another application can integrate under Apache-2.0. Read LICENSE, NOTICE,
SPEC.md and THREAT_MODEL.md before adopting it.

## Which repository is useful to you?

| Repository or branch | Purpose |
|---|---|
| `PaperSafeAI/vault-core` | Standalone library, specifications, adapters, tests and offline backup reader. Integrate this code or implement its documented formats. |
| PaperSafeAI app branch `niskumar/vault` | The closed-source app's integration with the library. It is not a public SDK or a dependency for your application. |
| `PaperSafeAI/vault-core-old` | Private historical archive. Not a dependency or part of the public distribution. |

Publication status at preparation time (2026-11-12): the fresh repository is
private and the npm package has not been published. Do not assume a public
clone or registry installation works until the release is announced. Authorized
source consumers can use the checked-out package now; once published, use its
reviewed release/tag and the `@papersafeailabs/vault-core` package name.

## What you can reuse

| Building block | Public entry point | Example use |
|---|---|---|
| Password/recovery-key wrapping and KDF schemes | Root `vaultUnlock`, `kdf`; `./kdf/auth-record` | Open a password-protected local vault and recover its vault key. |
| Per-document key generation/wrapping | Root `documentKey`; `./crypto/document-key` | Protect each document with its own key and bind the wrapped key to its vault/document identity. The app still implements body encryption/storage using the specified format. |
| Credential and sensitive-field sealing | Root `vaultCipher`; `./crypto/field-cipher` | Encrypt credential payloads or sensitive columns with authenticated record context. |
| Database key derivation | Root `dbKey`; `./crypto/db-key` | Derive the database encryption key; the consuming app supplies SQLCipher/database integration. |
| Encrypted backup envelopes and verified bundles | Root `backup`; `./backup` | Create portable encrypted backups or an independent reader. Persistence/transactional restore is still your application's job. |
| Catalogue key derivation and record sealing | Root `catalogKeys`, `catalogSeal`, `canonicalJson` | Encrypt and authenticate catalogue records exchanged between devices. |
| Pairing and transport security | Root `pairingTransport`, `responseBinding`; `./pairing/session` | Build authenticated paired-device communication, including replay/response-binding and session-key primitives. |
| Browser bridge cryptography | `./bridge` | Build compatible WebCrypto framing and session handling for an extension/desktop bridge. |
| Platform primitives | `./node`, `./platform/react-native` | Use the same formats in Node and React Native by supplying the supported crypto/compression libraries. |
| Formats and compatibility evidence | SPEC.md, types/, test-vectors/, test/ | Implement a reader in another language or verify a compatible adapter. A ready-made SDK for another language is not provided. |

The table names exported modules, not a promise of complete workflows. Refer
to the corresponding declaration in `types/` and its tests for argument types,
return values, failure handling and the precise adapter contract.

## What your application must provide

- Vault creation/identity, password/recovery UX, key persistence and OS secure
  storage; unlock/lock lifecycle, access policy and in-memory key handling.
- Stable IDs and record-type registration. Register your app-specific types
  through `aad.registerRecordTypes` before sealing/opening those records. Keep
  rules stable; conflicting registrations throw. Do not change registered
  meanings or derivation labels merely to rename your product.
- Backup layout configuration through `backup.configureBundle` where needed,
  filesystem I/O, free-space limits, atomic recovery/rollback and cleanup.
- Storage and database engines; vault-core derives/seals values but does not
  ship a complete database or secure every file created by your application.
- Network endpoints, device approval, identity-key persistence/pinning, nonce
  replay state, session lifecycle, concurrency and downgrade policy. The
  primitives do not by themselves create a secure sync service.
- Product sync behavior: change tracking, ordering, merges, conflict resolution,
  deletion handling and retry/offline behavior. Catalogue sealing is not a
  synchronization or CRDT engine.
- Native library setup and platform testing. The React Native adapter takes
  quick-crypto, Argon2 and compression implementations; they are not all bundled
  runtime dependencies. Pass streaming Gunzip for bounded phone decompression.

No UI, OCR, metadata extraction, semantic search, AI models, reminders,
licensing or billing is included.

## A practical integration sequence

1. Pin a reviewed source revision/release and read the relevant SPEC sections.
   For a source checkout, run `npm ci`, lint, tests, vectors and types checks.
2. Choose the Node or React Native adapter and install the native dependencies
   your selected operations require. Argon2-backed operations need Argon2.
3. Define your vault identity, record schema, persistence and lifecycle; supply
   the registered record contexts and backup layout before use.
4. Integrate one bounded workflow first: for example key wrapping, record
   sealing or a backup round-trip. Use synthetic fixtures and real adapters.
5. Verify tampering, wrong keys/passwords, malformed inputs, incorrect record
   binding, resource limits and failure/retry behavior on your target platforms.
6. For device transport, test the whole caller-managed handshake/replay/session
   policy, not only an encrypt/decrypt round-trip.
7. Plan migrations, patch delivery and security review before production use.

## Compatibility and support limits

- These are PaperSafeAI's existing, versioned formats. Product-specific HKDF
  labels/component names remain part of compatibility; they are not generic
  cryptographic recommendations for every product or protocol.
- The current document/credential wrappers accept suite 3, not suites 1/2.
  Backup compatibility is separately versioned; see SPEC §6. Do not assume
  arbitrary historical PaperSafeAI data or another app's archives are readable.
- The CLI opens a supported backup envelope/bundle without PaperSafeAI, but a
  recovered database/document blob may still be encrypted. Inspecting those
  requires the recorded keys, the right database cipher and document formats;
  it is not a universal plaintext-document export command.
- Native Windows CLI extraction is deliberately refused. macOS/Linux CLI
  output requires a private filesystem enforcing POSIX permissions. The Node
  crypto adapter's availability is separate from the CLI platform restriction.
- Backups are held in memory, with bounded decompression; a finite cap is not
  a guarantee that every phone has enough memory. Apply tighter application
  limits where necessary.
- Key overwriting in JavaScript is best effort. Read SPEC §12 for the remaining
  trust, legacy-transport, key-lifecycle and platform limits.
- No independent security audit has been completed. Tests, source visibility
  and reproducible vectors are evidence for review, not certification or proof
  that your consuming application is secure.

The strongest reason to adopt vault-core is its documented, inspectable
security formats and compatibility evidence. Adoption still requires an
application-specific security design and integration validation.
