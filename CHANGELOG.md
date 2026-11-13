# Changelog

## 1.0.0

First public release. Before publication, the standalone CLI was hardened to
preserve split UTF-8 terminal input and restore terminal state on cancellation
or failure. Native Windows CLI extraction is explicitly refused until private
ACL handling is implemented; the encryption library remains platform-neutral.

 Everything PaperSafeAI uses to keep your data encrypted:

- the associated-data scheme every seal is bound to (`aad.js`);
- opening a vault: the Argon2id KDF schemes, wrapping keys, vault-key unwrap
  and recovery-key normalisation, and biometric unlock's hardware-wrapped blob;
- the database key and the encrypted database fields;
- credential and document encryption (cipher suite 3 only; older suites are
  refused), and the credential digests;
- the encrypted backup format (envelope v3, reads v2; bundle v1, reads v2),
  with floors and ceilings on the key-derivation cost an archive may ask for;
- catalogue sync record sealing;
- phone ↔ desktop pairing and transport, including response binding, sync
  sessions (X25519) and device identity keys;
- the browser extension ↔ desktop bridge;
- app-supplied names: record types are registered by the app
  (`registerRecordTypes`; the package registers only `credential` and
  `document_key`), and the bundle's database entry is set with
  `configureBundle`;
- backup decompression capped at 8 GiB (`MAX_EXPANDED_BACKUP_BYTES`); the
  React Native adapter enforces it when handed fflate's streaming `Gunzip`;
- Node and React Native adapters, test vectors with an independent reader, and
  the `papersafe-open-backup` tool.
