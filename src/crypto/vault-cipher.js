'use strict';

/**
 * The vault's symmetric-encryption constants and the credential framing, in ONE
 * place for both platforms.
 *
 * Before this file the desktop and the phone each hand-typed the HKDF salt and
 * info that derive the credential open-payload key, and each wrote its own
 * "encrypt the JSON, return ciphertext/iv/tag" helper. Two statements of a
 * format drift silently: a one-character difference in a salt produces a key
 * that opens nothing, and nothing says why. Both apps now import these.
 *
 * ## Cipher suite 3: ciphertext is bound to its vault, record and part
 *
 * Every AES-GCM seal of vault data carries Associated Data naming WHERE the
 * ciphertext belongs, built by the app-wide builder (./aad.js) — the same
 * scheme the catalogue uses:
 *
 *   credential open half    { component:'vault-v3', vaultId, recordType:'credential',   primaryKey:[itemId], part:'open' }
 *   credential secret half  { component:'vault-v3', vaultId, recordType:'credential',   primaryKey:[itemId], part:'secret' }
 *   wrapped document key    { component:'vault-v3', vaultId, recordType:'document_key', primaryKey:[documentId] }
 *                           (./document-key.js)
 *
 * A ciphertext moved to another item, the other half, another record type or
 * ANOTHER VAULT — even one holding the same key material — fails its tag check.
 *
 * History: suite 1 bound nothing (a half copied onto any item decrypted).
 * Suite 2 bound the item with hand-built strings but not the vault or a record
 * type in a shared namespace. Suite 3 replaces both with the one builder, and
 * wraps document keys under a dedicated HKDF key instead of the raw vault key
 * (document-key.js).
 *
 * ## Only suite 3 is readable
 *
 * A credential half's `iv` column is 13 bytes, [0x03][nonce]; a wrapped
 * document key's leading envelope byte is 3. Suites 1 and 2 are not read at
 * all: there is no older reader, no upgrade path and no "try the current
 * suite, fall back to an older one", so an older, weaker-bound ciphertext put
 * in a row is refused like any other unknown format.
 */

const { buildAad, assertBindsAad, COMPONENT_VAULT } = require('./aad');

// ── Key derivation constants (ON-DISK FORMAT — never change) ────────────────
//
// Baked into every credential row ever written: the open half is sealed under
// HKDF-SHA256(vaultKey, CREDENTIAL_KEY_SALT, CREDENTIAL_KEY_INFO, 32). The `v1`
// is the KEY's version, not the cipher suite's: the key did not change in
// suites 2 or 3, only what the seal is bound to.
const CREDENTIAL_KEY_SALT = 'papersafeai:local-vault';
const CREDENTIAL_KEY_INFO = 'papersafeai:credentials:v1';

/**
 * The phone's thumbnail-cache key: HKDF-SHA256(vaultKey, CREDENTIAL_KEY_SALT,
 * THUMBNAIL_KEY_INFO). Before suite 3 the cache was sealed under the raw vault
 * key with no AAD; the cache is disposable, so old files simply fail to open
 * and are regenerated.
 */
const THUMBNAIL_KEY_INFO = 'papersafeai:thumbnail-cache:v1';

/**
 * The column cipher's key (./field-cipher.js):
 * HKDF-SHA256(vaultKey, CREDENTIAL_KEY_SALT, FIELD_KEY_INFO). Before suite 3
 * those columns were sealed under the raw vault key with no AAD.
 */
const FIELD_KEY_INFO = 'papersafeai:field-cipher:v3';

// ── Cipher suite number ──────────────────────────────────────────────────────
/** Vault-, record- and part-bound through ./aad.js. The only suite read or written. */
const CIPHER_SUITE = 3;
/** The vault-level "fully on CIPHER_SUITE" marker's app_settings section, on BOTH platforms. */
const CIPHER_SUITE_SETTINGS_SECTION = 'cipher_suite';

const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;

function requireId(value, what) {
  if (typeof value !== 'string' || !value) throw new Error(`${what} is required to bind this ciphertext to its place.`);
  return value;
}

/**
 * Suite-3 AAD for one half of a credential row.
 * @param {{ vaultId: string, itemId: string, half: 'open' | 'secret' }} binding
 * @returns {Uint8Array}
 */
function credentialAad({ vaultId, itemId, half } = {}) {
  return buildAad({
    component: COMPONENT_VAULT, vaultId, recordType: 'credential',
    primaryKey: [requireId(itemId, 'The item id')], part: half,
  });
}

/**
 * Suite-3 AAD for a document's wrapped key.
 *
 * Bound to the DOCUMENT, not to a version. A version row carries the document's
 * wrapped key verbatim (captureDocumentVersion copies it, restoreDocumentVersion
 * moves it back), so binding a version id in would mean re-wrapping on every
 * capture and restore for no gain: swapping a document's current bytes for one
 * of its OWN earlier versions is a rollback, which anyone able to write the
 * database can do anyway by putting back an older database file.
 *
 * @param {{ vaultId: string, documentId: string }} binding
 * @returns {Uint8Array}
 */
function documentKeyAad({ vaultId, documentId } = {}) {
  return buildAad({
    component: COMPONENT_VAULT, vaultId, recordType: 'document_key',
    primaryKey: [requireId(documentId, 'The document id')],
  });
}

/**
 * The nonce in a credential half's stored `iv` bytes, which must be suite 3.
 * @returns {{ version: 3, nonce: Uint8Array }}
 */
function parseCredentialIv(ivBytes) {
  const bytes = ivBytes instanceof Uint8Array ? ivBytes : new Uint8Array(ivBytes || []);
  if (bytes.length === NONCE_LENGTH + 1 && bytes[0] === CIPHER_SUITE) {
    return { version: CIPHER_SUITE, nonce: bytes.slice(1) };
  }
  if (bytes.length === NONCE_LENGTH || (bytes.length === NONCE_LENGTH + 1 && bytes[0] < CIPHER_SUITE)) {
    throw new Error('This vault item was stored in an older format that this build no longer reads.');
  }
  throw new Error(
    `Unsupported credential cipher (iv of ${bytes.length} bytes). This vault was written by a `
    + 'newer build of PaperSafeAI; update the app to open it.'
  );
}

/** The suite of a stored credential `iv` (3), or 0 when it is not one this build reads. */
function credentialIvSuite(ivBytes) {
  try {
    return parseCredentialIv(ivBytes).version;
  } catch {
    return 0;
  }
}

/** True when a stored credential `iv` is the current suite. */
function isCurrentCredentialIv(ivBytes) {
  return credentialIvSuite(ivBytes) === CIPHER_SUITE;
}

/**
 * Seal one half of a credential, bound to its vault, item and half.
 *
 * @param {Uint8Array} plaintext  the half's JSON, UTF-8 encoded
 * @param {Uint8Array} key        open-payload key (open) or credential master key (secret)
 * @param {{ vaultId: string, itemId: string, half: 'open'|'secret' }} binding
 * @param {{ randomBytes, aesGcmSeal, aesGcmOpen }} adapter  platform AES-GCM, AAD-binding
 * @returns {{ ciphertext: Uint8Array, iv: Uint8Array, tag: Uint8Array }}
 *   `iv` is the 13-byte stored form, [3][nonce] — store it as-is.
 */
function sealCredentialHalf(plaintext, key, binding, adapter) {
  if (!binding || typeof binding !== 'object') throw new Error('sealCredentialHalf needs { vaultId, itemId, half }.');
  const aad = credentialAad(binding);
  assertBindsAad(adapter);
  // Random 96-bit nonce per seal, never derived: a deterministic nonce under a
  // reused key is the one way AES-GCM fails catastrophically.
  const nonce = adapter.randomBytes(NONCE_LENGTH);
  if (!nonce || nonce.length !== NONCE_LENGTH) throw new Error('The platform returned a bad nonce.');
  const { ciphertext, tag } = adapter.aesGcmSeal({ plaintext, key, iv: nonce, aad });
  if (!tag || tag.length !== TAG_LENGTH) throw new Error('AES-GCM adapter returned a bad tag.');
  const iv = new Uint8Array(NONCE_LENGTH + 1);
  iv[0] = CIPHER_SUITE;
  iv.set(nonce, 1);
  return { ciphertext, iv, tag };
}

/** Open one half of a credential (suite 3 only; anything else is refused). */
function openCredentialHalf({ ciphertext, iv, tag, key, vaultId, itemId, half }, adapter) {
  const { nonce } = parseCredentialIv(iv);
  // A short tag would still be accepted by some AES-GCM implementations (Node
  // takes 4..16 bytes) and authenticates proportionally less. Only 16.
  if (!tag || tag.length !== TAG_LENGTH) throw new Error('This vault item\'s authentication tag is malformed.');
  assertBindsAad(adapter);
  return adapter.aesGcmOpen({ ciphertext, key, iv: nonce, tag, aad: credentialAad({ vaultId, itemId, half }) });
}

module.exports = {
  CREDENTIAL_KEY_SALT,
  CREDENTIAL_KEY_INFO,
  THUMBNAIL_KEY_INFO,
  FIELD_KEY_INFO,
  CIPHER_SUITE,
  CIPHER_SUITE_SETTINGS_SECTION,
  NONCE_LENGTH,
  TAG_LENGTH,
  credentialAad,
  documentKeyAad,
  parseCredentialIv,
  credentialIvSuite,
  isCurrentCredentialIv,
  sealCredentialHalf,
  openCredentialHalf
};
