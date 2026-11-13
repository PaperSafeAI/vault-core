'use strict';

/**
 * Per-document encryption keys.
 *
 * Each document is encrypted under its own random key (a DEK), and the DEK is
 * wrapped under a key derived from the vault key:
 *
 *     document bytes  ← encrypted under →  DEK
 *     DEK             ← wrapped under   →  HKDF(vaultKey, DOCUMENT_WRAP_KEY_*),
 *                                          AAD = shared builder (./aad.js):
 *                                          { component:'vault-v3', vaultId,
 *                                            recordType:'document_key', primaryKey:[documentId] }
 *
 * so one document can be handed over without handing over the key that opens
 * everything else.
 *
 * ## Every document has a DEK
 *
 * A row with no `wrapped_dek` (an old scheme, with the body under the vault
 * key itself) is refused: `documentKeyFor` reads only a suite-3 wrap.
 *
 * ## Why the wrap is bound, and the body is not
 *
 * The wrapped DEK carries its vault and document as AES-GCM Associated Data.
 * Moving a wrapped key onto another document's row — or into another vault —
 * therefore fails the tag check. The document BODY needs no AAD of its own:
 * every body has its own DEK, so a body copied onto another row is opened with
 * that row's DEK and fails — and the DEK it would need can only be recovered
 * under its own document's id. Binding the wrap is what binds the body.
 *
 * ## The envelope
 *
 * `[1B version=3][12B iv][16B tag][32B ciphertext]` (SPEC.md §5): shared AAD,
 * derived wrap key. Versions 1 and 2 (raw vault key) are not read.
 */

const { documentKeyAad, CIPHER_SUITE, CREDENTIAL_KEY_SALT } = require('./vault-cipher');
const { assertBindsAad } = require('./aad');

/** Suite 3: shared AAD (vault + document), under the dedicated wrap key. The only envelope read or written. */
const DEK_ENVELOPE_VERSION = CIPHER_SUITE;

/**
 * The suite-3 wrap key: HKDF-SHA256(vaultKey, salt, info). Before suite 3 the
 * DEK was wrapped under the raw vault key, which is also the input keying
 * material for every HKDF-derived key (database, credentials, catalogue). One
 * key, one purpose: the wrap key is derived for wrapping only. The (salt, info)
 * pair is unique among every derivation from the vault key
 * (test/key-separation.test.js checks this).
 */
const DOCUMENT_WRAP_KEY_SALT = CREDENTIAL_KEY_SALT;
const DOCUMENT_WRAP_KEY_INFO = 'papersafeai:document-key-wrap:v3';

const VERSION_LENGTH = 1;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = VERSION_LENGTH + IV_LENGTH + TAG_LENGTH;

/** AES-256. A shorter key would be accepted by some backends and be weaker. */
const DEK_LENGTH = 32;

/**
 * Mint a key for one document.
 *
 * Random, never derived. A DEK derived from the vault key plus a document id
 * would be reproducible from state that is resident for the whole session,
 * which would make the whole layer decorative — the same reasoning that makes
 * the credential master key random rather than derived.
 */
function generateDocumentKey(adapter) {
  const dek = adapter.randomBytes(DEK_LENGTH);
  if (!dek || dek.length !== DEK_LENGTH) {
    throw new Error('Could not generate a document key.');
  }
  return dek;
}

/** The suite-3 wrap key. The caller zeroes it when done. */
function deriveDocumentWrapKey(vaultKey, adapter) {
  if (!vaultKey || vaultKey.length !== DEK_LENGTH) throw new Error('A 32-byte vault key is required.');
  if (typeof adapter.hkdfSha256 !== 'function') throw new Error('The platform adapter has no HKDF.');
  const key = adapter.hkdfSha256({ key: vaultKey, salt: DOCUMENT_WRAP_KEY_SALT, info: DOCUMENT_WRAP_KEY_INFO, length: DEK_LENGTH });
  if (!key || key.length !== DEK_LENGTH) throw new Error('Could not derive the document wrap key.');
  return new Uint8Array(key);
}

function requireBinding(binding) {
  if (!binding || typeof binding !== 'object') {
    throw new Error('A document key is bound to { vaultId, documentId }; pass both.');
  }
  return binding;
}

/**
 * Wrap a DEK, bound to its vault and document (suite 3).
 *
 * @param {{ vaultId: string, documentId: string }} binding
 * @returns {string} base64, for a TEXT column
 */
function wrapDocumentKey(dek, vaultKey, adapter, binding) {
  if (!dek || dek.length !== DEK_LENGTH) {
    throw new Error('A document key must be 32 bytes.');
  }
  const aad = documentKeyAad(requireBinding(binding));
  assertBindsAad(adapter);
  const iv = adapter.randomBytes(IV_LENGTH);
  if (!iv || iv.length !== IV_LENGTH) throw new Error('The platform returned a bad nonce.');
  const wrapKey = deriveDocumentWrapKey(vaultKey, adapter);
  let sealed;
  try {
    const { ciphertext, tag } = adapter.aesGcmSeal({ plaintext: dek, key: wrapKey, iv, aad });
    if (!tag || tag.length !== TAG_LENGTH) throw new Error('AES-GCM adapter returned a bad tag.');
    sealed = new Uint8Array(HEADER_LENGTH + ciphertext.length);
    sealed[0] = DEK_ENVELOPE_VERSION;
    sealed.set(iv, VERSION_LENGTH);
    sealed.set(tag, VERSION_LENGTH + IV_LENGTH);
    sealed.set(ciphertext, HEADER_LENGTH);
  } finally {
    wrapKey.fill(0);
  }
  return adapter.toBase64(sealed);
}

/** The envelope version of a stored wrap (3), or 0 when absent, unreadable or older. */
function documentKeySuite(wrapped, adapter) {
  if (!wrapped) return 0;
  const bytes = adapter.fromBase64(String(wrapped));
  if (!bytes || bytes.length < HEADER_LENGTH) return 0;
  return bytes[0] === DEK_ENVELOPE_VERSION ? bytes[0] : 0;
}

/**
 * Recover a DEK (suite 3 only).
 *
 * Any other version byte fails loudly rather than being guessed at: a document
 * wrapped by a newer build must report "update the app", one wrapped in an
 * older format that it is no longer read, and neither may be decrypted with
 * the wrong assumption into garbage that looks like corruption.
 */
function unwrapDocumentKey(wrapped, vaultKey, adapter, binding) {
  const { vaultId, documentId } = requireBinding(binding);
  // Built first: a missing id is a caller's mistake, not "could not be opened".
  const aad = documentKeyAad({ vaultId, documentId });
  const sealed = adapter.fromBase64(String(wrapped || ''));
  // Exactly one 32-byte DEK: a wrap that is shorter or longer was not written by us.
  if (!sealed || sealed.length < HEADER_LENGTH) {
    throw new Error('This document\'s key is missing or truncated.');
  }

  const version = sealed[0];
  if (version !== DEK_ENVELOPE_VERSION) {
    throw new Error(version < DEK_ENVELOPE_VERSION
      ? 'This document\'s key is in an older format that this build no longer reads.'
      : `Unsupported document key version ${version}. This vault was written by a `
        + 'newer build of PaperSafeAI; update the app to open it.');
  }
  if (sealed.length !== HEADER_LENGTH + DEK_LENGTH) {
    throw new Error('This document\'s key is the wrong length.');
  }

  const iv = sealed.slice(VERSION_LENGTH, VERSION_LENGTH + IV_LENGTH);
  const tag = sealed.slice(VERSION_LENGTH + IV_LENGTH, HEADER_LENGTH);
  const ciphertext = sealed.slice(HEADER_LENGTH);

  assertBindsAad(adapter);
  const key = deriveDocumentWrapKey(vaultKey, adapter);
  let dek;
  try {
    dek = adapter.aesGcmOpen({ ciphertext, key, iv, tag, aad });
  } catch {
    // The GCM tag failed. The wrapped key was altered, was moved here from
    // another document or vault, or this is not the vault key it was wrapped
    // under — indistinguishable, and deliberately so, since telling them apart
    // would be an oracle.
    throw new Error('This document\'s key could not be opened with this vault key.');
  } finally {
    key.fill(0);
  }
  if (dek.length !== DEK_LENGTH) {
    throw new Error('This document\'s key is the wrong length.');
  }
  return dek;
}

/**
 * The key that opens THIS document.
 *
 * The single place that decision is made, on both platforms. `vaultId` and the
 * document id (`documentId`, else `row.id`) are required: the wrap is bound to
 * both. A row with no wrapped key is refused.
 *
 * @param {object} row  the document row: `id`, `wrapped_dek`
 * @param {Uint8Array} vaultKey
 * @param {object} adapter
 * @param {{ vaultId?: string, documentId?: string }} [options]
 * @returns {{ key: Uint8Array, perDocument: boolean }}
 */
function documentKeyFor(row, vaultKey, adapter, { vaultId, documentId } = {}) {
  const wrapped = row?.wrapped_dek ?? row?.wrappedDek ?? null;
  const id = documentId ?? row?.id ?? row?.documentId;
  if (!wrapped) {
    throw new Error('This document has no key of its own, an older format that this build no longer reads.');
  }
  return { key: unwrapDocumentKey(wrapped, vaultKey, adapter, { vaultId, documentId: id }), perDocument: true };
}

/** Whether a row has its own key yet. */
function hasDocumentKey(row) {
  return Boolean(row?.wrapped_dek ?? row?.wrappedDek);
}

/** Whether a row's key is wrapped in the current suite. */
function hasCurrentDocumentKey(row, adapter) {
  return documentKeySuite(row?.wrapped_dek ?? row?.wrappedDek, adapter) === DEK_ENVELOPE_VERSION;
}

module.exports = {
  DEK_ENVELOPE_VERSION,
  DEK_LENGTH,
  HEADER_LENGTH,
  DOCUMENT_WRAP_KEY_SALT,
  DOCUMENT_WRAP_KEY_INFO,
  deriveDocumentWrapKey,
  generateDocumentKey,
  wrapDocumentKey,
  unwrapDocumentKey,
  documentKeySuite,
  documentKeyFor,
  hasDocumentKey,
  hasCurrentDocumentKey
};
