'use strict';

/**
 * Catalogue keys, derived from the vault key (SPEC.md §7).
 *
 * Derived rather than random-and-stored, the way the database key
 * (../../crypto/db-key.js) and the credential index keys already are. The
 * vault key is the same on desktop and phone and survives password changes and
 * re-pairing, so these keys are too, with nothing to store, lose or let drift
 * apart between devices. A key drifting would be silent and harmful: every
 * folder name index would change, so collisions would go undetected, or every
 * receipt digest would stop matching.
 *
 *   nameIndex — HMAC key for folder name / collection alias equality indexes
 *   digest    — HMAC key for receipt digests (desktop authority only)
 *   payload   — AES-256-GCM key for sealed catalogue columns (seal.js)
 *
 * Each key's ID is its derivation label. Rotation means a new label (/v2) plus
 * the explicit reindex or re-encryption the contract requires.
 *
 * The adapter supplies `hkdfSha256({ key, salt, info, length }) -> Uint8Array`,
 * the same shape ../../crypto/db-key.js takes on both platforms.
 */

const SALT = 'papersafe/catalogue';
const LABELS = Object.freeze({
  nameIndex: 'name-index/v1',
  digest: 'receipt-digest/v1',
  payload: 'payload/v1',
});
const KEY_LENGTH = 32;

function derive(vaultKey, label, adapter) {
  if (!vaultKey || vaultKey.length !== 32) throw new Error('catalogue keys need the 32-byte vault key');
  const key = adapter.hkdfSha256({ key: vaultKey, salt: SALT, info: label, length: KEY_LENGTH });
  if (!key || key.length !== KEY_LENGTH) throw new Error(`could not derive the catalogue ${label} key`);
  return new Uint8Array(key);
}

/** The name-index and payload keys. Both platforms need these. */
function deriveReplicaKeys(vaultKey, adapter) {
  return {
    nameIndex: { id: LABELS.nameIndex, key: derive(vaultKey, LABELS.nameIndex, adapter) },
    payload: { id: LABELS.payload, key: derive(vaultKey, LABELS.payload, adapter) },
  };
}

/** Replica keys plus the receipt digest key. Only the desktop authority derives this. */
function deriveAuthorityKeys(vaultKey, adapter) {
  return {
    ...deriveReplicaKeys(vaultKey, adapter),
    digest: { id: LABELS.digest, key: derive(vaultKey, LABELS.digest, adapter) },
  };
}

module.exports = { SALT, LABELS, deriveReplicaKeys, deriveAuthorityKeys };
