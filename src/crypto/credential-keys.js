'use strict';

/**
 * Keys derived for saved passwords and secure notes (SPEC.md §4). ON-DISK
 * FORMAT: every input below is baked into stored and synced rows.
 *
 *   openKey      = HKDF(vaultKey, salt="papersafeai:local-vault", info="papersafeai:credentials:v1")
 *   reuseKey     = HKDF(openKey,  salt="papersafeai:credentials:reuse-digest", info="papersafeai:credentials:v1")
 *   noteIndexKey = HKDF(openKey,  salt="papersafeai:credentials:note-index",   info="papersafeai:credentials:v1")
 *
 * The two derived labels sit in the SALT position and the shared label in INFO.
 * That is the reverse of the usual convention, and it is what every existing
 * vault was written with, so it stays.
 *
 *   passwordDigest  = hex(HMAC-SHA256(reuseKey, utf8(password)))
 *   noteTokenDigest = hex(HMAC-SHA256(noteIndexKey, utf8(lowercase(token))))[0..12]
 *
 * The password digest groups identical passwords for the "reused password"
 * view without storing anything reversible; the note digests let secure notes
 * be searched by word without storing the words. Both live in the open
 * partition, readable by any unlocked session.
 *
 * The adapter supplies hkdfSha256, hmacSha256, utf8ToBytes.
 */
const { CREDENTIAL_KEY_SALT, CREDENTIAL_KEY_INFO } = require('./vault-cipher');

const REUSE_DIGEST_LABEL = 'papersafeai:credentials:reuse-digest';
const NOTE_INDEX_LABEL = 'papersafeai:credentials:note-index';
const NOTE_DIGEST_LENGTH = 12;
const KEY_LENGTH = 32;

function toHex(bytes) {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

function hkdf(key, salt, info, adapter) {
  const out = adapter.hkdfSha256({ key, salt, info, length: KEY_LENGTH });
  if (!out || out.length !== KEY_LENGTH) throw new Error('HKDF adapter returned a bad key.');
  return new Uint8Array(out);
}

/** The key that seals the open half of every credential. */
function deriveOpenPayloadKey(vaultKey, adapter) {
  if (!vaultKey || vaultKey.length !== KEY_LENGTH) throw new Error('The credential key needs the 32-byte vault key.');
  return hkdf(vaultKey, CREDENTIAL_KEY_SALT, CREDENTIAL_KEY_INFO, adapter);
}

/** The key behind password-reuse digests. */
function deriveReuseDigestKey(openKey, adapter) {
  return hkdf(openKey, REUSE_DIGEST_LABEL, CREDENTIAL_KEY_INFO, adapter);
}

/** Digest that is equal for equal passwords within one vault, and nothing more. */
function passwordReuseDigest(openKey, password, adapter) {
  const key = deriveReuseDigestKey(openKey, adapter);
  try {
    return toHex(adapter.hmacSha256(key, adapter.utf8ToBytes(String(password))));
  } finally {
    key.fill(0);
  }
}

/** The key behind secure-note search digests. */
function deriveNoteIndexKey(openKey, adapter) {
  return hkdf(openKey, NOTE_INDEX_LABEL, CREDENTIAL_KEY_INFO, adapter);
}

/** Search digest of one word of a secure note (case-insensitive). */
function noteTokenDigest(noteIndexKey, token, adapter) {
  return toHex(adapter.hmacSha256(noteIndexKey, adapter.utf8ToBytes(String(token).toLowerCase())))
    .slice(0, NOTE_DIGEST_LENGTH);
}

module.exports = {
  REUSE_DIGEST_LABEL,
  NOTE_INDEX_LABEL,
  NOTE_DIGEST_LENGTH,
  deriveOpenPayloadKey,
  deriveReuseDigestKey,
  passwordReuseDigest,
  deriveNoteIndexKey,
  noteTokenDigest
};
