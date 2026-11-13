'use strict';

/**
 * Encrypted database columns (cipher suite 3), inside the already-encrypted
 * database. SPEC.md §3. ON-DISK FORMAT:
 *
 *   fieldKey = HKDF-SHA256(vaultKey, salt="papersafeai:local-vault", info="papersafeai:field-cipher:v3")
 *   AAD      = aad.js { component:"vault-v3", vaultId, recordType (one per column), primaryKey (the row's key) }
 *   stored   = "\x00pse\x03" || b64(iv 12) || "." || b64(tag 16) || "." || b64(AES-256-GCM(fieldKey, iv, utf8(value), AAD))
 *
 * so a value copied to another row, another column or another vault fails its
 * tag check instead of being read as that row's data. A suite-1 value
 * ("\x00pse\x01", raw vault key, no AAD) is refused, not read.
 *
 * The adapter supplies randomBytes, hkdfSha256, aesGcmSeal, aesGcmOpen,
 * toBase64, fromBase64, utf8ToBytes, bytesToUtf8.
 */
const { buildAad, COMPONENT_VAULT } = require('./aad');
const { CREDENTIAL_KEY_SALT, FIELD_KEY_INFO } = require('./vault-cipher');

const FIELD_MARKER = '\x00pse';
/** Suite 3 prefix: what every writer produces. */
const FIELD_PREFIX = `${FIELD_MARKER}\x03`;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/**
 * Why a stored field could not be read. `code`: 'unknown_version' (an older
 * suite-1 value, or a newer one), 'malformed', or 'unauthenticated' (fails its
 * tag: tampered, moved, or another vault).
 */
class FieldCipherError extends Error {
  constructor(code, recordType) {
    super(`field-cipher: ${recordType || 'field'} could not be opened (${code}).`);
    this.name = 'FieldCipherError';
    this.code = code;
    this.recordType = recordType;
  }
}

/** The key every suite-3 field is sealed under. The caller may cache it per vault key. */
function deriveFieldKey(vaultKey, adapter) {
  if (!vaultKey || vaultKey.length !== 32) throw new Error('field-cipher: a 32-byte vault key is required.');
  return new Uint8Array(adapter.hkdfSha256({ key: vaultKey, salt: CREDENTIAL_KEY_SALT, info: FIELD_KEY_INFO, length: 32 }));
}

function aadFor(context) {
  if (!context || typeof context !== 'object') throw new Error('field-cipher: a value is bound to { vaultId, recordType, primaryKey }.');
  return buildAad({ component: COMPONENT_VAULT, vaultId: context.vaultId, recordType: context.recordType, primaryKey: context.primaryKey });
}

function parseBody(body, adapter) {
  const parts = body.split('.');
  if (parts.length !== 3) return null;
  const iv = adapter.fromBase64(parts[0]);
  const tag = adapter.fromBase64(parts[1]);
  if (iv.length !== IV_LENGTH || tag.length !== TAG_LENGTH) return null;
  return { iv, tag, ciphertext: adapter.fromBase64(parts[2]) };
}

/** Seal one non-empty value for `{ vaultId, recordType, primaryKey }`. */
function sealField(plaintext, fieldKey, context, adapter) {
  const aad = aadFor(context);
  const iv = adapter.randomBytes(IV_LENGTH);
  const { ciphertext, tag } = adapter.aesGcmSeal({ plaintext: adapter.utf8ToBytes(String(plaintext)), key: fieldKey, iv, aad });
  return `${FIELD_PREFIX}${adapter.toBase64(iv)}.${adapter.toBase64(tag)}.${adapter.toBase64(ciphertext)}`;
}

/**
 * Open a stored suite-3 value. Throws Error for a value without the marker (it
 * was never written by sealField: refusing it stops chosen bytes being read as
 * trusted) and FieldCipherError for everything else that does not open.
 */
function openField(stored, fieldKey, context, adapter) {
  const s = String(stored);
  if (!s.startsWith(FIELD_MARKER)) {
    throw new Error('field-cipher: refusing to trust an un-encrypted stored value.');
  }
  const recordType = context && context.recordType;
  if (!s.startsWith(FIELD_PREFIX)) throw new FieldCipherError('unknown_version', recordType);
  const aad = aadFor(context);
  const parsed = parseBody(s.slice(FIELD_PREFIX.length), adapter);
  if (!parsed) throw new FieldCipherError('malformed', recordType);
  try {
    return adapter.bytesToUtf8(adapter.aesGcmOpen({ ciphertext: parsed.ciphertext, key: fieldKey, iv: parsed.iv, tag: parsed.tag, aad }));
  } catch {
    throw new FieldCipherError('unauthenticated', recordType);
  }
}

/** Whether a stored value is field ciphertext of any version. */
function isFieldCiphertext(stored) {
  return typeof stored === 'string' && stored.startsWith(FIELD_MARKER);
}

module.exports = {
  FIELD_MARKER,
  FIELD_PREFIX,
  FieldCipherError,
  deriveFieldKey,
  sealField,
  openField,
  isFieldCiphertext
};
