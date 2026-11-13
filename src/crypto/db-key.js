'use strict';

/**
 * The SQLCipher key for the vault database — one rule, both platforms.
 *
 * The desktop has always encrypted its whole database file; the phone did
 * not, so every document title, party name, amount and filename sat in clear
 * text on the device most likely to be lost or stolen. Giving the phone
 * SQLCipher means the two apps must derive the SAME key from the same vault
 * key, because they hand each other database FILES: a pairing snapshot, and a
 * `.psbak` restored on the other platform.
 *
 * This rule once lived only in the desktop app. Restating it in the phone app
 * would be two copies of one rule, and copies diverge — here a divergence is not
 * a wrong answer, it is a vault nobody can open. So both apps call this.
 *
 * ## What it is, and what it is not
 *
 * HKDF-SHA256 over the vault key, with a fixed salt and info string. That gives
 * domain separation — the database key is not the vault key, so a key that
 * leaks from one layer is not the key to the other — without a second key
 * hierarchy and without a byte of new storage. The database key is reproducible
 * from the vault key alone, which is what lets a phone open a database a
 * desktop wrote, and lets either open its own after a restore.
 *
 * It is NOT bound to the master password beyond the vault key's own binding.
 * A password change re-wraps the vault key and does not replace it, so the
 * database key does not move either — on both platforms. That is deliberate:
 * re-keying a whole database on every password change would risk the vault for
 * no gain, since the vault key itself is what the password protects.
 *
 * ## Versioning
 *
 * The info string carries the version. A future cost or algorithm change is a
 * NEW info string, never a reinterpretation of this one — same rule as
 * `kdfScheme` in the auth record. Changing either constant below changes every
 * existing vault's key, so neither may be edited without a migration on both
 * platforms.
 */

/** MUST NOT change: these two strings define the key of every vault in the field. */
const DB_KEY_SALT = 'papersafeai:db-key';
const DB_KEY_INFO = 'papersafeai:db-key:v1';

/** AES-256. SQLCipher takes the 32 bytes as a raw key when given as x'…'. */
const DB_KEY_LENGTH = 32;

const VAULT_KEY_LENGTH = 32;

/**
 * Derive the database key from the vault key.
 *
 * @param {Uint8Array|Buffer} vaultKey  the 32-byte vault key
 * @param {{hkdfSha256: (args: {key: Uint8Array, salt: string, info: string, length: number}) => Uint8Array}} adapter
 *   the platform's HKDF. Node supplies `crypto.hkdfSync`; the phone supplies
 *   react-native-quick-crypto's, which is the same function.
 * @returns {Uint8Array} 32 bytes
 */
function deriveDbKey(vaultKey, adapter) {
  // Fail closed. A short key would still produce 32 bytes out of HKDF, and the
  // resulting vault would be encrypted under something nobody meant.
  if (!vaultKey || vaultKey.length !== VAULT_KEY_LENGTH) {
    throw new Error('deriveDbKey: expected a 32-byte vault key.');
  }
  const derived = adapter.hkdfSha256({
    key: vaultKey,
    salt: DB_KEY_SALT,
    info: DB_KEY_INFO,
    length: DB_KEY_LENGTH,
  });
  if (!derived || derived.length !== DB_KEY_LENGTH) {
    throw new Error('deriveDbKey: HKDF returned the wrong length.');
  }
  return derived;
}

/**
 * The same key in the form SQLCipher's `PRAGMA key = "x'…'"` wants.
 *
 * Lowercase hex, no prefix. Kept here rather than at each call site because
 * both platforms build that pragma string and a case or padding difference
 * would be a silent wrong key on one of them.
 */
function deriveDbKeyHex(vaultKey, adapter) {
  const bytes = deriveDbKey(vaultKey, adapter);
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

module.exports = {
  deriveDbKey,
  deriveDbKeyHex,
  DB_KEY_SALT,
  DB_KEY_INFO,
  DB_KEY_LENGTH,
};
