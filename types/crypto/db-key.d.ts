/**
 * Derive the database key from the vault key.
 *
 * @param {Uint8Array|Buffer} vaultKey  the 32-byte vault key
 * @param {{hkdfSha256: (args: {key: Uint8Array, salt: string, info: string, length: number}) => Uint8Array}} adapter
 *   the platform's HKDF. Node supplies `crypto.hkdfSync`; the phone supplies
 *   react-native-quick-crypto's, which is the same function.
 * @returns {Uint8Array} 32 bytes
 */
export function deriveDbKey(vaultKey: Uint8Array | Buffer, adapter: {
    hkdfSha256: (args: {
        key: Uint8Array;
        salt: string;
        info: string;
        length: number;
    }) => Uint8Array;
}): Uint8Array;
/**
 * The same key in the form SQLCipher's `PRAGMA key = "x'…'"` wants.
 *
 * Lowercase hex, no prefix. Kept here rather than at each call site because
 * both platforms build that pragma string and a case or padding difference
 * would be a silent wrong key on one of them.
 */
export function deriveDbKeyHex(vaultKey: any, adapter: any): string;
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
export const DB_KEY_SALT: "papersafeai:db-key";
export const DB_KEY_INFO: "papersafeai:db-key:v1";
/** AES-256. SQLCipher takes the 32 bytes as a raw key when given as x'…'. */
export const DB_KEY_LENGTH: 32;
