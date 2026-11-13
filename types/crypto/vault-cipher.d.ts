export const CREDENTIAL_KEY_SALT: "papersafeai:local-vault";
export const CREDENTIAL_KEY_INFO: "papersafeai:credentials:v1";
/**
 * The phone's thumbnail-cache key: HKDF-SHA256(vaultKey, CREDENTIAL_KEY_SALT,
 * THUMBNAIL_KEY_INFO). Before suite 3 the cache was sealed under the raw vault
 * key with no AAD; the cache is disposable, so old files simply fail to open
 * and are regenerated.
 */
export const THUMBNAIL_KEY_INFO: "papersafeai:thumbnail-cache:v1";
/**
 * The column cipher's key (./field-cipher.js):
 * HKDF-SHA256(vaultKey, CREDENTIAL_KEY_SALT, FIELD_KEY_INFO). Before suite 3
 * those columns were sealed under the raw vault key with no AAD.
 */
export const FIELD_KEY_INFO: "papersafeai:field-cipher:v3";
/** Vault-, record- and part-bound through ./aad.js. The only suite read or written. */
export const CIPHER_SUITE: 3;
/** The vault-level "fully on CIPHER_SUITE" marker's app_settings section, on BOTH platforms. */
export const CIPHER_SUITE_SETTINGS_SECTION: "cipher_suite";
export const NONCE_LENGTH: 12;
export const TAG_LENGTH: 16;
/**
 * Suite-3 AAD for one half of a credential row.
 * @param {{ vaultId: string, itemId: string, half: 'open' | 'secret' }} binding
 * @returns {Uint8Array}
 */
export function credentialAad({ vaultId, itemId, half }?: {
    vaultId: string;
    itemId: string;
    half: "open" | "secret";
}): Uint8Array;
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
export function documentKeyAad({ vaultId, documentId }?: {
    vaultId: string;
    documentId: string;
}): Uint8Array;
/**
 * The nonce in a credential half's stored `iv` bytes, which must be suite 3.
 * @returns {{ version: 3, nonce: Uint8Array }}
 */
export function parseCredentialIv(ivBytes: any): {
    version: 3;
    nonce: Uint8Array;
};
/** The suite of a stored credential `iv` (3), or 0 when it is not one this build reads. */
export function credentialIvSuite(ivBytes: any): 0 | 3;
/** True when a stored credential `iv` is the current suite. */
export function isCurrentCredentialIv(ivBytes: any): boolean;
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
export function sealCredentialHalf(plaintext: Uint8Array, key: Uint8Array, binding: {
    vaultId: string;
    itemId: string;
    half: "open" | "secret";
}, adapter: {
    randomBytes: any;
    aesGcmSeal: any;
    aesGcmOpen: any;
}): {
    ciphertext: Uint8Array;
    iv: Uint8Array;
    tag: Uint8Array;
};
/** Open one half of a credential (suite 3 only; anything else is refused). */
export function openCredentialHalf({ ciphertext, iv, tag, key, vaultId, itemId, half }: {
    ciphertext: any;
    iv: any;
    tag: any;
    key: any;
    vaultId: any;
    itemId: any;
    half: any;
}, adapter: any): any;
