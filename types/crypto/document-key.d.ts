/** Suite 3: shared AAD (vault + document), under the dedicated wrap key. The only envelope read or written. */
export const DEK_ENVELOPE_VERSION: 3;
/** AES-256. A shorter key would be accepted by some backends and be weaker. */
export const DEK_LENGTH: 32;
export const HEADER_LENGTH: number;
/**
 * The suite-3 wrap key: HKDF-SHA256(vaultKey, salt, info). Before suite 3 the
 * DEK was wrapped under the raw vault key, which is also the input keying
 * material for every HKDF-derived key (database, credentials, catalogue). One
 * key, one purpose: the wrap key is derived for wrapping only. The (salt, info)
 * pair is unique among every derivation from the vault key
 * (test/key-separation.test.js checks this).
 */
export const DOCUMENT_WRAP_KEY_SALT: "papersafeai:local-vault";
export const DOCUMENT_WRAP_KEY_INFO: "papersafeai:document-key-wrap:v3";
/** The suite-3 wrap key. The caller zeroes it when done. */
export function deriveDocumentWrapKey(vaultKey: any, adapter: any): Uint8Array<any>;
/**
 * Mint a key for one document.
 *
 * Random, never derived. A DEK derived from the vault key plus a document id
 * would be reproducible from state that is resident for the whole session,
 * which would make the whole layer decorative — the same reasoning that makes
 * the credential master key random rather than derived.
 */
export function generateDocumentKey(adapter: any): any;
/**
 * Wrap a DEK, bound to its vault and document (suite 3).
 *
 * @param {{ vaultId: string, documentId: string }} binding
 * @returns {string} base64, for a TEXT column
 */
export function wrapDocumentKey(dek: any, vaultKey: any, adapter: any, binding: {
    vaultId: string;
    documentId: string;
}): string;
/**
 * Recover a DEK (suite 3 only).
 *
 * Any other version byte fails loudly rather than being guessed at: a document
 * wrapped by a newer build must report "update the app", one wrapped in an
 * older format that it is no longer read, and neither may be decrypted with
 * the wrong assumption into garbage that looks like corruption.
 */
export function unwrapDocumentKey(wrapped: any, vaultKey: any, adapter: any, binding: any): any;
/** The envelope version of a stored wrap (3), or 0 when absent, unreadable or older. */
export function documentKeySuite(wrapped: any, adapter: any): any;
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
export function documentKeyFor(row: object, vaultKey: Uint8Array, adapter: object, { vaultId, documentId }?: {
    vaultId?: string;
    documentId?: string;
}): {
    key: Uint8Array;
    perDocument: boolean;
};
/** Whether a row has its own key yet. */
export function hasDocumentKey(row: any): boolean;
/** Whether a row's key is wrapped in the current suite. */
export function hasCurrentDocumentKey(row: any, adapter: any): boolean;
