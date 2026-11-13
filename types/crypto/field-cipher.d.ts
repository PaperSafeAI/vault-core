export const FIELD_MARKER: "\0pse";
/** Suite 3 prefix: what every writer produces. */
export const FIELD_PREFIX: "\0pse\u0003";
/**
 * Why a stored field could not be read. `code`: 'unknown_version' (an older
 * suite-1 value, or a newer one), 'malformed', or 'unauthenticated' (fails its
 * tag: tampered, moved, or another vault).
 */
export class FieldCipherError extends Error {
    constructor(code: any, recordType: any);
    code: any;
    recordType: any;
}
/** The key every suite-3 field is sealed under. The caller may cache it per vault key. */
export function deriveFieldKey(vaultKey: any, adapter: any): Uint8Array<any>;
/** Seal one non-empty value for `{ vaultId, recordType, primaryKey }`. */
export function sealField(plaintext: any, fieldKey: any, context: any, adapter: any): string;
/**
 * Open a stored suite-3 value. Throws Error for a value without the marker (it
 * was never written by sealField: refusing it stops chosen bytes being read as
 * trusted) and FieldCipherError for everything else that does not open.
 */
export function openField(stored: any, fieldKey: any, context: any, adapter: any): any;
/** Whether a stored value is field ciphertext of any version. */
export function isFieldCiphertext(stored: any): boolean;
