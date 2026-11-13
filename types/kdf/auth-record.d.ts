/** What a record with no `kdfScheme` (auth-record v1, and every phone-created record) was written with. */
export const LEGACY_KDF_SCHEME: "argon2id-v1";
export const SALT_LENGTH: 16;
/** The parameters this record was written with. */
export function kdfParamsFor(record: any): {
    timeCost: any;
    memoryCost: any;
    parallelism: any;
    hashLength: number;
};
/** Argon2id parameters for a scheme id. Throws "update the app" for one this build does not know. */
export function kdfParamsForScheme(schemeId: any): {
    timeCost: any;
    memoryCost: any;
    parallelism: any;
    hashLength: number;
};
/** The parameters a NEW record is written with. */
export function currentKdfParams(): {
    timeCost: any;
    memoryCost: any;
    parallelism: any;
    hashLength: number;
};
/**
 * Accept a recovery key the way a human retypes it: any case, spaces or dashes
 * anywhere. Only the 24 hex characters carry meaning; they are put back into
 * the canonical `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` form the key was derived over.
 * Null when the input cannot be a recovery key at all.
 */
export function normaliseRecoveryKey(input: any): string;
/** The 32-byte key that wraps the vault key, from a secret and its salt. */
export function deriveWrappingKey(secret: any, salt: any, params: any, adapter: any): Promise<Uint8Array<any>>;
/** A fresh random salt for a new wrapping key. */
export function generateSalt(adapter: any): Uint8Array<any>;
/** Wrap a key: `{ encrypted, iv, tag }`, base64, as auth.json stores it. */
export function wrapKey(key: any, wrappingKey: any, adapter: any): {
    encrypted: any;
    iv: any;
    tag: any;
};
/** Unwrap a `{ encrypted, iv, tag }` key. Throws when the wrapping key is wrong. */
export function unwrapKey(wrapped: any, wrappingKey: any, adapter: any): Uint8Array<any>;
/**
 * Open a vault with its master password.
 * @returns {Promise<{ vaultKey: Uint8Array, wrappingKey: Uint8Array }>}
 *   `wrappingKey` is returned because the desktop keeps it for the session.
 */
export function unlockWithPassword(record: any, password: any, adapter: any): Promise<{
    vaultKey: Uint8Array;
    wrappingKey: Uint8Array;
}>;
/**
 * Open a vault with its recovery key.
 * @returns {Promise<{ vaultKey: Uint8Array, wrappingKey: Uint8Array }>}
 */
export function unlockWithRecoveryKey(record: any, recoveryKeyInput: any, adapter: any): Promise<{
    vaultKey: Uint8Array;
    wrappingKey: Uint8Array;
}>;
