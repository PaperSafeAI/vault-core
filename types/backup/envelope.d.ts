export const CIPHER_NAME: "aes-256-gcm";
export const SALT_LENGTH: 16;
export const IV_LENGTH: 12;
/** Marks which fields the tag covers, so a future change is a new value here. */
export const AAD_SCHEME: "header-v1";
/**
 * The largest vault (sum of its file sizes) one archive can hold, about 272 MB.
 * v1 base64s the files INTO the JSON, so the bundle string is already 4/3 of
 * the vault before the envelope's own base64 pass. The same number on every
 * platform: a platform-local limit let the phone read and base64 a vault the
 * seal would refuse anyway.
 */
export const MAX_ARCHIVE_VAULT_BYTES: number;
/**
 * Refuse a vault too large for one archive. Callers pass the size from `stat`
 * BEFORE reading or copying anything, so the refusal comes before the memory
 * and disk it would otherwise cost; sealBundle checks again as the backstop.
 */
export function assertVaultFitsArchive(totalBytes: any, { platform }?: {
    platform?: string;
}): void;
export function readPassphraseHint(envelope: any): any;
export function sealBundle(bundle: any, passphrase: any, adapter: any, options?: {}): Promise<{
    ciphertext: any;
    passphraseHint?: any;
    cipher: {
        tag: any;
        name: string;
        iv: any;
        aad: string;
    };
    format: string;
    version: number;
    createdAt: any;
    fileCount: number;
    totalBytes: number;
    kdf: {
        salt: any;
        timeCost: number;
        memoryCost: number;
        parallelism: number;
        keyLength: number;
        name: string;
    };
}>;
/**
 * Parse the JSON text of a `.psbak`, without decrypting it.
 *
 * Returns null when the text is not an encrypted archive at all — the caller
 * then tries the legacy raw-gzip path. A version that is too NEW throws instead,
 * because "I do not recognise this" and "I recognise this and cannot read it"
 * need different answers: the second one has a fix, and it is "update the app".
 */
export function parseEnvelope(text: any): any;
/**
 * Open an envelope of any supported version.
 *
 * A wrong passphrase and a corrupted archive are deliberately indistinguishable
 * from the outside: both surface as a GCM tag failure. Reporting which one it
 * was would tell an attacker holding a stolen archive whether a guessed
 * passphrase was close.
 */
export function openEnvelope(envelope: any, passphrase: any, adapter: any): Promise<any>;
/**
 * The exact bytes bound into the GCM tag.
 *
 * Built by listing fields explicitly in a fixed order rather than serialising
 * the header object, because `JSON.stringify` over an object depends on key
 * insertion order — so a header that round-tripped through a parser could
 * produce different AAD bytes and fail to open a perfectly good archive.
 *
 * `tag` is excluded because it does not exist yet when sealing. `ciphertext` is
 * excluded because GCM already covers it.
 */
export function headerAad(header: any, adapter: any): any;
