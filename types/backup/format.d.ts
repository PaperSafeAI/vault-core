/**
 * The most a backup may expand to when it is decompressed (8 GiB). Enforced
 * while decompressing, so a small crafted archive cannot make the reader
 * allocate without bound before anything else is checked; the archive cannot
 * raise it. Above the largest real vault: the whole bundle is held in memory
 * either way.
 */
export const MAX_EXPANDED_BACKUP_BYTES: number;
/**
 * The backup format contract, shared by every platform.
 *
 * A `.psbak` is a single UTF-8 JSON object. There is no binary header, so a
 * human can open one and see what it claims to be — which matters for a file
 * users are told to keep for years and may find again on a drive long after
 * this app is gone.
 *
 * Three version numbers move independently, because they describe different
 * things and change for different reasons:
 *
 *   envelope  how the payload is encrypted (KDF, cipher, AAD)
 *   bundle    the shape of the decrypted payload
 *   manifest  what is recorded about the files inside it
 *
 * RULES, the same as for every stored format in the apps:
 *  - Additive only. Never renumber an existing constant.
 *  - Readers REFUSE anything newer than their MAX, and PRESERVE unknown fields
 *    on anything at or below it.
 *  - To change KDF cost, add a new scheme id. Never mutate an existing one — a
 *    backup in the field records the scheme it was written with, and
 *    reinterpreting that record silently derives the wrong key.
 */
export const ENVELOPE_FORMAT_V2: "papersafe-encrypted-backup-v2";
export const ENVELOPE_FORMAT_V3: "papersafe-encrypted-backup-v3";
export const BUNDLE_FORMAT: "papersafe-archive-v1";
/** Envelope v3 is what this build WRITES; v2 is still read, and always will be. */
export const CURRENT_ENVELOPE_VERSION: 3;
export const MAX_SUPPORTED_ENVELOPE_VERSION: 3;
export const BUNDLE_VERSION_V1: 1;
export const BUNDLE_VERSION_V2: 2;
export const MAX_SUPPORTED_BUNDLE_VERSION: 2;
export const MAX_SUPPORTED_MANIFEST_VERSION: 3;
export const CURRENT_BUNDLE_VERSION: 1;
export const CURRENT_MANIFEST_VERSION: 3;
export namespace KDF_SCHEMES {
    namespace scrypt {
        let name: string;
        let write: boolean;
        namespace defaults {
            let N: number;
            let r: number;
            let p: number;
            let keyLength: number;
        }
        namespace minimum {
            let N_1: number;
            export { N_1 as N };
        }
        namespace maximum {
            let N_2: number;
            export { N_2 as N };
            let r_1: number;
            export { r_1 as r };
            let p_1: number;
            export { p_1 as p };
            let keyLength_1: number;
            export { keyLength_1 as keyLength };
        }
    }
    namespace argon2id {
        let name_1: string;
        export { name_1 as name };
        let write_1: boolean;
        export { write_1 as write };
        export namespace defaults_1 {
            export let timeCost: number;
            export let memoryCost: number;
            export let parallelism: number;
            let keyLength_2: number;
            export { keyLength_2 as keyLength };
        }
        export { defaults_1 as defaults };
        export namespace minimum_1 {
            let timeCost_1: number;
            export { timeCost_1 as timeCost };
            let memoryCost_1: number;
            export { memoryCost_1 as memoryCost };
        }
        export { minimum_1 as minimum };
        export namespace maximum_1 {
            let timeCost_2: number;
            export { timeCost_2 as timeCost };
            let memoryCost_2: number;
            export { memoryCost_2 as memoryCost };
            let parallelism_1: number;
            export { parallelism_1 as parallelism };
            let keyLength_3: number;
            export { keyLength_3 as keyLength };
        }
        export { maximum_1 as maximum };
    }
}
export const CURRENT_KDF: "argon2id";
export namespace DATABASE_CIPHERS {
    let SQLCIPHER: string;
    let NONE: string;
}
export namespace BACKUP_PLATFORMS {
    let DESKTOP: string;
    let MOBILE: string;
    let UNKNOWN: string;
}
export const MINIMUM_PASSPHRASE_LENGTH: 10;
export function assertSupportedFormatVersion(kind: any, version: any, maxSupported: any): void;
/**
 * Check a recorded KDF descriptor against its scheme's floor.
 *
 * Every parameter comes from the file, so every parameter is attacker-supplied.
 * The failure this prevents is not a crash — it is a backup that opens fine and
 * whose passphrase can be brute-forced offline in minutes.
 */
export function assertKdfCost(kdf: any): any;
/**
 * The passphrase rule.
 *
 * Ten characters is weak for something protecting an entire document vault, and
 * raising it is tempting. It is deliberately unchanged: this same function
 * gates RESTORE, so a higher floor would lock users out of backups they already
 * hold. Strength belongs in the UI at the moment of choosing, where it can
 * advise without stranding anyone.
 */
export function validateBackupPassphrase(value: any): string;
