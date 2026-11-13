/**
 * Catalogue keys, derived from the vault key (SPEC.md §7).
 *
 * Derived rather than random-and-stored, the way the database key
 * (../../crypto/db-key.js) and the credential index keys already are. The
 * vault key is the same on desktop and phone and survives password changes and
 * re-pairing, so these keys are too, with nothing to store, lose or let drift
 * apart between devices. A key drifting would be silent and harmful: every
 * folder name index would change, so collisions would go undetected, or every
 * receipt digest would stop matching.
 *
 *   nameIndex — HMAC key for folder name / collection alias equality indexes
 *   digest    — HMAC key for receipt digests (desktop authority only)
 *   payload   — AES-256-GCM key for sealed catalogue columns (seal.js)
 *
 * Each key's ID is its derivation label. Rotation means a new label (/v2) plus
 * the explicit reindex or re-encryption the contract requires.
 *
 * The adapter supplies `hkdfSha256({ key, salt, info, length }) -> Uint8Array`,
 * the same shape ../../crypto/db-key.js takes on both platforms.
 */
export const SALT: "papersafe/catalogue";
export const LABELS: Readonly<{
    nameIndex: "name-index/v1";
    digest: "receipt-digest/v1";
    payload: "payload/v1";
}>;
/** The name-index and payload keys. Both platforms need these. */
export function deriveReplicaKeys(vaultKey: any, adapter: any): {
    nameIndex: {
        id: "name-index/v1";
        key: Uint8Array<any>;
    };
    payload: {
        id: "payload/v1";
        key: Uint8Array<any>;
    };
};
/** Replica keys plus the receipt digest key. Only the desktop authority derives this. */
export function deriveAuthorityKeys(vaultKey: any, adapter: any): {
    digest: {
        id: "receipt-digest/v1";
        key: Uint8Array<any>;
    };
    nameIndex: {
        id: "name-index/v1";
        key: Uint8Array<any>;
    };
    payload: {
        id: "payload/v1";
        key: Uint8Array<any>;
    };
};
