/**
 * How a master password (or recovery key) becomes the key that unwraps the
 * vault key. ON-DISK FORMAT: every auth record names the scheme it was written
 * with and copies its parameters, so a scheme id is never mutated — a cost
 * change is a new id, migrated forward on the next successful unlock.
 *
 * The derivation itself (./auth-record.js, run by both apps) is Argon2id with these
 * parameters and a random 16-byte salt per key, producing 32 raw bytes. Those
 * 32 bytes AES-256-GCM-wrap a random 32-byte vault key; see SPEC.md §2.
 */
export const KDF_SCHEMES: Readonly<{
    'argon2id-v1': Readonly<{
        kdf: "argon2id";
        timeCost: 3;
        memoryCost: 65536;
        parallelism: 1;
        hashLength: 32;
    }>;
}>;
export const CURRENT_KDF_SCHEME: "argon2id-v1";
