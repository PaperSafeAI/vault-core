export let VERSION: string;
export let vaultCipher: typeof import("./crypto/vault-cipher");
export let documentKey: typeof import("./crypto/document-key");
export let dbKey: typeof import("./crypto/db-key");
export let kdf: typeof import("./kdf/vault-kdf");
export let vaultUnlock: typeof import("./kdf/auth-record");
export let backup: {
    CIPHER_NAME: "aes-256-gcm";
    SALT_LENGTH: 16;
    IV_LENGTH: 12;
    AAD_SCHEME: "header-v1";
    MAX_ARCHIVE_VAULT_BYTES: number;
    assertVaultFitsArchive: typeof import("./backup/envelope").assertVaultFitsArchive;
    readPassphraseHint: typeof import("./backup/envelope").readPassphraseHint;
    sealBundle: typeof import("./backup/envelope").sealBundle;
    parseEnvelope: typeof import("./backup/envelope").parseEnvelope;
    openEnvelope: typeof import("./backup/envelope").openEnvelope;
    headerAad: typeof import("./backup/envelope").headerAad;
    assembleBundle: typeof import("./backup/bundle").assembleBundle;
    serializeBundle: typeof import("./backup/bundle").serializeBundle;
    deserializeBundle: typeof import("./backup/bundle").deserializeBundle;
    looksLikeBundleV2: typeof import("./backup/bundle").looksLikeBundleV2;
    verifyBundle: typeof import("./backup/bundle").verifyBundle;
    assertBundleIntact: typeof import("./backup/bundle").assertBundleIntact;
    databaseCipherOf: typeof import("./backup/bundle").databaseCipherOf;
    observedDatabaseCipher: typeof import("./backup/bundle").observedDatabaseCipher;
    configureBundle: typeof import("./backup/bundle").configureBundle;
    producerPlatformOf: typeof import("./backup/bundle").producerPlatformOf;
    canRestoreDatabaseOn: typeof import("./backup/bundle").canRestoreDatabaseOn;
    assertRestorableOn: typeof import("./backup/bundle").assertRestorableOn;
    normalizeRelativePath: typeof import("./backup/bundle").normalizeRelativePath;
    REQUIRED_METHODS: string[];
    assertAdapter: typeof import("./backup/adapter").assertAdapter;
    timestamp: typeof import("./backup/adapter").timestamp;
    MAX_EXPANDED_BACKUP_BYTES: number;
    ENVELOPE_FORMAT_V2: "papersafe-encrypted-backup-v2";
    ENVELOPE_FORMAT_V3: "papersafe-encrypted-backup-v3";
    BUNDLE_FORMAT: "papersafe-archive-v1";
    CURRENT_ENVELOPE_VERSION: 3;
    MAX_SUPPORTED_ENVELOPE_VERSION: 3;
    BUNDLE_VERSION_V1: 1;
    BUNDLE_VERSION_V2: 2;
    MAX_SUPPORTED_BUNDLE_VERSION: 2;
    MAX_SUPPORTED_MANIFEST_VERSION: 3;
    CURRENT_BUNDLE_VERSION: 1;
    CURRENT_MANIFEST_VERSION: 3;
    KDF_SCHEMES: {
        scrypt: {
            name: string;
            write: boolean;
            defaults: {
                N: number;
                r: number;
                p: number;
                keyLength: number;
            };
            minimum: {
                N: number;
            };
            maximum: {
                N: number;
                r: number;
                p: number;
                keyLength: number;
            };
        };
        argon2id: {
            name: string;
            write: boolean;
            defaults: {
                timeCost: number;
                memoryCost: number;
                parallelism: number;
                keyLength: number;
            };
            minimum: {
                timeCost: number;
                memoryCost: number;
            };
            maximum: {
                timeCost: number;
                memoryCost: number;
                parallelism: number;
                keyLength: number;
            };
        };
    };
    CURRENT_KDF: "argon2id";
    DATABASE_CIPHERS: {
        SQLCIPHER: string;
        NONE: string;
    };
    BACKUP_PLATFORMS: {
        DESKTOP: string;
        MOBILE: string;
        UNKNOWN: string;
    };
    MINIMUM_PASSPHRASE_LENGTH: 10;
    assertSupportedFormatVersion: typeof import("./backup/format").assertSupportedFormatVersion;
    assertKdfCost: typeof import("./backup/format").assertKdfCost;
    validateBackupPassphrase: typeof import("./backup/format").validateBackupPassphrase;
};
export let catalogKeys: typeof import("./sync/catalog/keys");
export let catalogSeal: typeof import("./sync/catalog/seal");
export let canonicalJson: typeof import("./sync/catalog/canonical-json");
export let aad: typeof import("./crypto/aad");
export let pairingTransport: typeof import("./pairing/transport");
export let responseBinding: typeof import("./pairing/response-binding");
