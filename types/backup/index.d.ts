declare const _exports: {
    CIPHER_NAME: "aes-256-gcm";
    SALT_LENGTH: 16;
    IV_LENGTH: 12;
    AAD_SCHEME: "header-v1";
    MAX_ARCHIVE_VAULT_BYTES: number;
    assertVaultFitsArchive: typeof envelope.assertVaultFitsArchive;
    readPassphraseHint: typeof envelope.readPassphraseHint;
    sealBundle: typeof envelope.sealBundle;
    parseEnvelope: typeof envelope.parseEnvelope;
    openEnvelope: typeof envelope.openEnvelope;
    headerAad: typeof envelope.headerAad;
    assembleBundle: typeof bundle.assembleBundle;
    serializeBundle: typeof bundle.serializeBundle;
    deserializeBundle: typeof bundle.deserializeBundle;
    looksLikeBundleV2: typeof bundle.looksLikeBundleV2;
    verifyBundle: typeof bundle.verifyBundle;
    assertBundleIntact: typeof bundle.assertBundleIntact;
    databaseCipherOf: typeof bundle.databaseCipherOf;
    observedDatabaseCipher: typeof bundle.observedDatabaseCipher;
    configureBundle: typeof bundle.configureBundle;
    producerPlatformOf: typeof bundle.producerPlatformOf;
    canRestoreDatabaseOn: typeof bundle.canRestoreDatabaseOn;
    assertRestorableOn: typeof bundle.assertRestorableOn;
    normalizeRelativePath: typeof bundle.normalizeRelativePath;
    REQUIRED_METHODS: string[];
    assertAdapter: typeof adapter.assertAdapter;
    timestamp: typeof adapter.timestamp;
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
    assertSupportedFormatVersion: typeof format.assertSupportedFormatVersion;
    assertKdfCost: typeof format.assertKdfCost;
    validateBackupPassphrase: typeof format.validateBackupPassphrase;
};
export = _exports;
import envelope = require("./envelope");
import bundle = require("./bundle");
import adapter = require("./adapter");
import format = require("./format");
