export const nodeAdapter: Readonly<{
    randomBytes: (length: any) => NonSharedBuffer;
    aesGcmSeal: typeof aesGcmSeal;
    aesGcmOpen: typeof aesGcmOpen;
    hkdfSha256: ({ key, salt, info, length }: {
        key: any;
        salt: any;
        info: any;
        length: any;
    }) => Uint8Array<ArrayBuffer>;
    hmacSha256: (key: any, bytes: any) => NonSharedBuffer;
    sha256: (bytes: any) => NonSharedBuffer;
    sha256Hex: (bytes: any) => string;
    x25519GenerateKeyPair: typeof x25519GenerateKeyPair;
    x25519SharedSecret: typeof x25519SharedSecret;
    deriveKey: typeof deriveKey;
    argon2idRaw: typeof argon2idRaw;
    gzip: (bytes: any) => NonSharedBuffer;
    /** @param {Uint8Array} bytes @param {{ maxOutputLength?: number }} [options] */
    gunzip: (bytes: Uint8Array, options?: {
        maxOutputLength?: number;
    }) => NonSharedBuffer;
    toBase64: (bytes: any) => string;
    fromBase64: (value: any) => Buffer<ArrayBuffer>;
    utf8ToBytes: (value: any) => Buffer<ArrayBuffer>;
    bytesToUtf8: (bytes: any) => string;
}>;
/**
 * Refuse a nonce or tag of the wrong length before decrypting. Node accepts
 * shorter GCM tags unless told otherwise, and a truncated tag is a weaker one.
 */
export function checkGcmShape(iv: any, tag: any): void;
/**
 * Derive a backup archive key with the parameters the ARCHIVE recorded — never
 * this build's defaults, or every archive breaks the day a default is raised.
 * Callers check them against the scheme's tamper floor first (backup/format.js).
 */
export function deriveKey({ passphrase, salt, kdf }: {
    passphrase: any;
    salt: any;
    kdf: any;
}): Promise<Buffer<ArrayBufferLike>>;
/** Raw Argon2id output, for vault wrapping keys (SPEC.md §2). */
export function argon2idRaw({ secret, salt, timeCost, memoryCost, parallelism, hashLength }: {
    secret: any;
    salt: any;
    timeCost: any;
    memoryCost: any;
    parallelism: any;
    hashLength: any;
}): Promise<Uint8Array<ArrayBuffer>>;
export function aesGcmSeal({ plaintext, key, iv, aad }: {
    plaintext: any;
    key: any;
    iv: any;
    aad: any;
}): {
    ciphertext: Buffer<ArrayBuffer>;
    tag: NonSharedBuffer;
};
export function aesGcmOpen({ ciphertext, key, iv, tag, aad }: {
    ciphertext: any;
    key: any;
    iv: any;
    tag: any;
    aad: any;
}): Buffer<ArrayBuffer>;
/**
 * A fresh X25519 key pair; the public key is 32 raw bytes. The private key
 * stays a KeyObject (never exported) unless `exportPrivate` asks for its 32 raw
 * bytes, which only a device identity key needs (to keep in the OS keystore).
 */
declare function x25519GenerateKeyPair({ exportPrivate }?: {
    exportPrivate?: boolean;
}): {
    privateKey: crypto.KeyObject;
    publicKey: Uint8Array<ArrayBuffer>;
} | {
    privateKey: Uint8Array<ArrayBuffer>;
    publicKey: Uint8Array<ArrayBuffer>;
};
/** X25519(privateKey, peerPublic). `privateKey` is a generated KeyObject, or 32 raw bytes (test vectors). */
declare function x25519SharedSecret(privateKey: any, peerPublic: any): Uint8Array<ArrayBuffer>;
import crypto = require("node:crypto");
export {};
