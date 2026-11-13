/**
 * @param {{ quickCrypto: any, argon2?: Function, gzip?: (bytes: Uint8Array) => Uint8Array, gunzip?: (bytes: Uint8Array) => Uint8Array, Gunzip?: any }} libraries
 */
export function createReactNativeAdapter({ quickCrypto, argon2, gzip, gunzip, Gunzip }?: {
    quickCrypto: any;
    argon2?: Function;
    gzip?: (bytes: Uint8Array) => Uint8Array;
    gunzip?: (bytes: Uint8Array) => Uint8Array;
    Gunzip?: any;
}): Readonly<{
    randomBytes: (length: any) => Uint8Array<any>;
    aesGcmSeal: ({ plaintext, key, iv, aad }: {
        plaintext: any;
        key: any;
        iv: any;
        aad: any;
    }) => {
        ciphertext: Uint8Array<any>;
        tag: Uint8Array<any>;
    };
    aesGcmOpen: ({ ciphertext, key, iv, tag, aad }: {
        ciphertext: any;
        key: any;
        iv: any;
        tag: any;
        aad: any;
    }) => Uint8Array<any>;
    hkdfSha256: ({ key, salt, info, length }: {
        key: any;
        salt: any;
        info: any;
        length: any;
    }) => Uint8Array<any>;
    hmacSha256: (key: any, data: any) => Uint8Array<any>;
    sha256: (data: any) => Uint8Array<any>;
    sha256Hex: (data: any) => string;
    x25519GenerateKeyPair: ({ exportPrivate }?: {
        exportPrivate?: boolean;
    }) => {
        privateKey: any;
        publicKey: Uint8Array<ArrayBuffer>;
    };
    x25519SharedSecret: (privateKey: any, peerPublic: any) => Uint8Array<any>;
    argon2idRaw: ({ secret, salt, timeCost, memoryCost, parallelism, hashLength }: {
        secret: any;
        salt: any;
        timeCost: any;
        memoryCost: any;
        parallelism: any;
        hashLength: any;
    }) => Promise<Uint8Array<ArrayBuffer>>;
    deriveKey: ({ passphrase, salt, kdf }: {
        passphrase: any;
        salt: any;
        kdf: any;
    }) => Promise<Uint8Array<ArrayBuffer>>;
    gzip: (data: any) => Uint8Array<any>;
    /** @param {Uint8Array} data @param {{ maxOutputLength?: number }} [options] */
    gunzip: (data: Uint8Array, options?: {
        maxOutputLength?: number;
    }) => Uint8Array<any>;
    toBase64: (value: any) => string;
    fromBase64: (value: any) => Uint8Array<any>;
    utf8ToBytes: (value: any) => Uint8Array<ArrayBuffer>;
    bytesToUtf8: (data: any) => string;
}>;
