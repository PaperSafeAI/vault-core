export type BackupAdapter = {
    /**
     *   Cryptographically secure. Used for the salt and the IV, so a weak source
     *   here silently destroys the encryption rather than failing.
     */
    randomBytes: (length: number) => Uint8Array;
    /**
     *   Lowercase hex. This is what the manifest records per file and what restore
     *   re-computes to detect a truncated or altered archive.
     */
    sha256Hex: (bytes: Uint8Array) => string;
    /**
     *   Derive the archive key from the passphrase, using the parameters RECORDED
     *   in `kdf` — not the platform's current defaults. A backup written under one
     *   cost must stay openable after the default changes. The caller has already
     *   checked those parameters against the scheme's floor.
     */
    deriveKey: (args: {
        passphrase: string;
        salt: Uint8Array;
        kdf: object;
    }) => Promise<Uint8Array>;
    /**
     *   AES-256-GCM. `aad` is additional authenticated data: not encrypted, but
     *   covered by the tag. Passing it through is required — see envelope.js.
     */
    aesGcmSeal: (args: {
        plaintext: Uint8Array;
        key: Uint8Array;
        iv: Uint8Array;
        aad: Uint8Array | null;
    }) => {
        ciphertext: Uint8Array;
        tag: Uint8Array;
    };
    /**
     *   Must THROW on a tag mismatch rather than returning whatever it decrypted.
     *   The tag is the only thing standing between a corrupt archive and a restore
     *   that half-succeeds.
     */
    aesGcmOpen: (args: {
        ciphertext: Uint8Array;
        key: Uint8Array;
        iv: Uint8Array;
        tag: Uint8Array;
        aad: Uint8Array | null;
    }) => Uint8Array;
    gzip: (bytes: Uint8Array) => Uint8Array;
    /**
     *   Must stop at `maxOutputLength` bytes of output, throwing an error whose
     *   `code` is 'ERR_BUFFER_TOO_LARGE'.
     */
    gunzip: (bytes: Uint8Array, options?: {
        maxOutputLength?: number;
    }) => Uint8Array;
    toBase64: (bytes: Uint8Array) => string;
    fromBase64: (value: string) => Uint8Array;
    utf8ToBytes: (value: string) => Uint8Array;
    bytesToUtf8: (bytes: Uint8Array) => string;
    /**
     * ISO timestamp. Defaults to the system clock;
     * injectable so tests can pin it and produce byte-stable archives.
     */
    now?: () => string;
};
/**
 * What a platform must supply for the shared backup logic to run on it.
 *
 * The format logic — what a bundle contains, how a manifest is verified, how an
 * envelope is sealed and what makes one refusable — is identical everywhere and
 * lives in this directory. What differs is only the primitives underneath it:
 * Node's `crypto` and `zlib` on the desktop, `react-native-quick-crypto`,
 * `react-native-argon2` and `fflate` on a phone.
 *
 * So the platforms inject those, and there is exactly one implementation of the
 * part that is easy to get subtly and silently wrong. Two hand-written
 * implementations of a backup format do not fail loudly when they diverge —
 * they produce a file the other platform declines to open, months later, when
 * the user needs it most.
 *
 * Every byte value crossing this boundary is a `Uint8Array`. Node `Buffer` is a
 * `Uint8Array`, so a desktop adapter can pass its buffers straight through, but
 * the shared code must never ASSUME Buffer methods exist.
 */
/**
 * @typedef {object} BackupAdapter
 *
 * @property {(length: number) => Uint8Array} randomBytes
 *   Cryptographically secure. Used for the salt and the IV, so a weak source
 *   here silently destroys the encryption rather than failing.
 *
 * @property {(bytes: Uint8Array) => string} sha256Hex
 *   Lowercase hex. This is what the manifest records per file and what restore
 *   re-computes to detect a truncated or altered archive.
 *
 * @property {(args: {passphrase: string, salt: Uint8Array, kdf: object}) => Promise<Uint8Array>} deriveKey
 *   Derive the archive key from the passphrase, using the parameters RECORDED
 *   in `kdf` — not the platform's current defaults. A backup written under one
 *   cost must stay openable after the default changes. The caller has already
 *   checked those parameters against the scheme's floor.
 *
 * @property {(args: {plaintext: Uint8Array, key: Uint8Array, iv: Uint8Array, aad: Uint8Array|null}) => {ciphertext: Uint8Array, tag: Uint8Array}} aesGcmSeal
 *   AES-256-GCM. `aad` is additional authenticated data: not encrypted, but
 *   covered by the tag. Passing it through is required — see envelope.js.
 *
 * @property {(args: {ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array, tag: Uint8Array, aad: Uint8Array|null}) => Uint8Array} aesGcmOpen
 *   Must THROW on a tag mismatch rather than returning whatever it decrypted.
 *   The tag is the only thing standing between a corrupt archive and a restore
 *   that half-succeeds.
 *
 * @property {(bytes: Uint8Array) => Uint8Array} gzip
 * @property {(bytes: Uint8Array, options?: { maxOutputLength?: number }) => Uint8Array} gunzip
 *   Must stop at `maxOutputLength` bytes of output, throwing an error whose
 *   `code` is 'ERR_BUFFER_TOO_LARGE'.
 *
 * @property {(bytes: Uint8Array) => string} toBase64
 * @property {(value: string) => Uint8Array} fromBase64
 *
 * @property {(value: string) => Uint8Array} utf8ToBytes
 * @property {(bytes: Uint8Array) => string} bytesToUtf8
 *
 * @property {() => string} [now] ISO timestamp. Defaults to the system clock;
 *   injectable so tests can pin it and produce byte-stable archives.
 */
export const REQUIRED_METHODS: string[];
/**
 * Fail at the call, not three layers down inside a crypto primitive.
 *
 * A half-built adapter otherwise surfaces as "cannot read property of
 * undefined" in the middle of sealing an archive, which tells the user their
 * backup failed and tells the developer nothing.
 */
export function assertAdapter(adapter: any): any;
/** The adapter's clock, or the real one. */
export function timestamp(adapter: any): any;
