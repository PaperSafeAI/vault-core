/**
 * Biometric unlock: the vault key wrapped under a secret that only the
 * device's security hardware (Secure Enclave on macOS, TPM via Windows Hello)
 * can produce, and only after a live fingerprint or face check. SPEC.md §2.
 * ON-DISK FORMAT (the stored blob):
 *
 *   challenge   = random(32)                      # stored; fed to the hardware
 *   secret      = hardware(challenge)             # needs the biometric; never stored
 *   salt        = random(32)
 *   wrappingKey = HKDF-SHA256(ikm=secret, salt, info="papersafeai-vault-key-wrap-v1", L=32)
 *   blob        = { version: 1, provider, challenge, salt, iv, tag, ciphertext }   # base64 fields
 *                 ciphertext = AES-256-GCM(wrappingKey, iv=random(12), vaultKey)    # no AAD
 *
 * The hardware secret must be deterministic for a (credential, challenge):
 * Windows Hello signs with RSA PKCS#1 v1.5; on macOS the app keeps random bytes
 * in a Keychain item gated by the current set of enrolled biometrics and the
 * secret is sha256(storedSecret || challenge). HKDF turns either into a uniform
 * key. The blob alone opens nothing.
 *
 * The adapter supplies randomBytes, hkdfSha256, aesGcmSeal, aesGcmOpen,
 * toBase64, fromBase64. Getting the secret from the hardware is the app's job.
 */
export const FORMAT_VERSION: 1;
export const HKDF_INFO: "papersafeai-vault-key-wrap-v1";
/** A fresh challenge to hand the hardware at enrollment. */
export function newChallenge(adapter: any): Uint8Array<any>;
/** Wrap `key` under the hardware's answer to `challenge`. Returns the blob to store. */
export function sealWithHardwareSecret({ key, secret, challenge, provider }: {
    key: any;
    secret: any;
    challenge: any;
    provider: any;
}, adapter: any): {
    version: number;
    provider: any;
    challenge: any;
    salt: any;
    iv: any;
    tag: any;
    ciphertext: any;
};
/** The challenge to hand the hardware when opening `blob`. Refuses a blob of another version. */
export function challengeOf(blob: any, adapter: any): any;
/**
 * Open `blob` with the hardware's answer. A failed tag means the hardware
 * credential no longer matches the one that enrolled — typically a fingerprint
 * added or removed, which invalidates it by design — so re-enrolment is the
 * only way back.
 */
export function openWithHardwareSecret(blob: any, secret: any, adapter: any): Uint8Array<any>;
