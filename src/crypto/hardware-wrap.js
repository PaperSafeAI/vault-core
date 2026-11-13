'use strict';

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
const FORMAT_VERSION = 1;
const HKDF_INFO = 'papersafeai-vault-key-wrap-v1';
const CHALLENGE_BYTES = 32;
const SALT_BYTES = 32;
const IV_BYTES = 12;

/** A fresh challenge to hand the hardware at enrollment. */
function newChallenge(adapter) {
  return new Uint8Array(adapter.randomBytes(CHALLENGE_BYTES));
}

function wrappingKeyFrom(secret, salt, adapter) {
  return adapter.hkdfSha256({ key: secret, salt, info: HKDF_INFO, length: 32 });
}

/** Wrap `key` under the hardware's answer to `challenge`. Returns the blob to store. */
function sealWithHardwareSecret({ key, secret, challenge, provider }, adapter) {
  if (!key || key.length === 0) throw new Error('A vault key is required to enable biometric unlock.');
  if (!secret || secret.length === 0) throw new Error('The security hardware did not return a usable key.');
  const salt = adapter.randomBytes(SALT_BYTES);
  const iv = adapter.randomBytes(IV_BYTES);
  const { ciphertext, tag } = adapter.aesGcmSeal({ plaintext: key, key: wrappingKeyFrom(secret, salt, adapter), iv, aad: null });
  return {
    version: FORMAT_VERSION,
    provider,
    challenge: adapter.toBase64(challenge),
    salt: adapter.toBase64(salt),
    iv: adapter.toBase64(iv),
    tag: adapter.toBase64(tag),
    ciphertext: adapter.toBase64(ciphertext)
  };
}

/** The challenge to hand the hardware when opening `blob`. Refuses a blob of another version. */
function challengeOf(blob, adapter) {
  if (!blob || blob.version !== FORMAT_VERSION) {
    throw new Error('Biometric data is from an older version. Set it up again.');
  }
  return adapter.fromBase64(blob.challenge);
}

/**
 * Open `blob` with the hardware's answer. A failed tag means the hardware
 * credential no longer matches the one that enrolled — typically a fingerprint
 * added or removed, which invalidates it by design — so re-enrolment is the
 * only way back.
 */
function openWithHardwareSecret(blob, secret, adapter) {
  challengeOf(blob, adapter);
  try {
    return new Uint8Array(adapter.aesGcmOpen({
      ciphertext: adapter.fromBase64(blob.ciphertext),
      key: wrappingKeyFrom(secret, adapter.fromBase64(blob.salt), adapter),
      iv: adapter.fromBase64(blob.iv),
      tag: adapter.fromBase64(blob.tag),
      aad: null
    }));
  } catch {
    throw new Error('Biometric unlock is no longer valid. Unlock with your master password and set it up again.');
  }
}

module.exports = { FORMAT_VERSION, HKDF_INFO, newChallenge, sealWithHardwareSecret, challengeOf, openWithHardwareSecret };
