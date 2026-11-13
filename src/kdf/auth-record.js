'use strict';

/**
 * Opening a vault: master password or recovery key → wrapping key → vault key.
 * SPEC.md §2. ON-DISK FORMAT: auth.json records written by every past build
 * must keep opening.
 *
 *   wrappingKey = Argon2id(secret, salt, the record's own scheme parameters) — 32 raw bytes
 *   vaultKey    = AES-256-GCM-open(wrappingKey, wrapped.iv, wrapped.encrypted, wrapped.tag)   # no AAD
 *
 * The parameters come from the RECORD, never from this build's defaults: a
 * vault written under one cost must still open after the default is raised,
 * and an unknown scheme id is refused rather than guessed at (downgrade
 * protection). The GCM tag is the check that the secret is right.
 *
 * The record's `passwordHash` / `recoveryHash` (Argon2id encoded verifier
 * strings) are not used here: they are an app-side early check, and the
 * recovery path deliberately skips them so there is no second oracle to probe.
 *
 * Platform-free. The adapter supplies:
 *   argon2idRaw({ secret, salt, timeCost, memoryCost, parallelism, hashLength }) → Promise<Uint8Array>
 *   aesGcmSeal, aesGcmOpen, randomBytes, toBase64, fromBase64
 */
const { KDF_SCHEMES, CURRENT_KDF_SCHEME } = require('./vault-kdf');

/** What a record with no `kdfScheme` (auth-record v1, and every phone-created record) was written with. */
const LEGACY_KDF_SCHEME = 'argon2id-v1';
const WRAPPING_KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

/** Argon2id parameters for a scheme id. Throws "update the app" for one this build does not know. */
function kdfParamsForScheme(schemeId) {
  const scheme = KDF_SCHEMES[schemeId];
  if (!scheme) {
    throw new Error(
      `Unsupported KDF scheme "${schemeId}". This vault was written by a newer `
      + 'build of PaperSafeAI; update the app to unlock it.'
    );
  }
  return {
    timeCost: scheme.timeCost,
    memoryCost: scheme.memoryCost,
    parallelism: scheme.parallelism,
    hashLength: WRAPPING_KEY_LENGTH
  };
}

/** The parameters this record was written with. */
function kdfParamsFor(record) {
  return kdfParamsForScheme((record && record.kdfScheme) || LEGACY_KDF_SCHEME);
}

/** The parameters a NEW record is written with. */
function currentKdfParams() {
  return kdfParamsForScheme(CURRENT_KDF_SCHEME);
}

/**
 * Accept a recovery key the way a human retypes it: any case, spaces or dashes
 * anywhere. Only the 24 hex characters carry meaning; they are put back into
 * the canonical `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` form the key was derived over.
 * Null when the input cannot be a recovery key at all.
 */
function normaliseRecoveryKey(input) {
  if (typeof input !== 'string') return null;
  const compact = input.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
  if (compact.length !== 24) return null;
  return compact.match(/.{4}/g).join('-');
}

/** The 32-byte key that wraps the vault key, from a secret and its salt. */
async function deriveWrappingKey(secret, salt, params, adapter) {
  const saltBytes = typeof salt === 'string' ? adapter.fromBase64(salt) : salt;
  if (!saltBytes || saltBytes.length < 8) throw new Error('A wrapping-key salt is required.');
  const key = await adapter.argon2idRaw({
    secret: String(secret),
    salt: new Uint8Array(saltBytes),
    timeCost: params.timeCost,
    memoryCost: params.memoryCost,
    parallelism: params.parallelism,
    hashLength: WRAPPING_KEY_LENGTH
  });
  if (!key || key.length !== WRAPPING_KEY_LENGTH) throw new Error('Argon2id adapter returned a bad key.');
  return new Uint8Array(key);
}

/** A fresh random salt for a new wrapping key. */
function generateSalt(adapter) {
  return new Uint8Array(adapter.randomBytes(SALT_LENGTH));
}

/** Wrap a key: `{ encrypted, iv, tag }`, base64, as auth.json stores it. */
function wrapKey(key, wrappingKey, adapter) {
  const iv = adapter.randomBytes(IV_LENGTH);
  const { ciphertext, tag } = adapter.aesGcmSeal({ plaintext: key, key: wrappingKey, iv, aad: null });
  return { encrypted: adapter.toBase64(ciphertext), iv: adapter.toBase64(iv), tag: adapter.toBase64(tag) };
}

/** Unwrap a `{ encrypted, iv, tag }` key. Throws when the wrapping key is wrong. */
function unwrapKey(wrapped, wrappingKey, adapter) {
  return new Uint8Array(adapter.aesGcmOpen({
    ciphertext: adapter.fromBase64(wrapped.encrypted),
    key: wrappingKey,
    iv: adapter.fromBase64(wrapped.iv),
    tag: adapter.fromBase64(wrapped.tag),
    aad: null
  }));
}

/**
 * Open a vault with its master password.
 * @returns {Promise<{ vaultKey: Uint8Array, wrappingKey: Uint8Array }>}
 *   `wrappingKey` is returned because the desktop keeps it for the session.
 */
async function unlockWithPassword(record, password, adapter) {
  const wrapped = record && record.wrappedVaultKeyByPassword;
  if (!wrapped || !record.passwordSalt) throw new Error('This vault has no password wrapping on file.');
  const wrappingKey = await deriveWrappingKey(password, record.passwordSalt, kdfParamsFor(record), adapter);
  let vaultKey;
  try {
    vaultKey = unwrapKey(wrapped, wrappingKey, adapter);
  } catch {
    wrappingKey.fill(0);
    throw new Error('Invalid master password.');
  }
  return { vaultKey, wrappingKey };
}

/**
 * Open a vault with its recovery key.
 * @returns {Promise<{ vaultKey: Uint8Array, wrappingKey: Uint8Array }>}
 */
async function unlockWithRecoveryKey(record, recoveryKeyInput, adapter) {
  const normalised = normaliseRecoveryKey(recoveryKeyInput);
  if (!normalised) throw new Error('That does not look like a recovery key.');
  const wrapped = record && record.wrappedVaultKeyByRecovery;
  if (!wrapped || !record.recoverySalt) {
    // Vaults created before recovery wrapping existed cannot be opened this
    // way at all, which is a different answer than a wrong key.
    throw new Error('This vault has no recovery key on file. Use your master password.');
  }
  const wrappingKey = await deriveWrappingKey(normalised, record.recoverySalt, kdfParamsFor(record), adapter);
  try {
    return { vaultKey: unwrapKey(wrapped, wrappingKey, adapter), wrappingKey };
  } catch {
    wrappingKey.fill(0);
    throw new Error('That recovery key does not open this vault.');
  }
}

module.exports = {
  LEGACY_KDF_SCHEME,
  SALT_LENGTH,
  kdfParamsFor,
  kdfParamsForScheme,
  currentKdfParams,
  normaliseRecoveryKey,
  deriveWrappingKey,
  generateSalt,
  wrapKey,
  unwrapKey,
  unlockWithPassword,
  unlockWithRecoveryKey
};
