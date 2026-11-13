'use strict';

/**
 * Node implementations of the primitives the core takes as an adapter.
 *
 * Everything under src/ except this folder is platform-free: it never touches
 * a crypto library itself, it is handed one. The desktop app passes these Node
 * primitives; the phone passes react-native-quick-crypto behind the same
 * function names. Anyone checking the core can therefore run every format with
 * nothing but Node (and, for Argon2id, the `argon2` package).
 *
 * The phone app never loads this folder: it has no Node built-ins and passes
 * src/platform/react-native.js instead.
 */
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { constants: { MAX_LENGTH } } = require('node:buffer');
const { KDF_SCHEMES } = require('../backup/format');

const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/**
 * Refuse a nonce or tag of the wrong length before decrypting. Node accepts
 * shorter GCM tags unless told otherwise, and a truncated tag is a weaker one.
 */
function checkGcmShape(iv, tag) {
  if (!iv || iv.length !== IV_LENGTH) throw new Error('AES-GCM nonce must be 12 bytes.');
  if (!tag || tag.length !== TAG_LENGTH) throw new Error('AES-GCM tag must be 16 bytes.');
}

function aesGcmSeal({ plaintext, key, iv, aad }) {
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(iv));
  if (aad) cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return { ciphertext, tag: cipher.getAuthTag() };
}

function aesGcmOpen({ ciphertext, key, iv, tag, aad }) {
  checkGcmShape(iv, tag);
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(iv), { authTagLength: TAG_LENGTH });
  if (aad) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(tag));
  // final() is what verifies the tag; never skip it.
  return Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]);
}

/** Argon2id is a native module; loaded only when something asks for it. */
function loadArgon2() {
  try {
    return require('argon2');
  } catch {
    throw new Error('Argon2id needs the optional "argon2" package (npm install argon2).');
  }
}

/**
 * Derive a backup archive key with the parameters the ARCHIVE recorded — never
 * this build's defaults, or every archive breaks the day a default is raised.
 * Callers check them against the scheme's tamper floor first (backup/format.js).
 */
async function deriveKey({ passphrase, salt, kdf }) {
  const name = String(kdf?.name || '');
  if (name === 'argon2id') {
    const argon2 = loadArgon2();
    const defaults = KDF_SCHEMES.argon2id.defaults;
    return argon2.hash(passphrase, {
      type: argon2.argon2id,
      salt: Buffer.from(salt),
      timeCost: Number(kdf.timeCost || defaults.timeCost),
      memoryCost: Number(kdf.memoryCost || defaults.memoryCost),
      parallelism: Number(kdf.parallelism || defaults.parallelism),
      hashLength: Number(kdf.keyLength || defaults.keyLength),
      raw: true
    });
  }
  if (name === 'scrypt') {
    // Read-only: v2 archives use it; nothing writes scrypt any more.
    const defaults = KDF_SCHEMES.scrypt.defaults;
    const N = Number(kdf.N || defaults.N);
    const r = Number(kdf.r || defaults.r);
    const p = Number(kdf.p || defaults.p);
    // scrypt needs ~128*N*r*p bytes; maxmem must leave headroom above that.
    const requiredBytes = 128 * N * r * p;
    return crypto.scryptSync(passphrase, Buffer.from(salt), Number(kdf.keyLength || 32), {
      N, r, p, maxmem: Math.max(requiredBytes * 2, 64 * 1024 * 1024)
    });
  }
  throw new Error(`Unsupported backup key-derivation scheme: ${name || 'missing'}`);
}

/** Raw Argon2id output, for vault wrapping keys (SPEC.md §2). */
async function argon2idRaw({ secret, salt, timeCost, memoryCost, parallelism, hashLength }) {
  const argon2 = loadArgon2();
  return new Uint8Array(await argon2.hash(String(secret), {
    type: argon2.argon2id,
    salt: Buffer.from(salt),
    timeCost,
    memoryCost,
    parallelism,
    hashLength,
    raw: true
  }));
}

// X25519 keys travel as their 32 raw bytes (RFC 7748). Node imports and
// exports them as DER: these fixed prefixes wrap the raw bytes as SPKI / PKCS#8.
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

/**
 * A fresh X25519 key pair; the public key is 32 raw bytes. The private key
 * stays a KeyObject (never exported) unless `exportPrivate` asks for its 32 raw
 * bytes, which only a device identity key needs (to keep in the OS keystore).
 */
function x25519GenerateKeyPair({ exportPrivate = false } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const pub = new Uint8Array(spki.subarray(X25519_SPKI_PREFIX.length));
  if (!exportPrivate) return { privateKey, publicKey: pub };
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  return { privateKey: new Uint8Array(pkcs8.subarray(X25519_PKCS8_PREFIX.length)), publicKey: pub };
}

/** X25519(privateKey, peerPublic). `privateKey` is a generated KeyObject, or 32 raw bytes (test vectors). */
function x25519SharedSecret(privateKey, peerPublic) {
  const priv = privateKey instanceof Uint8Array
    ? crypto.createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(privateKey)]), format: 'der', type: 'pkcs8' })
    : privateKey;
  const pub = crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(peerPublic)]), format: 'der', type: 'spki' });
  return new Uint8Array(crypto.diffieHellman({ privateKey: priv, publicKey: pub }));
}

const nodeAdapter = Object.freeze({
  randomBytes: (length) => crypto.randomBytes(length),
  aesGcmSeal,
  aesGcmOpen,
  hkdfSha256: ({ key, salt, info, length }) => new Uint8Array(crypto.hkdfSync('sha256', key, salt, info, length)),
  hmacSha256: (key, bytes) => crypto.createHmac('sha256', Buffer.from(key)).update(Buffer.from(bytes)).digest(),
  sha256: (bytes) => crypto.createHash('sha256').update(Buffer.from(bytes)).digest(),
  sha256Hex: (bytes) => crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex'),
  x25519GenerateKeyPair,
  x25519SharedSecret,
  deriveKey,
  argon2idRaw,
  gzip: (bytes) => zlib.gzipSync(Buffer.from(bytes)),
  // maxOutputLength stops inflating at the limit (RangeError
  // ERR_BUFFER_TOO_LARGE) instead of allocating whatever the input asks for.
  /** @param {Uint8Array} bytes @param {{ maxOutputLength?: number }} [options] */
  gunzip: (bytes, options) => {
    const limit = options && options.maxOutputLength;
    return zlib.gunzipSync(Buffer.from(bytes), limit ? { maxOutputLength: Math.min(limit, MAX_LENGTH) } : {});
  },
  toBase64: (bytes) => Buffer.from(bytes).toString('base64'),
  fromBase64: (value) => Buffer.from(String(value || ''), 'base64'),
  utf8ToBytes: (value) => Buffer.from(String(value), 'utf8'),
  bytesToUtf8: (bytes) => Buffer.from(bytes).toString('utf8')
});

module.exports = { nodeAdapter, checkGcmShape, deriveKey, argon2idRaw, aesGcmSeal, aesGcmOpen };
