'use strict';

/**
 * The phone's primitives, in the adapter shape every core module takes.
 *
 * The libraries are passed in rather than imported, so the core stays free of
 * dependencies (test/boundary.test.js) and this file runs unchanged under Node
 * in its own tests, handed Node's `crypto`:
 *
 *   createReactNativeAdapter({
 *     quickCrypto,   // react-native-quick-crypto (Node's crypto API)
 *     argon2,        // react-native-argon2: (password, saltHex, options) → { rawHash }
 *     gzip, gunzip,  // fflate gzipSync / gunzipSync, for backups
 *     Gunzip,        // fflate's streaming Gunzip class: when given, a backup's
 *                    // output is capped while inflating (MAX_EXPANDED_BACKUP_BYTES)
 *   })
 *
 * One adapter serves the catalogue sealing (§7), transport (§8), vault unlock
 * (§2), document and credential sealing (§4–§5) and backups (§6). Every AES-GCM
 * seal here binds AAD when it is given one — catalogue sealing refuses an
 * adapter that does not (seal.js assertBindsAad).
 */

/** Compressed bytes per Gunzip push (16 KiB inflates to at most about 16 MiB). */
const BOUNDED_GUNZIP_CHUNK = 16 * 1024;

/**
 * @param {{ quickCrypto: any, argon2?: Function, gzip?: (bytes: Uint8Array) => Uint8Array, gunzip?: (bytes: Uint8Array) => Uint8Array, Gunzip?: any }} libraries
 */
function createReactNativeAdapter({ quickCrypto, argon2, gzip, gunzip, Gunzip } = {}) {
  /**
   * Inflate with fflate's streaming Gunzip, refusing to produce more than
   * `limit` bytes.
   *
   * fflate inflates all of one `push` before it calls `ondata`, at up to about
   * 1,000x the input, so the input goes in BOUNDED_GUNZIP_CHUNK pieces: the cap
   * is then overshot by at most about 16 MiB, never by the whole archive.
   *
   * @param {Uint8Array} data gzip bytes
   * @param {number} limit the most output to produce
   * @returns {Uint8Array}
   */
  function boundedGunzip(data, limit) {
    const chunks = [];
    let total = 0;
    const stream = new Gunzip();
    stream.ondata = (chunk) => {
      total += chunk.length;
      if (total > limit) {
        const error = new RangeError(`gunzip output exceeds ${limit} bytes`);
        error.code = 'ERR_BUFFER_TOO_LARGE';
        throw error;
      }
      chunks.push(chunk);
    };
    if (data.length === 0) {
      stream.push(data, true);
    } else {
      for (let offset = 0; offset < data.length; offset += BOUNDED_GUNZIP_CHUNK) {
        const end = Math.min(offset + BOUNDED_GUNZIP_CHUNK, data.length);
        stream.push(data.subarray(offset, end), end === data.length);
      }
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
    return out;
  }

  if (!quickCrypto) throw new Error('createReactNativeAdapter needs react-native-quick-crypto.');
  const Crypto = quickCrypto;
  const NodeLikeBuffer = globalThis.Buffer;

  const bytes = (value) => (value instanceof Uint8Array
    ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    : new Uint8Array(value));
  const concat = (a, b) => {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  };
  const toHex = (value) => Array.from(value, (b) => b.toString(16).padStart(2, '0')).join('');
  const fromHex = (hex) => {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
  };

  function aesGcmSeal({ plaintext, key, iv, aad }) {
    const cipher = Crypto.createCipheriv('aes-256-gcm', bytes(key), bytes(iv));
    // Binds the caller's associated data into the tag; a silent no-op here
    // would produce ciphertext that claims a protection it lacks.
    if (aad) cipher.setAAD(bytes(aad));
    const ciphertext = concat(bytes(cipher.update(bytes(plaintext))), bytes(cipher.final()));
    return { ciphertext, tag: bytes(cipher.getAuthTag()) };
  }

  function aesGcmOpen({ ciphertext, key, iv, tag, aad }) {
    // Only a 12-byte nonce and a full 16-byte tag: GCM implementations accept a
    // truncated tag, and a shortened tag authenticates proportionally less.
    if (!iv || iv.length !== 12) throw new Error('AES-GCM nonce must be 12 bytes.');
    if (!tag || tag.length !== 16) throw new Error('AES-GCM tag must be 16 bytes.');
    const decipher = Crypto.createDecipheriv('aes-256-gcm', bytes(key), bytes(iv));
    if (aad) decipher.setAAD(bytes(aad));
    decipher.setAuthTag(bytes(tag));
    // final() is what verifies the tag; it must never be skipped.
    return concat(bytes(decipher.update(bytes(ciphertext))), bytes(decipher.final()));
  }

  /** Raw Argon2id. react-native-argon2 takes a hex salt and returns hex. */
  async function argon2idRaw({ secret, salt, timeCost, memoryCost, parallelism, hashLength }) {
    if (typeof argon2 !== 'function') throw new Error('Argon2id needs react-native-argon2.');
    const result = await argon2(String(secret), toHex(bytes(salt)), {
      mode: 'argon2id',
      hashLength,
      iterations: timeCost,
      memory: memoryCost,
      parallelism,
      saltEncoding: 'hex'
    });
    return fromHex(String(result.rawHash));
  }

  /**
   * Backup archive key with the parameters the ARCHIVE recorded (§6). scrypt is
   * refused: React Native has none, and a pure-JS one would have to run below
   * the cost floor. The desktop opens those and can re-save them as v3.
   */
  function deriveKey({ passphrase, salt, kdf }) {
    const name = String((kdf && kdf.name) || '');
    if (name !== 'argon2id') {
      throw new Error(name === 'scrypt'
        ? 'This backup uses the older scrypt format, which phones cannot open. '
          + 'Restore it on the desktop app, which can also save it in the current format.'
        : `Unsupported backup key-derivation scheme: ${name || 'missing'}`);
    }
    return argon2idRaw({
      secret: passphrase,
      salt,
      timeCost: Number(kdf.timeCost ?? 3),
      memoryCost: Number(kdf.memoryCost ?? 65536),
      parallelism: Number(kdf.parallelism ?? 1),
      hashLength: Number(kdf.keyLength ?? 32)
    });
  }

  // X25519 (SPEC.md §8, sync sessions) through the Node-compatible KeyObject API
  // react-native-quick-crypto provides; the same DER wrapping as src/node/.
  const X25519_SPKI_PREFIX = fromHex('302a300506032b656e032100');
  const X25519_PKCS8_PREFIX = fromHex('302e020100300506032b656e04220420');

  function x25519GenerateKeyPair({ exportPrivate = false } = {}) {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('x25519');
    const spki = bytes(publicKey.export({ format: 'der', type: 'spki' }));
    const pub = spki.slice(X25519_SPKI_PREFIX.length);
    if (!exportPrivate) return { privateKey, publicKey: pub };
    const pkcs8 = bytes(privateKey.export({ format: 'der', type: 'pkcs8' }));
    return { privateKey: pkcs8.slice(X25519_PKCS8_PREFIX.length), publicKey: pub };
  }

  function x25519SharedSecret(privateKey, peerPublic) {
    const priv = privateKey instanceof Uint8Array
      ? Crypto.createPrivateKey({ key: NodeLikeBuffer.from(concat(X25519_PKCS8_PREFIX, bytes(privateKey))), format: 'der', type: 'pkcs8' })
      : privateKey;
    const pub = Crypto.createPublicKey({ key: NodeLikeBuffer.from(concat(X25519_SPKI_PREFIX, bytes(peerPublic))), format: 'der', type: 'spki' });
    return bytes(Crypto.diffieHellman({ privateKey: priv, publicKey: pub }));
  }

  const toBase64 = (value) => NodeLikeBuffer.from(bytes(value)).toString('base64');
  const fromBase64 = (value) => bytes(NodeLikeBuffer.from(String(value || ''), 'base64'));

  return Object.freeze({
    randomBytes: (length) => bytes(Crypto.randomBytes(length)),
    aesGcmSeal,
    aesGcmOpen,
    hkdfSha256: ({ key, salt, info, length }) => bytes(Crypto.hkdfSync('sha256', key, salt, info, length)),
    hmacSha256: (key, data) => bytes(Crypto.createHmac('sha256', bytes(key)).update(bytes(data)).digest()),
    sha256: (data) => bytes(Crypto.createHash('sha256').update(bytes(data)).digest()),
    sha256Hex: (data) => toHex(bytes(Crypto.createHash('sha256').update(bytes(data)).digest())),
    x25519GenerateKeyPair,
    x25519SharedSecret,
    argon2idRaw,
    deriveKey,
    gzip: (data) => bytes(gzip(bytes(data))),
    /** @param {Uint8Array} data @param {{ maxOutputLength?: number }} [options] */
    gunzip: (data, options) => {
      const limit = options && options.maxOutputLength;
      if (!limit) return bytes(gunzip(bytes(data)));
      // A cap that cannot be enforced is refused, never silently dropped.
      if (!Gunzip) {
        throw new Error('gunzip with maxOutputLength needs fflate\'s streaming Gunzip: pass it to createReactNativeAdapter.');
      }
      return boundedGunzip(bytes(data), limit);
    },
    toBase64,
    fromBase64,
    utf8ToBytes: (value) => new TextEncoder().encode(String(value)),
    bytesToUtf8: (data) => new TextDecoder().decode(bytes(data))
  });
}

module.exports = { createReactNativeAdapter };
