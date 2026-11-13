/**
 * The phone adapter, run under Node with Node's crypto standing in for
 * react-native-quick-crypto (the same API) and the argon2 package standing in
 * for react-native-argon2 (same algorithm, hex in, hex out). It must reproduce
 * the published vectors exactly as the Node adapter does.
 */
import './setup.mjs'; // example record types (scripts/example-record-types.js)
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import argon2 from 'argon2';
import * as fflate from 'fflate';
import { createReactNativeAdapter } from '../src/platform/react-native.js';
import { nodeAdapter } from '../src/node/index.js';
import * as auth from '../src/kdf/auth-record.js';
import { sealRecord, openRecord } from '../src/sync/catalog/seal.js';
import { deriveAuthorityKeys } from '../src/sync/catalog/keys.js';
import { deriveDbKeyHex } from '../src/crypto/db-key.js';
import * as transport from '../src/pairing/transport.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(fs.readFileSync(path.join(here, '..', 'test-vectors', 'vault-core-v1.json'), 'utf8'));

/** react-native-argon2's call shape over the argon2 package. */
async function rnArgon2(password, saltHex, { hashLength, iterations, memory, parallelism, saltEncoding, mode }) {
  expect(saltEncoding).toBe('hex');
  expect(mode).toBe('argon2id');
  const raw = await argon2.hash(password, {
    type: argon2.argon2id, salt: Buffer.from(saltHex, 'hex'), hashLength, timeCost: iterations, memoryCost: memory, parallelism, raw: true
  });
  return { rawHash: raw.toString('hex') };
}

const rn = createReactNativeAdapter({ quickCrypto: crypto, argon2: rnArgon2, gzip: zlib.gzipSync, gunzip: zlib.gunzipSync });
const hex = (b) => Buffer.from(b).toString('hex');
const vaultKey = Buffer.from(vectors.vaultKeyHex, 'hex');

describe('phone adapter', () => {
  it('opens the §2 vault-unlock vector', async () => {
    const { vaultKey: opened } = await auth.unlockWithPassword(vectors.vaultUnlock.authRecord, vectors.vaultUnlock.password, rn);
    expect(hex(opened)).toBe(vectors.vaultKeyHex);
  });

  it('derives the §3 database key and §7 catalogue keys exactly as Node does', () => {
    expect(deriveDbKeyHex(vaultKey, rn)).toBe(vectors.databaseKey.keyHex);
    const keys = deriveAuthorityKeys(vaultKey, rn);
    for (const [name, k] of Object.entries(keys)) expect(hex(k.key)).toBe(vectors.catalogRecord.keys[name].keyHex);
  });

  it('opens the §7 catalogue record (and binds AAD, as seal requires)', () => {
    const key = Buffer.from(vectors.catalogRecord.keys.payload.keyHex, 'hex');
    const envelope = Buffer.from(vectors.catalogRecord.envelopeHex, 'hex');
    expect(openRecord(vectors.catalogRecord.context, envelope, key, rn)).toEqual(vectors.catalogRecord.value);
    const sealed = sealRecord(vectors.catalogRecord.context, { a: 1 }, key, rn);
    expect(openRecord(vectors.catalogRecord.context, sealed, key, nodeAdapter)).toEqual({ a: 1 });
  });

  it('opens the §8 transport body and reproduces its key', () => {
    const v = vectors.pairingTransport;
    const key = transport.deriveTransportKey(v.pairingSecretHex, rn);
    expect(hex(key)).toBe(v.transportKeyHex);
    expect(new TextDecoder().decode(transport.openTransport(Buffer.from(v.sealedBodyHex, 'hex'), key, rn))).toBe(v.body);
  });

  it('derives a backup key like Node, and refuses scrypt with a reason', async () => {
    const salt = new Uint8Array(16).fill(7);
    const kdf = { name: 'argon2id', timeCost: 3, memoryCost: 65536, parallelism: 1, keyLength: 32 };
    expect(hex(await rn.deriveKey({ passphrase: 'pass phrase here', salt, kdf })))
      .toBe(hex(await nodeAdapter.deriveKey({ passphrase: 'pass phrase here', salt, kdf })));
    expect(() => rn.deriveKey({ passphrase: 'x', salt, kdf: { name: 'scrypt' } })).toThrow(/scrypt format, which phones cannot open/);
  });

  it('round-trips base64, utf8 and gzip', () => {
    const data = crypto.randomBytes(100);
    expect(hex(rn.fromBase64(rn.toBase64(data)))).toBe(hex(data));
    expect(rn.bytesToUtf8(rn.utf8ToBytes('héllo'))).toBe('héllo');
    expect(hex(rn.gunzip(rn.gzip(data)))).toBe(hex(data));
    expect(rn.sha256Hex(data)).toBe(nodeAdapter.sha256Hex(data));
  });

  it('refuses a short nonce or a truncated tag before decrypting', () => {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const { ciphertext, tag } = rn.aesGcmSeal({ plaintext: Buffer.from('x'), key, iv, aad: null });
    expect(() => rn.aesGcmOpen({ ciphertext, key, iv, tag: tag.subarray(0, 12), aad: null })).toThrow(/16 bytes/);
    expect(() => rn.aesGcmOpen({ ciphertext, key, iv: iv.subarray(0, 8), tag, aad: null })).toThrow(/12 bytes/);
  });
});

describe('phone adapter: backup decompression cap', () => {
  // The real fflate (a dev dependency) at the version the phone ships: it
  // inflates a whole push before calling ondata, which is what the cap has to
  // work around.
  const capped = createReactNativeAdapter({ quickCrypto: crypto, gzip: fflate.gzipSync, gunzip: fflate.gunzipSync, Gunzip: fflate.Gunzip });
  const zeros = fflate.gzipSync(new Uint8Array(1024 * 1024));

  it('stops at the cap with the code openEnvelope recognises', () => {
    let error = null;
    try { capped.gunzip(zeros, { maxOutputLength: 100 * 1024 }); } catch (e) { error = e; }
    expect(error && error.code).toBe('ERR_BUFFER_TOO_LARGE');
  });

  it('feeds the input in pieces, so no step inflates far past the cap', () => {
    // 64 MiB of zeros is ~64 KiB compressed: pushed whole it would come out as
    // one 64 MiB chunk. Fed in 16 KiB pieces, no chunk is above ~16 MiB.
    const big = fflate.gzipSync(new Uint8Array(64 * 1024 * 1024));
    let largest = 0;
    /** Real fflate Gunzip that records the largest chunk it hands to ondata. */
    class Measuring extends fflate.Gunzip {
      push(chunk, final) {
        if (!this.measured) {
          const inner = this.ondata;
          this.ondata = (out, last) => { largest = Math.max(largest, out.length); inner(out, last); };
          this.measured = true;
        }
        return super.push(chunk, final);
      }
    }
    const measured = createReactNativeAdapter({ quickCrypto: crypto, gzip: fflate.gzipSync, gunzip: fflate.gunzipSync, Gunzip: Measuring });
    expect(() => measured.gunzip(big, { maxOutputLength: 8 * 1024 * 1024 })).toThrow(expect.objectContaining({ code: 'ERR_BUFFER_TOO_LARGE' }));
    expect(largest).toBeGreaterThan(0);
    expect(largest).toBeLessThanOrEqual(17 * 1024 * 1024);
  });

  it('returns the whole output under the cap, and an empty input', () => {
    expect(Buffer.from(capped.gunzip(zeros, { maxOutputLength: 2 * 1024 * 1024 })).equals(Buffer.alloc(1024 * 1024))).toBe(true);
    expect(capped.gunzip(fflate.gzipSync(new Uint8Array(0)), { maxOutputLength: 10 }).length).toBe(0);
  });

  it('refuses a cap it cannot enforce, and without a cap uses gunzip', () => {
    expect(() => rn.gunzip(zeros, { maxOutputLength: 2 * 1024 * 1024 })).toThrow(/streaming Gunzip/);
    expect(rn.gunzip(zeros).length).toBe(1024 * 1024);
  });
});
