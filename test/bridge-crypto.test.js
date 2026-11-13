/**
 * Browser extension <-> desktop bridge (SPEC.md §9).
 *
 * The stored vector is opened twice: by the core itself, and by an independent
 * reader written from the spec with node:crypto alone. Together they pin the
 * format — a change to the key derivation, the AAD or the frame layout fails
 * one or both.
 */
import './setup.mjs'; // example record types (scripts/example-record-types.js)
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as bridge from '../src/bridge/bridge-crypto.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const vector = JSON.parse(fs.readFileSync(path.join(here, '..', 'test-vectors', 'bridge-v1.json'), 'utf8'));
const subtle = globalThis.crypto.subtle;
const CURVE = { name: 'ECDH', namedCurve: 'P-256' };
const b64 = (value) => Buffer.from(value, 'base64');

async function vectorSessionKey(side = 'extension') {
  const mine = side === 'extension' ? vector.extension : vector.desktop;
  const theirs = side === 'extension' ? vector.desktop : vector.extension;
  const privateKey = await subtle.importKey('pkcs8', b64(mine.privateKeyPkcs8), CURVE, false, ['deriveBits']);
  const peerPublicKey = await bridge.importPublicKey(theirs.publicKey);
  return bridge.deriveSessionKey({ privateKey, peerPublicKey, clientNonce: vector.clientNonce, serverNonce: vector.serverNonce });
}

/** The frame's own timestamp, so `open` judges staleness against when it was sealed. */
function sealedAt() {
  const { frame } = vector;
  const key = independentSessionKey();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, b64(frame.iv));
  const ct = b64(frame.ct);
  decipher.setAAD(Buffer.from(`${vector.protocol}|${frame.direction}|${frame.seq}`));
  decipher.setAuthTag(ct.subarray(ct.length - 16));
  return JSON.parse(Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]).toString('utf8')).ts;
}

/** SPEC.md §9 with node:crypto only: ECDH P-256, then HKDF-SHA256(salt = clientNonce || serverNonce, info = protocol). */
function independentSessionKey() {
  const ecdh = crypto.createPrivateKey({ key: b64(vector.extension.privateKeyPkcs8), format: 'der', type: 'pkcs8' });
  const peer = crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', ...rawPointToJwk(b64(vector.desktop.publicKey)) }, format: 'jwk'
  });
  const shared = crypto.diffieHellman({ privateKey: ecdh, publicKey: peer });
  const salt = Buffer.concat([b64(vector.clientNonce), b64(vector.serverNonce)]);
  return Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.from(vector.protocol), 32));
}

function rawPointToJwk(raw) {
  const url = (bytes) => bytes.toString('base64url');
  return { x: url(raw.subarray(1, 33)), y: url(raw.subarray(33, 65)) };
}

describe('bridge vector', () => {
  it('fingerprint = hex(SHA-256(raw public key))', async () => {
    expect(await bridge.fingerprint(vector.extension.publicKey)).toBe(vector.extension.fingerprint);
    expect(crypto.createHash('sha256').update(b64(vector.extension.publicKey)).digest('hex')).toBe(vector.extension.fingerprint);
  });

  it('opens with the core, from either side of the ECDH', async () => {
    for (const side of ['extension', 'desktop']) {
      const key = await vectorSessionKey(side);
      const payload = await bridge.open(key, vector.frame, { direction: 'c2s', expectedSeq: 1, now: sealedAt() });
      expect(payload).toEqual(vector.payload);
    }
  });

  it('opens with an independent reader: AES-256-GCM, AAD "<protocol>|<direction>|<seq>", tag appended to ct', () => {
    const { frame } = vector;
    const key = independentSessionKey();
    const ct = b64(frame.ct);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, b64(frame.iv));
    decipher.setAAD(Buffer.from(`${vector.protocol}|c2s|1`));
    decipher.setAuthTag(ct.subarray(ct.length - 16));
    const plain = JSON.parse(Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]).toString('utf8'));
    expect(plain.payload).toEqual(vector.payload);
    expect(typeof plain.ts).toBe('number');
  });
});

describe('bridge framing', () => {
  async function session() {
    const extension = await bridge.generateKeyPair();
    const desktop = await bridge.generateKeyPair();
    const nonces = { clientNonce: bridge.toBase64(bridge.randomBytes(32)), serverNonce: bridge.toBase64(bridge.randomBytes(32)) };
    const ext = await bridge.deriveSessionKey({ privateKey: extension.privateKey, peerPublicKey: desktop.publicKey, ...nonces });
    const desk = await bridge.deriveSessionKey({ privateKey: desktop.privateKey, peerPublicKey: extension.publicKey, ...nonces });
    return { ext, desk };
  }

  it('round-trips between the two sides', async () => {
    const { ext, desk } = await session();
    const frame = await bridge.seal(ext, { hello: 1 }, { direction: 'c2s', seq: 0 });
    expect(await bridge.open(desk, frame, { direction: 'c2s', expectedSeq: 0 })).toEqual({ hello: 1 });
  });

  it('refuses a replayed, reordered, reflected, tampered or stale frame', async () => {
    const { ext, desk } = await session();
    const frame = await bridge.seal(ext, { hello: 1 }, { direction: 'c2s', seq: 3 });
    await expect(bridge.open(desk, frame, { direction: 'c2s', expectedSeq: 4 })).rejects.toThrow(/sequence/);
    await expect(bridge.open(desk, frame, { direction: 's2c', expectedSeq: 3 })).rejects.toThrow();
    const tampered = { ...frame, ct: bridge.toBase64(bridge.fromBase64(frame.ct).map((b, i) => (i === 0 ? b ^ 1 : b))) };
    await expect(bridge.open(desk, tampered, { direction: 'c2s', expectedSeq: 3 })).rejects.toThrow();
    await expect(bridge.open(desk, frame, { direction: 'c2s', expectedSeq: 3, now: Date.now() + bridge.MAX_CLOCK_SKEW_MS + 1000 }))
      .rejects.toThrow(/stale/);
  });

  it('gives a different key to every session, even between the same two identities', async () => {
    const extension = await bridge.generateKeyPair();
    const desktop = await bridge.generateKeyPair();
    const derive = () => bridge.deriveSessionKey({
      privateKey: extension.privateKey, peerPublicKey: desktop.publicKey,
      clientNonce: bridge.toBase64(bridge.randomBytes(32)), serverNonce: bridge.toBase64(bridge.randomBytes(32))
    });
    const a = await derive();
    const frame = await bridge.seal(a, 'x', { direction: 'c2s', seq: 0 });
    await expect(bridge.open(await derive(), frame, { direction: 'c2s', expectedSeq: 0 })).rejects.toThrow();
  });
});
