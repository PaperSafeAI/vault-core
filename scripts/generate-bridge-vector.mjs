#!/usr/bin/env node
/**
 * Writes test-vectors/bridge-v1.json: a browser-extension <-> desktop session
 * (two P-256 key pairs, the handshake nonces) and one frame sealed by the
 * core's own `seal`. ECDH key generation cannot be made deterministic through
 * WebCrypto, so unlike vault-core-v1.json this file is generated once and kept:
 * test/bridge-crypto.test.js opens it with the core and again with an
 * independent node:crypto reader, which is what pins the format.
 *
 *   node scripts/generate-bridge-vector.mjs --force   # only for a NEW format version
 *
 * TEST KEYS ONLY.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as bridge from '../src/bridge/bridge-crypto.mjs';

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'test-vectors', 'bridge-v1.json');
if (fs.existsSync(OUT) && !process.argv.includes('--force')) {
  console.log('test-vectors/bridge-v1.json exists; pass --force only for a new format version.');
  process.exit(0);
}

const subtle = globalThis.crypto.subtle;
const extension = await bridge.generateKeyPair(true);
const desktop = await bridge.generateKeyPair(true);
const pkcs8 = async (key) => bridge.toBase64(await subtle.exportKey('pkcs8', key));
const clientNonce = bridge.toBase64(bridge.randomBytes(32));
const serverNonce = bridge.toBase64(bridge.randomBytes(32));
const sessionKey = await bridge.deriveSessionKey({
  privateKey: extension.privateKey, peerPublicKey: desktop.publicKey, clientNonce, serverNonce
});
const payload = { type: 'detect-fields', origin: 'https://example.com' };
const frame = await bridge.seal(sessionKey, payload, { direction: 'c2s', seq: 1 });
const extensionPublic = await bridge.exportPublicKey(extension.publicKey);

const vector = {
  description: 'PaperSafeAI browser bridge test vector. TEST KEYS ONLY. See SPEC.md §9.',
  protocol: bridge.PROTOCOL,
  extension: { publicKey: extensionPublic, privateKeyPkcs8: await pkcs8(extension.privateKey), fingerprint: await bridge.fingerprint(extensionPublic) },
  desktop: { publicKey: await bridge.exportPublicKey(desktop.publicKey), privateKeyPkcs8: await pkcs8(desktop.privateKey) },
  clientNonce,
  serverNonce,
  frame: { direction: 'c2s', ...frame },
  payload
};
fs.writeFileSync(OUT, `${JSON.stringify(vector, null, 2)}\n`);
console.log('wrote test-vectors/bridge-v1.json');
