/**
 * AES-GCM nonces: every sealer takes its 96-bit nonce straight from the
 * platform RNG, never from the content, the id or a counter. A deterministic
 * nonce under a reused key is the one way AES-GCM fails catastrophically
 * (keystream reuse and tag forgery), so this is checked for every sealer that
 * uses a long-lived key: credential halves, document key wraps and catalogue
 * records.
 */
import './setup.mjs'; // example record types (scripts/example-record-types.js)
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { nodeAdapter as gcmAdapter } from '../src/node/index.js';
import { sealCredentialHalf } from '../src/crypto/vault-cipher.js';
import { wrapDocumentKey, generateDocumentKey } from '../src/crypto/document-key.js';
import { sealRecord } from '../src/sync/catalog/seal.js';

/** The real adapter, recording every nonce the RNG handed out and every nonce a seal used. */
function recording() {
  const handedOut = [];
  const used = [];
  const adapter = {
    ...gcmAdapter,
    randomBytes: (n) => {
      const bytes = gcmAdapter.randomBytes(n);
      if (n === 12) handedOut.push(Buffer.from(bytes).toString('hex'));
      return bytes;
    },
    aesGcmSeal: (args) => {
      used.push(Buffer.from(args.iv).toString('hex'));
      return gcmAdapter.aesGcmSeal(args);
    },
  };
  return { adapter, handedOut, used };
}

const KEY = crypto.randomBytes(32);
const SEALERS = {
  'credential half': (adapter) => sealCredentialHalf(new Uint8Array([1]), KEY, { vaultId: 'v', itemId: 'same', half: 'open' }, adapter),
  'document key wrap': (adapter) => wrapDocumentKey(new Uint8Array(32).fill(1), KEY, adapter, { vaultId: 'v', documentId: 'same' }),
  'catalogue record': (adapter) => sealRecord({ vaultId: 'v', recordType: 'record', primaryKey: ['same', 'i'] }, { name: 'x' }, KEY, adapter),
};

describe.each(Object.entries(SEALERS))('%s', (_name, seal) => {
  it('uses a nonce the RNG just produced, and never repeats one for identical input', () => {
    const { adapter, handedOut, used } = recording();
    for (let i = 0; i < 500; i += 1) seal(adapter);
    // The AAD self-test also seals once per adapter; every seal's nonce came from the RNG.
    for (const nonce of used) expect(handedOut).toContain(nonce);
    const sealNonces = used.slice(used.length - 500);
    expect(new Set(sealNonces).size).toBe(500);
  });

  it('a stuck RNG shows up as a repeated nonce (the property is the RNG\'s, not the content\'s)', () => {
    const stuck = { ...gcmAdapter, randomBytes: (n) => new Uint8Array(n).fill(7) };
    const { adapter, used } = recording();
    const pinned = { ...adapter, randomBytes: stuck.randomBytes };
    seal(pinned);
    seal(pinned);
    expect(used.at(-1)).toBe(used.at(-2));
  });
});

it('document keys are random, never derived from the vault key or the id', () => {
  const a = Buffer.from(generateDocumentKey(gcmAdapter));
  const b = Buffer.from(generateDocumentKey(gcmAdapter));
  expect(a.equals(b)).toBe(false);
});
