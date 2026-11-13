/**
 * Per-document keys, cipher suite 3.
 *
 * Tested against real AES-GCM (the desktop adapter), because the properties
 * here decide whether a vault opens at all.
 *
 * A document with no wrapped key, or with a version-1 (unbound) or version-2
 * (item-bound) wrap, is never read: only a suite-3 wrap opens.
 */
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { nodeAdapter as adapter } from '../src/node/index.js';
import {
  DEK_ENVELOPE_VERSION,
  DEK_LENGTH,
  DOCUMENT_WRAP_KEY_INFO,
  deriveDocumentWrapKey,
  generateDocumentKey,
  wrapDocumentKey,
  unwrapDocumentKey,
  documentKeySuite,
  documentKeyFor,
  hasDocumentKey,
  hasCurrentDocumentKey
} from '../src/crypto/document-key.js';

const VAULT_KEY = crypto.randomBytes(32);
const VAULT = 'vault-1';
const DOC = 'doc-a';
const B = { vaultId: VAULT, documentId: DOC };

/** A version-1 wrap, exactly as builds before suite 2 wrote it (no AAD, raw vault key). */
function legacyWrap(dek) {
  const iv = crypto.randomBytes(12);
  const { ciphertext, tag } = adapter.aesGcmSeal({ plaintext: dek, key: VAULT_KEY, iv, aad: null });
  return Buffer.concat([Buffer.from([1]), iv, tag, ciphertext]).toString('base64');
}

/** A version-2 wrap, exactly as suite 2 wrote it ("dek:v2|<id>", raw vault key). Built here: the core no longer can. */
function suite2Wrap(dek, documentId = DOC) {
  const iv = crypto.randomBytes(12);
  const { ciphertext, tag } = adapter.aesGcmSeal({ plaintext: dek, key: VAULT_KEY, iv, aad: Buffer.from(`dek:v2|${documentId}`) });
  return Buffer.concat([Buffer.from([2]), iv, tag, ciphertext]).toString('base64');
}

describe('minting a document key', () => {
  it('is 32 random bytes, never the vault key, never repeated', () => {
    const keys = new Set();
    for (let i = 0; i < 200; i += 1) {
      const dek = Buffer.from(generateDocumentKey(adapter));
      expect(dek).toHaveLength(DEK_LENGTH);
      expect(dek.equals(VAULT_KEY)).toBe(false);
      keys.add(dek.toString('hex'));
    }
    expect(keys.size).toBe(200);
  });
});

describe('the suite-3 wrap key', () => {
  it('is derived for wrapping only: not the vault key, and pinned', () => {
    const fixed = new Uint8Array(32).fill(7);
    const wrapKey = Buffer.from(deriveDocumentWrapKey(fixed, adapter));
    expect(wrapKey.equals(Buffer.from(fixed))).toBe(false);
    expect(DOCUMENT_WRAP_KEY_INFO).toBe('papersafeai:document-key-wrap:v3');
    // Pinned: HKDF-SHA256(0x07*32, "papersafeai:local-vault", "papersafeai:document-key-wrap:v3").
    expect(wrapKey.toString('hex')).toBe(Buffer.from(crypto.hkdfSync(
      'sha256', fixed, 'papersafeai:local-vault', 'papersafeai:document-key-wrap:v3', 32,
    )).toString('hex'));
  });

  it('a suite-3 wrap does NOT open under the raw vault key', () => {
    const dek = generateDocumentKey(adapter);
    const sealed = Buffer.from(wrapDocumentKey(dek, VAULT_KEY, adapter, B), 'base64');
    expect(() => adapter.aesGcmOpen({
      ciphertext: sealed.subarray(29), key: VAULT_KEY, iv: sealed.subarray(1, 13), tag: sealed.subarray(13, 29), aad: null,
    })).toThrow();
  });
});

describe('wrapping and unwrapping (bound to the vault and document)', () => {
  it('round-trips a key for the document it was wrapped for', () => {
    const dek = generateDocumentKey(adapter);
    const wrapped = wrapDocumentKey(dek, VAULT_KEY, adapter, B);
    expect(Buffer.from(unwrapDocumentKey(wrapped, VAULT_KEY, adapter, B)).equals(Buffer.from(dek))).toBe(true);
  });

  it('stamps envelope version 3 and a fresh IV every time', () => {
    const dek = generateDocumentKey(adapter);
    const a = wrapDocumentKey(dek, VAULT_KEY, adapter, B);
    expect(Buffer.from(a, 'base64')[0]).toBe(DEK_ENVELOPE_VERSION);
    expect(DEK_ENVELOPE_VERSION).toBe(3);
    expect(Buffer.from(a, 'base64')).toHaveLength(61);
    expect(a).not.toBe(wrapDocumentKey(dek, VAULT_KEY, adapter, B));
  });

  it('FAILS when the wrapped key is moved onto another document', () => {
    const wrapped = wrapDocumentKey(generateDocumentKey(adapter), VAULT_KEY, adapter, B);
    expect(() => unwrapDocumentKey(wrapped, VAULT_KEY, adapter, { vaultId: VAULT, documentId: 'doc-b' })).toThrow(/could not be opened/);
    expect(() => documentKeyFor({ id: 'doc-b', wrapped_dek: wrapped }, VAULT_KEY, adapter, { vaultId: VAULT })).toThrow();
  });

  it('FAILS when the wrapped key is moved into another vault with the same key material', () => {
    const wrapped = wrapDocumentKey(generateDocumentKey(adapter), VAULT_KEY, adapter, B);
    expect(() => unwrapDocumentKey(wrapped, VAULT_KEY, adapter, { vaultId: 'vault-2', documentId: DOC })).toThrow(/could not be opened/);
  });

  it('refuses to wrap or unwrap without a vault id and document id', () => {
    const dek = generateDocumentKey(adapter);
    expect(() => wrapDocumentKey(dek, VAULT_KEY, adapter)).toThrow(/vaultId, documentId/);
    expect(() => wrapDocumentKey(dek, VAULT_KEY, adapter, DOC)).toThrow();
    expect(() => wrapDocumentKey(dek, VAULT_KEY, adapter, { documentId: DOC })).toThrow(/vaultId/);
    const wrapped = wrapDocumentKey(dek, VAULT_KEY, adapter, B);
    expect(() => unwrapDocumentKey(wrapped, VAULT_KEY, adapter, { vaultId: VAULT, documentId: '' })).toThrow(/document id/);
  });

  it('refuses a different vault key, an altered wrap, an unknown version, a truncated or extended wrap', () => {
    const wrapped = wrapDocumentKey(generateDocumentKey(adapter), VAULT_KEY, adapter, B);
    expect(() => unwrapDocumentKey(wrapped, crypto.randomBytes(32), adapter, B)).toThrow(/could not be opened/);
    const altered = Buffer.from(wrapped, 'base64');
    altered[altered.length - 1] ^= 1;
    expect(() => unwrapDocumentKey(altered.toString('base64'), VAULT_KEY, adapter, B)).toThrow(/could not be opened/);
    const newer = Buffer.from(wrapped, 'base64');
    newer[0] = 4;
    expect(() => unwrapDocumentKey(newer.toString('base64'), VAULT_KEY, adapter, B)).toThrow(/update the app/);
    for (const bad of ['', null, undefined, 'AAAA']) {
      expect(() => unwrapDocumentKey(bad, VAULT_KEY, adapter, B), String(bad)).toThrow(/missing or truncated/);
    }
    const full = Buffer.from(wrapped, 'base64');
    for (const len of [full.length - 1, full.length - 16, 30]) {
      expect(() => unwrapDocumentKey(full.subarray(0, len).toString('base64'), VAULT_KEY, adapter, B), `len ${len}`).toThrow(/wrong length/);
    }
    expect(() => unwrapDocumentKey(Buffer.concat([full, Buffer.from([0])]).toString('base64'), VAULT_KEY, adapter, B)).toThrow(/wrong length/);
  });

  it('refuses a DEK that is not 32 bytes', () => {
    for (const bad of [new Uint8Array(16), new Uint8Array(33), null]) {
      expect(() => wrapDocumentKey(bad, VAULT_KEY, adapter, B), String(bad?.length)).toThrow(/must be 32 bytes/);
    }
  });
});

describe('older suites are never read', () => {
  it('an unbound (v1) or item-bound (v2) wrap is refused, whatever the caller passes', () => {
    for (const wrapped of [legacyWrap(generateDocumentKey(adapter)), suite2Wrap(generateDocumentKey(adapter))]) {
      expect(() => unwrapDocumentKey(wrapped, VAULT_KEY, adapter, B)).toThrow(/older format/);
      // The old way to ask for them is gone: an extra option changes nothing.
      expect(() => unwrapDocumentKey(wrapped, VAULT_KEY, adapter, B, { minSuite: 1 })).toThrow(/older format/);
      expect(() => documentKeyFor({ id: DOC, wrapped_dek: wrapped }, VAULT_KEY, adapter, { vaultId: VAULT })).toThrow(/older format/);
    }
  });

  it('a suite-3 wrap relabelled as v2 or v1 (a downgrade) is refused', () => {
    const wrapped = Buffer.from(wrapDocumentKey(generateDocumentKey(adapter), VAULT_KEY, adapter, B), 'base64');
    for (const version of [2, 1]) {
      const relabelled = Buffer.from(wrapped);
      relabelled[0] = version;
      expect(() => unwrapDocumentKey(relabelled.toString('base64'), VAULT_KEY, adapter, B)).toThrow(/older format/);
    }
  });

  it('a row with NO key is refused — never read under the vault key', () => {
    for (const row of [{ id: DOC }, { id: DOC, wrapped_dek: null }, { id: DOC, wrapped_dek: '' }]) {
      expect(() => documentKeyFor(row, VAULT_KEY, adapter, { vaultId: VAULT }), JSON.stringify(row)).toThrow(/no key of its own/);
      expect(() => documentKeyFor(row, VAULT_KEY, adapter, { vaultId: VAULT, minSuite: 1 })).toThrow(/no key of its own/);
    }
  });
});

describe('choosing the key for a document', () => {
  it('uses the document key, read however the platform spells the column', () => {
    const dek = generateDocumentKey(adapter);
    const wrapped = wrapDocumentKey(dek, VAULT_KEY, adapter, B);
    for (const row of [{ id: DOC, wrapped_dek: wrapped }, { id: DOC, wrappedDek: wrapped }, { wrappedDek: wrapped, documentId: DOC }]) {
      const chosen = documentKeyFor(row, VAULT_KEY, adapter, { vaultId: VAULT });
      expect(chosen.perDocument).toBe(true);
      expect(Buffer.from(chosen.key).equals(Buffer.from(dek))).toBe(true);
    }
  });

  it('reports which rows have a key, and which suite it is', () => {
    const current = wrapDocumentKey(generateDocumentKey(adapter), VAULT_KEY, adapter, B);
    const v2 = suite2Wrap(generateDocumentKey(adapter));
    const unbound = legacyWrap(generateDocumentKey(adapter));
    expect(hasDocumentKey({})).toBe(false);
    expect(hasDocumentKey({ wrapped_dek: unbound })).toBe(true);
    expect(hasCurrentDocumentKey({ wrapped_dek: current }, adapter)).toBe(true);
    expect(hasCurrentDocumentKey({ wrapped_dek: v2 }, adapter)).toBe(false);
    expect(hasCurrentDocumentKey({ wrapped_dek: unbound }, adapter)).toBe(false);
    expect(hasCurrentDocumentKey({}, adapter)).toBe(false);
    // Only suite 3 counts; an older wrap reads as "none this build reads".
    expect([documentKeySuite(unbound, adapter), documentKeySuite(v2, adapter), documentKeySuite(current, adapter)]).toEqual([0, 0, 3]);
    expect(documentKeySuite('', adapter)).toBe(0);
  });

  it('a whole document survives wrap → unwrap → decrypt', () => {
    const plaintext = crypto.randomBytes(4096);
    const dek = generateDocumentKey(adapter);
    const iv = adapter.randomBytes(12);
    const { ciphertext, tag } = adapter.aesGcmSeal({ plaintext, key: dek, iv, aad: null });
    const { key } = documentKeyFor({ id: DOC, wrapped_dek: wrapDocumentKey(dek, VAULT_KEY, adapter, B) }, VAULT_KEY, adapter, { vaultId: VAULT });
    expect(Buffer.from(adapter.aesGcmOpen({ ciphertext, key, iv, tag, aad: null })).equals(plaintext)).toBe(true);
  });

  it('losing one document\'s key does not cost any other document', () => {
    const good = { id: DOC, wrapped_dek: wrapDocumentKey(generateDocumentKey(adapter), VAULT_KEY, adapter, B) };
    const corrupt = { id: 'doc-x', wrapped_dek: 'AwIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=' };
    expect(() => documentKeyFor(corrupt, VAULT_KEY, adapter, { vaultId: VAULT })).toThrow();
    expect(documentKeyFor(good, VAULT_KEY, adapter, { vaultId: VAULT }).perDocument).toBe(true);
  });
});
