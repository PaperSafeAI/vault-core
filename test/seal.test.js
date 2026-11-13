/**
 * Catalogue keys and sealing.
 *
 * Pinned vectors were computed with Node. The derived keys were cross-checked
 * with a Python HKDF built from hmac/hashlib only; the envelope's layout and AAD
 * are opened independently by test/test-vectors.test.js. The vault key is a
 * test constant, and the record types are the examples in
 * scripts/example-record-types.js.
 */
import './setup.mjs'; // example record types (scripts/example-record-types.js)
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { deriveAuthorityKeys, deriveReplicaKeys, LABELS } from '../src/sync/catalog/keys.js';
import { sealRecord, openRecord, assertBindsAad, hmacWith } from '../src/sync/catalog/seal.js';

const adapter = {
  randomBytes: (n) => new Uint8Array(crypto.randomBytes(n)),
  hkdfSha256: ({ key, salt, info, length }) => new Uint8Array(crypto.hkdfSync('sha256', key, salt, info, length)),
  hmacSha256: (key, bytes) => new Uint8Array(crypto.createHmac('sha256', key).update(bytes).digest()),
  aesGcmSeal({ plaintext, key, iv, aad }) {
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    if (aad) c.setAAD(aad);
    const ciphertext = Buffer.concat([c.update(plaintext), c.final()]);
    return { ciphertext: new Uint8Array(ciphertext), tag: new Uint8Array(c.getAuthTag()) };
  },
  aesGcmOpen({ ciphertext, key, iv, tag, aad }) {
    const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
    if (aad) d.setAAD(aad);
    d.setAuthTag(tag);
    return new Uint8Array(Buffer.concat([d.update(ciphertext), d.final()]));
  },
};
const hex = (b) => Buffer.from(b).toString('hex');
const VAULT_KEY = new Uint8Array(32).fill(1);
const keys = deriveAuthorityKeys(VAULT_KEY, adapter);
const record = { vaultId: 'vault-1', recordType: 'record', primaryKey: ['f1', 'inc-1'] };

describe('derived keys (pinned)', () => {
  it('match the independently computed vectors', () => {
    expect(hex(keys.nameIndex.key)).toBe('2f655fe2c654fcf7272c1e0aa40b16becb97f1e48d70ce0a7d3cf318daab890c');
    expect(hex(keys.digest.key)).toBe('c880f499174746247f80821b831186bbc08641dc73dcaf0bb54cd90366443739');
    expect(hex(keys.payload.key)).toBe('1a8fce4878f94fa4982dc9d9a26a2c7308b30d14c1ec5b431395480214ccb44e');
    expect(keys.nameIndex.id).toBe(LABELS.nameIndex);
  });

  it('give the phone the replica keys but never the receipt digest key', () => {
    const replica = deriveReplicaKeys(VAULT_KEY, adapter);
    expect(hex(replica.nameIndex.key)).toBe(hex(keys.nameIndex.key));
    expect(replica.digest).toBeUndefined();
  });

  it('refuse anything but a 32-byte vault key', () => {
    expect(() => deriveReplicaKeys(new Uint8Array(16), adapter)).toThrow(/32-byte/);
  });
});

describe('envelope (pinned)', () => {
  it('matches the WebCrypto-verified vector for a fixed IV', () => {
    const fixed = { ...adapter, randomBytes: (n) => new Uint8Array(n).fill(0x42) };
    expect(hex(sealRecord(record, { name: 'Taxes', extensions: {} }, keys.payload.key, fixed)))
      .toBe('0142424242424242424242424209f37e4a4ae952f0f3b7021d8a1c140b0a1e7e6de47f5fd64a282611d039e3c0188f43511091313d6d660a108430d41e');
  });
});

describe('AAD binding', () => {
  const sealed = sealRecord(record, { name: 'Taxes' }, keys.payload.key, adapter);

  it('round-trips in its own context', () => {
    expect(openRecord(record, sealed, keys.payload.key, adapter)).toEqual({ name: 'Taxes' });
  });

  it.each([
    ['another row', { ...record, primaryKey: ['f2', 'inc-1'] }],
    ['another incarnation', { ...record, primaryKey: ['f1', 'inc-2'] }],
    ['another record type', { ...record, recordType: 'other_record' }],
    ['another vault', { ...record, vaultId: 'vault-2' }],
  ])('refuses the value moved to %s', (_, context) => {
    expect(() => openRecord(context, sealed, keys.payload.key, adapter)).toThrow();
  });

  it('binds generation-scoped records to their generation, and requires one', () => {
    const conflict = { vaultId: 'vault-1', recordType: 'other_log_entry', primaryKey: ['c1'], generation: 'g1' };
    const blob = sealRecord(conflict, { intended: 1 }, keys.payload.key, adapter);
    expect(openRecord(conflict, blob, keys.payload.key, adapter)).toEqual({ intended: 1 });
    expect(() => openRecord({ ...conflict, generation: 'g2' }, blob, keys.payload.key, adapter)).toThrow();
    expect(() => sealRecord({ ...conflict, generation: undefined }, {}, keys.payload.key, adapter)).toThrow(/generation/);
  });

  it('refuses unknown record types, tampering, a wrong key and an unknown version', () => {
    expect(() => sealRecord({ ...record, recordType: 'recordz' }, {}, keys.payload.key, adapter)).toThrow(/unknown/);
    const flipped = new Uint8Array(sealed); flipped[flipped.length - 1] ^= 1;
    expect(() => openRecord(record, flipped, keys.payload.key, adapter)).toThrow();
    expect(() => openRecord(record, sealed, keys.nameIndex.key, adapter)).toThrow();
    const v2 = new Uint8Array(sealed); v2[0] = 2;
    expect(() => openRecord(record, v2, keys.payload.key, adapter)).toThrow(/envelope/);
  });
});

describe('adapter self-test', () => {
  it('refuses an AES-GCM adapter that ignores associated data (as documentKeyAdapter would)', () => {
    const dropsAad = {
      ...adapter,
      aesGcmSeal: ({ plaintext, key, iv }) => adapter.aesGcmSeal({ plaintext, key, iv, aad: null }),
      aesGcmOpen: ({ ciphertext, key, iv, tag }) => adapter.aesGcmOpen({ ciphertext, key, iv, tag, aad: null }),
    };
    expect(() => assertBindsAad(dropsAad)).toThrow(/ignores associated data/);
    expect(() => sealRecord(record, {}, keys.payload.key, dropsAad)).toThrow(/ignores associated data/);
  });

  it('HMAC closures return 32 bytes under the derived key', () => {
    const mac = hmacWith(keys.nameIndex.key, adapter)(new TextEncoder().encode('x'));
    expect(mac).toHaveLength(32);
    expect(hex(mac)).toBe(hex(crypto.createHmac('sha256', keys.nameIndex.key).update('x').digest()));
  });
});
