/**
 * Trying to break the per-document key rule, under cipher suite 3.
 *
 * `documentKeyFor` decides which key opens a document. Under suite 3 its rule
 * is: a document opens ONLY with its own key, wrapped bound to its vault and
 * id. A row with no key, or an older wrap, is refused — and must never quietly
 * resolve to the vault key.
 *
 * These use values a real row can actually hold: what a JSON round trip
 * produces, what a sync payload produces, what a restored backup produces,
 * what a corrupt or hostile row produces.
 *
 * The bar throughout is **fail closed, never fail wrong**.
 */
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  generateDocumentKey,
  wrapDocumentKey,
  unwrapDocumentKey,
  documentKeyFor,
  hasDocumentKey,
  DEK_LENGTH,
} from '../src/crypto/document-key.js';

/** Node's half of the shared adapter contract. */
const adapter = {
  randomBytes: (n) => new Uint8Array(crypto.randomBytes(n)),
  hkdfSha256: ({ key, salt, info, length }) => new Uint8Array(crypto.hkdfSync('sha256', key, salt, info, length)),
  aesGcmSeal: ({ plaintext, key, iv, aad }) => {
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(iv));
    if (aad) cipher.setAAD(Buffer.from(aad));
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    return { ciphertext: new Uint8Array(ciphertext), tag: new Uint8Array(cipher.getAuthTag()) };
  },
  aesGcmOpen: ({ ciphertext, key, iv, tag, aad }) => {
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(iv));
    if (aad) decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(Buffer.from(tag));
    return new Uint8Array(Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]));
  },
  toBase64: (bytes) => Buffer.from(bytes).toString('base64'),
  fromBase64: (value) => new Uint8Array(Buffer.from(String(value || ''), 'base64')),
  sha256Hex: (bytes) => crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex'),
  utf8ToBytes: (v) => new Uint8Array(Buffer.from(String(v), 'utf8')),
  bytesToUtf8: (b) => Buffer.from(b).toString('utf8'),
  gzip: (b) => b,
  gunzip: (b) => b,
  deriveKey: async () => new Uint8Array(32),
};

const VAULT_KEY = new Uint8Array(crypto.randomBytes(32));
const VAULT = 'vault-1';
const B = { vaultId: VAULT, documentId: 'd' };
const CURRENT = { vaultId: VAULT };
// What a caller once passed to admit older suites; it must change nothing now.
const LEGACY = { vaultId: VAULT, minSuite: 1 };
const same = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

describe('THE rule: no current key, no read', () => {
  it('refuses every shape an absent value actually takes, however it is asked', () => {
    for (const absent of [undefined, null, '', 0, false, NaN]) {
      for (const row of [{ id: 'd', wrapped_dek: absent }, { id: 'd', wrappedDek: absent }, { id: 'd' }]) {
        expect(() => documentKeyFor(row, VAULT_KEY, adapter, CURRENT), JSON.stringify({ absent, row })).toThrow(/no key of its own/);
        expect(() => documentKeyFor(row, VAULT_KEY, adapter, LEGACY), JSON.stringify({ absent, row })).toThrow(/no key of its own/);
      }
    }
  });

  it('refuses a row that is not an object at all', () => {
    for (const row of [null, undefined]) {
      expect(() => documentKeyFor(row, VAULT_KEY, adapter, CURRENT), String(row)).toThrow();
    }
  });

  it('accepts snake_case and camelCase identically', () => {
    const dek = generateDocumentKey(adapter);
    const wrapped = wrapDocumentKey(dek, VAULT_KEY, adapter, B);

    const fromSnake = documentKeyFor({ id: 'd', wrapped_dek: wrapped }, VAULT_KEY, adapter, CURRENT);
    const fromCamel = documentKeyFor({ id: 'd', wrappedDek: wrapped }, VAULT_KEY, adapter, CURRENT);

    expect(fromSnake.perDocument).toBe(true);
    expect(same(fromSnake.key, fromCamel.key)).toBe(true);
    expect(same(fromSnake.key, dek)).toBe(true);
  });
});

describe('a corrupt or hostile wrapping fails closed', () => {
  const openWith = (wrapped) => () => documentKeyFor({ id: 'd', wrapped_dek: wrapped }, VAULT_KEY, adapter, LEGACY);

  it('refuses rather than falling back to the vault key', () => {
    // The dangerous alternative. A wrapping that cannot be opened must NOT
    // quietly resolve to the vault key: the document was encrypted under a
    // different key, so the vault key would decrypt it to garbage and hand that
    // back as though it were the file.
    for (const junk of [
      'not-base64-at-all!!!',
      Buffer.from('too short').toString('base64'),
      // (Not the empty string: that is ABSENT, covered above.)
      Buffer.alloc(60).toString('base64'),
      'null',      // what a JSON round trip makes of a null
      'undefined',
      '{}',
      ' ',
    ]) {
      expect(openWith(junk), junk).toThrow();
    }
  });

  it('refuses a wrapping whose tag was altered', () => {
    // A row can be edited by anything that can write the database — a restored
    // backup, a sync push from a compromised device, a hand-edited file.
    const wrapped = wrapDocumentKey(generateDocumentKey(adapter), VAULT_KEY, adapter, B);
    const bytes = Buffer.from(wrapped, 'base64');
    bytes[13] ^= 0xff; // inside the tag

    expect(openWith(bytes.toString('base64'))).toThrow();
  });

  it('refuses a wrapping made under a DIFFERENT vault key', () => {
    // What a restored backup from another vault looks like.
    const otherVaultKey = new Uint8Array(crypto.randomBytes(32));
    const wrapped = wrapDocumentKey(generateDocumentKey(adapter), otherVaultKey, adapter, B);

    expect(openWith(wrapped)).toThrow();
  });

  it('refuses a wrapping with an unknown version byte', () => {
    // Forward compatibility failing CLOSED. A newer build's envelope must be
    // refused, not guessed at — guessing means decrypting with the wrong
    // interpretation and returning bytes.
    const wrapped = wrapDocumentKey(generateDocumentKey(adapter), VAULT_KEY, adapter, B);
    const bytes = Buffer.from(wrapped, 'base64');
    bytes[0] = 99;

    expect(openWith(bytes.toString('base64'))).toThrow();
  });

  it('never returns a key that is not the right length', () => {
    // A short key would be accepted by some ciphers and produce garbage rather
    // than an error.
    const dek = generateDocumentKey(adapter);
    expect(dek).toHaveLength(DEK_LENGTH);
    expect(unwrapDocumentKey(wrapDocumentKey(dek, VAULT_KEY, adapter, B), VAULT_KEY, adapter, B))
      .toHaveLength(DEK_LENGTH);
  });
});

describe('hasDocumentKey agrees with the key rule', () => {
  it('says "no key" for exactly the rows documentKeyFor refuses as keyless', () => {
    const wrapped = wrapDocumentKey(generateDocumentKey(adapter), VAULT_KEY, adapter, B);
    const rows = [
      { id: 'd' }, { id: 'd', wrapped_dek: null }, { id: 'd', wrapped_dek: '' }, { id: 'd', wrappedDek: undefined },
      { id: 'd', wrapped_dek: wrapped }, { id: 'd', wrappedDek: wrapped },
    ];
    for (const row of rows) {
      let keyless = false;
      try { documentKeyFor(row, VAULT_KEY, adapter, CURRENT); } catch (e) { keyless = /no key of its own/.test(e.message); }
      expect(hasDocumentKey(row), JSON.stringify(row)).toBe(!keyless);
    }
  });

  it('says "has a key" for a row it cannot open', () => {
    // A corrupt wrapping is not a keyless row: it is refused for what it is.
    expect(hasDocumentKey({ wrapped_dek: 'garbage' })).toBe(true);
  });
});

describe('every document gets its own key', () => {
  it('never reuses a key across documents', () => {
    // The entire point. A shared key means handing someone one document hands
    // them all of them.
    const keys = new Set();
    for (let i = 0; i < 200; i += 1) {
      keys.add(Buffer.from(generateDocumentKey(adapter)).toString('hex'));
    }
    expect(keys.size).toBe(200);
  });

  it('never produces the same wrapping twice for the same key', () => {
    // A deterministic wrapping would leak that two documents share a key, and
    // under AES-GCM a repeated IV loses confidentiality outright.
    const dek = generateDocumentKey(adapter);
    const wrappings = new Set();
    for (let i = 0; i < 50; i += 1) {
      wrappings.add(wrapDocumentKey(dek, VAULT_KEY, adapter, B));
    }
    expect(wrappings.size).toBe(50);
  });

  it('round-trips through a JSON payload, which is how it reaches a phone', () => {
    // The wrapping travels as a string in a sync payload and inside a backup
    // bundle. A value that does not survive JSON is a value that arrives broken.
    const dek = generateDocumentKey(adapter);
    const row = JSON.parse(JSON.stringify({ id: 'd', wrapped_dek: wrapDocumentKey(dek, VAULT_KEY, adapter, B) }));

    expect(same(documentKeyFor(row, VAULT_KEY, adapter, CURRENT).key, dek)).toBe(true);
  });
});
