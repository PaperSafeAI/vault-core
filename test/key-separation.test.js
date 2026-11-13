/**
 * One key, one purpose.
 *
 * Every key the app derives from the vault key is HKDF-SHA256 with its own
 * (salt, info) pair. Two purposes sharing a pair would share a key, and a
 * ciphertext or MAC made for one would be accepted by the other. This lists
 * every derivation from the vault key and checks the pairs, and the keys, are
 * distinct — and that none of them is the vault key itself.
 */
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { DB_KEY_SALT, DB_KEY_INFO } from '../src/crypto/db-key.js';
import { CREDENTIAL_KEY_SALT, CREDENTIAL_KEY_INFO, THUMBNAIL_KEY_INFO, FIELD_KEY_INFO } from '../src/crypto/vault-cipher.js';
import { DOCUMENT_WRAP_KEY_SALT, DOCUMENT_WRAP_KEY_INFO } from '../src/crypto/document-key.js';
import { SALT as CATALOGUE_SALT, LABELS as CATALOGUE_LABELS } from '../src/sync/catalog/keys.js';

const FROM_VAULT_KEY = [
  ['database (SQLCipher)', DB_KEY_SALT, DB_KEY_INFO],
  ['credential open half', CREDENTIAL_KEY_SALT, CREDENTIAL_KEY_INFO],
  ['document key wrap (suite 3)', DOCUMENT_WRAP_KEY_SALT, DOCUMENT_WRAP_KEY_INFO],
  ['phone thumbnail cache', CREDENTIAL_KEY_SALT, THUMBNAIL_KEY_INFO],
  ['desktop column cipher (field-cipher.js)', CREDENTIAL_KEY_SALT, FIELD_KEY_INFO],
  ...Object.entries(CATALOGUE_LABELS).map(([name, label]) => [`catalogue ${name}`, CATALOGUE_SALT, label]),
];

describe('derivations from the vault key', () => {
  it('each has its own (salt, info) pair', () => {
    const pairs = FROM_VAULT_KEY.map(([, salt, info]) => JSON.stringify([salt, info]));
    expect(new Set(pairs).size).toBe(pairs.length);
  });

  it('each yields a different key, and none is the vault key', () => {
    const vaultKey = crypto.randomBytes(32);
    const keys = FROM_VAULT_KEY.map(([, salt, info]) => Buffer.from(crypto.hkdfSync('sha256', vaultKey, salt, info, 32)).toString('hex'));
    expect(new Set(keys).size).toBe(keys.length);
    expect(keys).not.toContain(vaultKey.toString('hex'));
  });
});
