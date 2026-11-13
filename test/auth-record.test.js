import './setup.mjs'; // example record types (scripts/example-record-types.js)
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { nodeAdapter as adapter } from '../src/node/index.js';
import * as auth from '../src/kdf/auth-record.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(fs.readFileSync(path.join(here, '..', 'test-vectors', 'vault-core-v1.json'), 'utf8'));
const { authRecord, password } = vectors.vaultUnlock;
const VAULT_KEY = vectors.vaultKeyHex;
const hex = (bytes) => Buffer.from(bytes).toString('hex');

/** A record as the apps write it: one vault key wrapped under the password and the recovery key. */
async function makeRecord({ recoveryKey = 'A1B2-C3D4-E5F6-0718-293A-4B5C', kdfScheme } = {}) {
  const vaultKey = adapter.randomBytes(32);
  const passwordSalt = auth.generateSalt(adapter);
  const recoverySalt = auth.generateSalt(adapter);
  const params = auth.currentKdfParams();
  const record = {
    ...(kdfScheme ? { kdfScheme } : {}),
    passwordSalt: adapter.toBase64(passwordSalt),
    recoverySalt: adapter.toBase64(recoverySalt),
    wrappedVaultKeyByPassword: auth.wrapKey(vaultKey, await auth.deriveWrappingKey('a long master password', passwordSalt, params, adapter), adapter),
    wrappedVaultKeyByRecovery: auth.wrapKey(vaultKey, await auth.deriveWrappingKey(recoveryKey, recoverySalt, params, adapter), adapter)
  };
  return { record, vaultKey, recoveryKey };
}

describe('vault unlock', () => {
  it('opens the vector record with its password', async () => {
    const { vaultKey, wrappingKey } = await auth.unlockWithPassword(authRecord, password, adapter);
    expect(hex(vaultKey)).toBe(VAULT_KEY);
    expect(hex(wrappingKey)).toBe(vectors.vaultUnlock.wrappingKeyHex);
  });

  it('refuses a wrong password', async () => {
    await expect(auth.unlockWithPassword(authRecord, 'not the password', adapter)).rejects.toThrow('Invalid master password.');
  });

  it('reads a record with no scheme as argon2id-v1, and refuses a scheme it does not know', async () => {
    const { kdfScheme, ...legacy } = authRecord;
    expect(kdfScheme).toBe('argon2id-v1');
    expect(hex((await auth.unlockWithPassword(legacy, password, adapter)).vaultKey)).toBe(VAULT_KEY);
    await expect(auth.unlockWithPassword({ ...authRecord, kdfScheme: 'argon2id-v9' }, password, adapter))
      .rejects.toThrow(/Unsupported KDF scheme "argon2id-v9".*update the app/);
  });

  it('opens with the recovery key however it is typed, and says why when it cannot', async () => {
    const { record, vaultKey, recoveryKey } = await makeRecord();
    const typed = recoveryKey.toLowerCase().replace(/-/g, ' ');
    expect(hex((await auth.unlockWithRecoveryKey(record, typed, adapter)).vaultKey)).toBe(hex(vaultKey));
    await expect(auth.unlockWithRecoveryKey(record, 'nope', adapter)).rejects.toThrow('That does not look like a recovery key.');
    await expect(auth.unlockWithRecoveryKey(record, 'FFFF-FFFF-FFFF-FFFF-FFFF-FFFF', adapter)).rejects.toThrow('That recovery key does not open this vault.');
    const { wrappedVaultKeyByRecovery, ...noRecovery } = record;
    expect(wrappedVaultKeyByRecovery).toBeTruthy();
    await expect(auth.unlockWithRecoveryKey(noRecovery, recoveryKey, adapter)).rejects.toThrow(/no recovery key on file/);
  });

  it('normalises recovery keys to the canonical grouped form', () => {
    expect(auth.normaliseRecoveryKey(' a1b2 c3d4-e5f6 0718 293a 4b5c ')).toBe('A1B2-C3D4-E5F6-0718-293A-4B5C');
    expect(auth.normaliseRecoveryKey('A1B2')).toBeNull();
    expect(auth.normaliseRecoveryKey(42)).toBeNull();
  });
});
