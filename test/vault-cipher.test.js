/**
 * Cipher suite 3 — every credential half is bound to its vault, item and half.
 *
 * Real AES-GCM throughout (the desktop adapter). The swap tests are the point:
 * each one is a ciphertext that an older suite would have opened in the wrong
 * place.
 */
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { nodeAdapter as adapter } from '../src/node/index.js';
import {
  CIPHER_SUITE,
  CREDENTIAL_KEY_INFO,
  CREDENTIAL_KEY_SALT,
  credentialAad,
  documentKeyAad,
  parseCredentialIv,
  credentialIvSuite,
  isCurrentCredentialIv,
  sealCredentialHalf,
  openCredentialHalf,
} from '../src/crypto/vault-cipher.js';

const VAULT = 'vault-1';
const OPEN_KEY = crypto.randomBytes(32);
const CMK = crypto.randomBytes(32);
const json = (value) => new TextEncoder().encode(JSON.stringify(value));
const text = (bytes) => JSON.parse(Buffer.from(bytes).toString('utf8'));

function seal(value, key, itemId, half, vaultId = VAULT) {
  return sealCredentialHalf(json(value), key, { vaultId, itemId, half }, adapter);
}

function open(sealed, key, itemId, half, extra = {}) {
  return text(openCredentialHalf({ ...sealed, key, vaultId: VAULT, itemId, half, ...extra }, adapter));
}

/** A half exactly as suite 1 wrote it: bare 12-byte nonce, no AAD. */
function legacySeal(value, key) {
  const nonce = crypto.randomBytes(12);
  const { ciphertext, tag } = adapter.aesGcmSeal({ plaintext: json(value), key, iv: nonce, aad: null });
  return { ciphertext, iv: nonce, tag };
}

/** A half exactly as suite 2 wrote it: [2][nonce], AAD "cred:v2|<id>|<half>". Built here: the core no longer can. */
function suite2Seal(value, key, itemId, half) {
  const nonce = crypto.randomBytes(12);
  const { ciphertext, tag } = adapter.aesGcmSeal({ plaintext: json(value), key, iv: nonce, aad: Buffer.from(`cred:v2|${itemId}|${half}`) });
  return { ciphertext, iv: Buffer.concat([Buffer.from([2]), nonce]), tag };
}

describe('the on-disk constants', () => {
  it('are the exact strings every stored credential was sealed under', () => {
    // Changing either silently makes every row undecryptable.
    expect(CREDENTIAL_KEY_SALT).toBe('papersafeai:local-vault');
    expect(CREDENTIAL_KEY_INFO).toBe('papersafeai:credentials:v1');
  });

  it('builds the documented AAD bytes (pinned)', () => {
    expect(Buffer.from(credentialAad({ vaultId: 'v', itemId: 'item-1', half: 'open' })).toString())
      .toBe('{"component":"vault-v3","part":"open","primaryKey":["item-1"],"recordType":"credential","vaultId":"v"}');
    expect(Buffer.from(documentKeyAad({ vaultId: 'v', documentId: 'doc-1' })).toString())
      .toBe('{"component":"vault-v3","primaryKey":["doc-1"],"recordType":"document_key","vaultId":"v"}');
    expect(() => credentialAad({ vaultId: 'v', itemId: '', half: 'open' })).toThrow(/item id/);
    expect(() => credentialAad({ vaultId: 'v', itemId: 'x', half: 'other' })).toThrow(/part/);
    expect(() => credentialAad({ itemId: 'x', half: 'open' })).toThrow(/vaultId/);
  });
});

describe('round trips', () => {
  it('open and secret halves come back for the vault and item they were sealed for', () => {
    const openHalf = seal({ title: 'Bank' }, OPEN_KEY, 'item-1', 'open');
    const secretHalf = seal({ password: 'hunter2' }, CMK, 'item-1', 'secret');
    expect(open(openHalf, OPEN_KEY, 'item-1', 'open')).toEqual({ title: 'Bank' });
    expect(open(secretHalf, CMK, 'item-1', 'secret')).toEqual({ password: 'hunter2' });
  });

  it('marks the stored iv as suite 3: 13 bytes, leading 3', () => {
    const { iv } = seal({}, OPEN_KEY, 'item-1', 'open');
    expect(iv).toHaveLength(13);
    expect(iv[0]).toBe(CIPHER_SUITE);
    expect(CIPHER_SUITE).toBe(3);
    expect(isCurrentCredentialIv(iv)).toBe(true);
    expect(parseCredentialIv(iv).nonce).toHaveLength(12);
  });

  it('refuses a binding passed the suite-2 way (positional id)', () => {
    expect(() => sealCredentialHalf(json({}), OPEN_KEY, 'item-1', adapter)).toThrow();
  });
});

describe('a ciphertext moved to the wrong place FAILS', () => {
  it('an open half swapped onto another item', () => {
    const a = seal({ title: 'A' }, OPEN_KEY, 'item-a', 'open');
    expect(() => open(a, OPEN_KEY, 'item-b', 'open')).toThrow();
    // Suite 1 would have opened it anywhere (no AAD); it is not read at all now.
    expect(() => open(legacySeal({ title: 'A' }, OPEN_KEY), OPEN_KEY, 'item-b', 'open')).toThrow(/older format/);
  });

  it('a secret half swapped onto another item', () => {
    const a = seal({ password: 'a' }, CMK, 'item-a', 'secret');
    expect(() => open(a, CMK, 'item-b', 'secret')).toThrow();
  });

  it('a secret half put in the OPEN slot — even if the two keys were the same', () => {
    const secret = seal({ password: 'x' }, OPEN_KEY, 'item-a', 'secret');
    expect(() => open(secret, OPEN_KEY, 'item-a', 'open')).toThrow();
  });

  it('a half moved to ANOTHER VAULT holding the same key material', () => {
    const a = seal({ title: 'A' }, OPEN_KEY, 'item-a', 'open', 'vault-A');
    expect(() => open(a, OPEN_KEY, 'item-a', 'open', { vaultId: 'vault-B' })).toThrow();
    expect(open(a, OPEN_KEY, 'item-a', 'open', { vaultId: 'vault-A' })).toEqual({ title: 'A' });
    // Suite 2 bound no vault, so the same move opened; it is not read at all now.
    const s2 = suite2Seal({ title: 'A' }, OPEN_KEY, 'item-a', 'open');
    expect(() => open(s2, OPEN_KEY, 'item-a', 'open', { vaultId: 'vault-B' })).toThrow(/older format/);
  });
});

describe('downgrades and malformed framing are refused', () => {
  const good = () => seal({ title: 'A' }, OPEN_KEY, 'item-a', 'open');

  it('an iv with its version byte stripped (a downgrade to "unbound")', () => {
    const downgraded = { ...good(), iv: good().iv.slice(1) };
    expect(() => open(downgraded, OPEN_KEY, 'item-a', 'open')).toThrow(/older format/);
  });

  it('an iv relabelled as suite 2 (same nonce) does not open under the old AAD', () => {
    const sealed = good();
    const relabelled = { ...sealed, iv: Uint8Array.from([2, ...sealed.iv.slice(1)]) };
    expect(() => open(relabelled, OPEN_KEY, 'item-a', 'open')).toThrow(/older format/);
  });

  it('a genuine suite-2 or suite-1 half is never read, whatever the caller passes', () => {
    const s2 = suite2Seal({ title: 'Two' }, OPEN_KEY, 'item-1', 'open');
    const s1 = legacySeal({ title: 'One' }, OPEN_KEY);
    for (const old of [s1, s2]) {
      expect(() => open(old, OPEN_KEY, 'item-1', 'open')).toThrow(/older format/);
      // The old way to ask for them is gone: an extra option changes nothing.
      expect(() => open(old, OPEN_KEY, 'item-1', 'open', { minSuite: 1 })).toThrow(/older format/);
    }
  });

  it('a truncated or extended tag is refused before AES-GCM sees it', () => {
    const sealed = good();
    for (const tag of [sealed.tag.slice(0, 4), sealed.tag.slice(0, 12), sealed.tag.slice(0, 15), Buffer.concat([sealed.tag, Buffer.from([0])])]) {
      expect(() => open({ ...sealed, tag }, OPEN_KEY, 'item-a', 'open'), `tag ${tag.length}`).toThrow(/tag/);
    }
  });

  it('a truncated or extended iv is refused', () => {
    const sealed = good();
    for (const iv of [sealed.iv.slice(0, 12), sealed.iv.slice(0, 8), Buffer.concat([sealed.iv, Buffer.from([0])]), new Uint8Array(0)]) {
      expect(() => open({ ...sealed, iv }, OPEN_KEY, 'item-a', 'open'), `iv ${iv.length}`).toThrow();
    }
  });

  it('an unknown suite byte says "update the app", never guesses', () => {
    const newer = Uint8Array.from(good().iv);
    newer[0] = 4;
    expect(() => parseCredentialIv(newer)).toThrow(/update the app/);
    expect(() => parseCredentialIv(new Uint8Array(16))).toThrow(/update the app/);
    expect(credentialIvSuite(new Uint8Array(12))).toBe(0);
    expect(credentialIvSuite(newer)).toBe(0);
    expect(() => open({ ...good(), iv: newer }, OPEN_KEY, 'item-a', 'open')).toThrow(/update the app/);
  });


});

describe('nonces', () => {
  it('are random per seal: 2,000 seals of the same value under the same key never repeat one', () => {
    const seen = new Set();
    for (let i = 0; i < 2000; i += 1) seen.add(Buffer.from(seal({ same: true }, OPEN_KEY, 'item-1', 'open').iv).toString('hex'));
    expect(seen.size).toBe(2000);
  });

  it('come from the adapter\'s randomBytes, never from the content (a stuck RNG shows up as a repeat)', () => {
    let calls = 0;
    const counting = { ...adapter, randomBytes: (n) => { calls += 1; return adapter.randomBytes(n); } };
    seal({}, OPEN_KEY, 'item-1', 'open', VAULT);
    sealCredentialHalf(json({}), OPEN_KEY, { vaultId: VAULT, itemId: 'x', half: 'open' }, counting);
    expect(calls).toBeGreaterThanOrEqual(1);
  });

  it('an adapter that drops the AAD is refused before it seals anything', () => {
    const dropsAad = { ...adapter, aesGcmSeal: (a) => adapter.aesGcmSeal({ ...a, aad: null }), aesGcmOpen: (a) => adapter.aesGcmOpen({ ...a, aad: null }) };
    expect(() => sealCredentialHalf(json({}), OPEN_KEY, { vaultId: VAULT, itemId: 'x', half: 'open' }, dropsAad))
      .toThrow(/ignores associated data/);
  });
});
