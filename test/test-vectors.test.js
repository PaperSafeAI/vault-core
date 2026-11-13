/**
 * An independent reader of every format in test-vectors/vault-core-v1.json,
 * written from SPEC.md with nothing but node:crypto — none of this package's
 * code is imported here, and every AAD is built by hand from the spec. If the
 * spec and the code ever disagree, this fails. It is also the template for
 * anyone writing their own implementation.
 */
import './setup.mjs'; // example record types (scripts/example-record-types.js)
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(fs.readFileSync(path.join(here, '..', 'test-vectors', 'vault-core-v1.json'), 'utf8'));
const vaultKey = Buffer.from(vectors.vaultKeyHex, 'hex');
const VAULT_ID = vectors.vaultId;
const hkdf = (key, salt, info) => Buffer.from(crypto.hkdfSync('sha256', key, Buffer.from(salt), Buffer.from(info), 32));

/** SPEC.md §1: canonical JSON (sorted keys, no whitespace) of the place a value belongs. */
function aad(fields) {
  const sorted = Object.fromEntries(Object.keys(fields).sort().map((k) => [k, fields[k]]));
  return JSON.stringify(sorted);
}

function gcmOpen({ key, iv, tag, ciphertext, aad: associated }) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAAD(Buffer.from(associated, 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

describe('test vectors, read from SPEC.md alone', () => {
  it('are what the code produces today (a format change is a new version, not an edit)', () => {
    const script = path.join(here, '..', 'scripts', 'generate-test-vectors.js');
    expect(() => execFileSync(process.execPath, [script, '--check'], { stdio: 'pipe' })).not.toThrow();
  });

  it('§2 password KDF: Argon2id, t=3, m=64 MiB, p=1, 32-byte output', () => {
    expect(vectors.passwordKdf.params).toEqual({ kdf: 'argon2id', timeCost: 3, memoryCost: 65536, parallelism: 1, hashLength: 32 });
  });

  it('§3 database key = HKDF-SHA256(vaultKey, salt, info, 32)', () => {
    const { salt, info, keyHex } = vectors.databaseKey;
    expect(hkdf(vaultKey, salt, info).toString('hex')).toBe(keyHex);
  });

  it('§4 credential half (suite 3): iv = [0x03][nonce], AAD binds vault, item and half', () => {
    const v = vectors.credentialOpenHalf;
    const key = hkdf(vaultKey, v.hkdfSalt, v.hkdfInfo);
    expect(key.toString('hex')).toBe(v.keyHex);
    const expectedAad = aad({ component: 'vault-v3', vaultId: VAULT_ID, recordType: 'credential', primaryKey: [v.itemId], part: v.half });
    expect(expectedAad).toBe(v.aad);
    const iv = Buffer.from(v.ivHex, 'hex');
    expect(iv.length).toBe(13);
    expect(iv[0]).toBe(3);
    const plain = gcmOpen({ key, iv: iv.subarray(1), tag: Buffer.from(v.tagHex, 'hex'), ciphertext: Buffer.from(v.ciphertextHex, 'hex'), aad: expectedAad });
    expect(plain.toString('utf8')).toBe(v.plaintext);
  });

  it('§4 a credential moved to another item, half or vault does not open', () => {
    const v = vectors.credentialOpenHalf;
    const iv = Buffer.from(v.ivHex, 'hex').subarray(1);
    const open = (fields) => gcmOpen({
      key: Buffer.from(v.keyHex, 'hex'), iv, tag: Buffer.from(v.tagHex, 'hex'), ciphertext: Buffer.from(v.ciphertextHex, 'hex'),
      aad: aad({ component: 'vault-v3', recordType: 'credential', vaultId: VAULT_ID, primaryKey: [v.itemId], part: v.half, ...fields })
    });
    expect(() => open({ primaryKey: ['item-2'] })).toThrow();
    expect(() => open({ part: 'secret' })).toThrow();
    expect(() => open({ vaultId: 'another-vault' })).toThrow();
  });

  it('§5 wrapped document key (suite 3): [0x03][iv 12][tag 16][ct] under HKDF(vaultKey, wrap salt, wrap info)', () => {
    const v = vectors.documentKey;
    const sealed = Buffer.from(v.wrappedBase64, 'base64');
    expect(sealed[0]).toBe(3);
    const expectedAad = aad({ component: 'vault-v3', vaultId: VAULT_ID, recordType: 'document_key', primaryKey: [v.documentId] });
    expect(expectedAad).toBe(v.aad);
    const dek = gcmOpen({
      key: hkdf(vaultKey, v.wrapKeySalt, v.wrapKeyInfo),
      iv: sealed.subarray(1, 13), tag: sealed.subarray(13, 29), ciphertext: sealed.subarray(29), aad: expectedAad
    });
    expect(dek.toString('hex')).toBe(v.dekHex);
  });

  it('§7 catalogue keys = HKDF-SHA256(vaultKey, "papersafe/catalogue", label, 32)', () => {
    const v = vectors.catalogRecord;
    for (const { info, keyHex } of Object.values(v.keys)) {
      expect(hkdf(vaultKey, v.hkdfSalt, info).toString('hex')).toBe(keyHex);
    }
  });

  it('§7 catalogue record: [0x01][iv 12][tag 16][ct], AAD = canonical JSON of its place', () => {
    const v = vectors.catalogRecord;
    const envelope = Buffer.from(v.envelopeHex, 'hex');
    expect(envelope[0]).toBe(1);
    const plain = gcmOpen({
      key: Buffer.from(v.keys.payload.keyHex, 'hex'),
      iv: envelope.subarray(1, 13), tag: envelope.subarray(13, 29), ciphertext: envelope.subarray(29),
      aad: aad({ component: 'catalogue-v1', ...v.context })
    });
    expect(JSON.parse(plain.toString('utf8'))).toEqual(v.value);
  });

  it('§8 transport key and fingerprint are HMAC-SHA256 of the pairing secret', () => {
    const v = vectors.pairingTransport;
    const secret = Buffer.from(v.pairingSecretHex, 'hex');
    const mac = (info) => crypto.createHmac('sha256', secret).update(info).digest('hex');
    expect(mac(v.transportKeyInfo)).toBe(v.transportKeyHex);
    expect(mac(v.fingerprintInfo).slice(0, 32)).toBe(v.fingerprint);
  });

  it('§8 a sealed body is [nonce 12][tag 16][ciphertext] under the transport key, no AAD', () => {
    const v = vectors.pairingTransport;
    const sealed = Buffer.from(v.sealedBodyHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(v.transportKeyHex, 'hex'), sealed.subarray(0, 12));
    decipher.setAuthTag(sealed.subarray(12, 28));
    expect(Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()]).toString('utf8')).toBe(v.body);
  });

  it('§8 the request signature covers method, path+query, time, nonce and the SEALED body; inst is outside it', () => {
    const v = vectors.pairingTransport;
    const params = Object.fromEntries(v.authorization.replace(/^PapersafeHMAC /, '').split(',').map((p) => p.split('=')));
    expect(params.id).toBe(v.request.deviceId);
    expect(params.inst).toBe('install-1');
    const bodyHash = crypto.createHash('sha256').update(Buffer.from(v.sealedBodyHex, 'hex')).digest('hex');
    const signing = `PSHMAC-v3\n${v.request.method}\n${v.request.target}\n${params.ts}\n${params.nonce}\n${bodyHash}`;
    expect(crypto.createHmac('sha256', Buffer.from(v.pairingSecretHex, 'hex')).update(signing).digest('hex')).toBe(params.sig);
  });

  it('§8 a bound answer carries AAD "psai-resp-v1\\n<METHOD>\\n<target>\\n<nonce>"', () => {
    const v = vectors.pairingTransport;
    const params = Object.fromEntries(v.authorization.replace(/^PapersafeHMAC /, '').split(',').map((p) => p.split('=')));
    const expectedAad = `psai-resp-v1\n${v.request.method}\n${v.request.target}\n${params.nonce}`;
    expect(v.responseBindingAad).toBe(expectedAad);
    const sealed = Buffer.from(v.boundAnswerHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(v.transportKeyHex, 'hex'), sealed.subarray(0, 12));
    decipher.setAAD(Buffer.from(expectedAad));
    decipher.setAuthTag(sealed.subarray(12, 28));
    expect(Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()]).toString('utf8')).toBe(v.boundAnswer);
  });

  it('§8 (sync sessions) session keys: X25519 (RFC 7748), transcript-salted HKDF, one key per direction', () => {
    const v = vectors.pairingSession;
    const spki = (raw) => crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), Buffer.from(raw, 'hex')]), format: 'der', type: 'spki' });
    const pkcs8 = (raw) => crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(raw, 'hex')]), format: 'der', type: 'pkcs8' });
    const shared = crypto.diffieHellman({ privateKey: pkcs8(v.phonePrivateHex), publicKey: spki(v.desktopPublicHex) });
    // RFC 7748 §6.1's shared secret, from either side.
    expect(shared.toString('hex')).toBe('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');
    expect(crypto.diffieHellman({ privateKey: pkcs8(v.desktopPrivateHex), publicKey: spki(v.phonePublicHex) }).equals(shared)).toBe(true);
    const fp = crypto.createHmac('sha256', Buffer.from(v.pairingSecretHex, 'hex')).update('papersafe-fp-v1').digest('hex').slice(0, 32);
    expect(fp).toBe(v.fingerprint);
    const transcript = crypto.createHash('sha256')
      .update(['psai-sess-v1', fp, v.deviceId, v.sessionIdHex, v.phonePublicHex, v.desktopPublicHex].join('\n')).digest();
    const key = (info) => Buffer.from(crypto.hkdfSync('sha256', shared, transcript, info, 32)).toString('hex');
    expect(key('papersafe-session-v1 phone->desktop')).toBe(v.phoneToDesktopKeyHex);
    expect(key('papersafe-session-v1 desktop->phone')).toBe(v.desktopToPhoneKeyHex);
    expect(JSON.parse(v.openRequest)).toEqual({ v: 1, pub: v.phonePublicHex });
    expect(JSON.parse(v.openAnswer)).toEqual({ v: 1, id: v.sessionIdHex, pub: v.desktopPublicHex, expiresIn: 3600 });
  });

  it('§8 (sync sessions, v2) identity keys: ikm = X25519(e_p,E_d) || X25519(s_p,E_d) || X25519(e_p,S_d), from either side', () => {
    const v = vectors.pairingSession;
    const id = v.identity;
    const spki = (raw) => crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), Buffer.from(raw, 'hex')]), format: 'der', type: 'spki' });
    const pkcs8 = (raw) => crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(raw, 'hex')]), format: 'der', type: 'pkcs8' });
    const dh = (priv, pub) => crypto.diffieHellman({ privateKey: pkcs8(priv), publicKey: spki(pub) });
    const phoneSide = Buffer.concat([dh(v.phonePrivateHex, v.desktopPublicHex), dh(id.phoneIdentityPrivateHex, v.desktopPublicHex), dh(v.phonePrivateHex, id.desktopIdentityPublicHex)]);
    const desktopSide = Buffer.concat([dh(v.desktopPrivateHex, v.phonePublicHex), dh(v.desktopPrivateHex, id.phoneIdentityPublicHex), dh(id.desktopIdentityPrivateHex, v.phonePublicHex)]);
    expect(desktopSide.equals(phoneSide)).toBe(true);
    const transcript = crypto.createHash('sha256').update(['psai-sess-v2', v.fingerprint, v.deviceId, v.sessionIdHex,
      v.phonePublicHex, v.desktopPublicHex, id.phoneIdentityPublicHex, id.desktopIdentityPublicHex].join('\n')).digest();
    const key = (info) => Buffer.from(crypto.hkdfSync('sha256', phoneSide, transcript, info, 32)).toString('hex');
    expect(key('papersafe-session-v2 phone->desktop')).toBe(id.phoneToDesktopKeyHex);
    expect(key('papersafe-session-v2 desktop->phone')).toBe(id.desktopToPhoneKeyHex);
    expect(JSON.parse(id.openRequest)).toEqual({ v: 2, pub: v.phonePublicHex, spk: id.phoneIdentityPublicHex });
    expect(JSON.parse(id.openAnswer)).toEqual({ v: 2, id: v.sessionIdHex, pub: v.desktopPublicHex, spk: id.desktopIdentityPublicHex, expiresIn: 3600 });
  });

  it('§8 (sync sessions) within a session: requests under the phone->desktop key, answers under desktop->phone with "psai-resp-v2" AAD', () => {
    const v = vectors.pairingSession;
    const open = (hexBox, keyHex, aad) => {
      const box = Buffer.from(hexBox, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), box.subarray(0, 12));
      if (aad) decipher.setAAD(Buffer.from(aad));
      decipher.setAuthTag(box.subarray(12, 28));
      return Buffer.concat([decipher.update(box.subarray(28)), decipher.final()]).toString('utf8');
    };
    expect(open(v.sealedRequestHex, v.phoneToDesktopKeyHex, null)).toBe(v.requestBody);
    const a = v.answer;
    expect(open(v.sealedAnswerHex, v.desktopToPhoneKeyHex, `psai-resp-v2\n${a.method}\n${a.target}\n${a.nonce}\n${v.sessionIdHex}`)).toBe(a.body);
    // A request box never opens as an answer: wrong key.
    expect(() => open(v.sealedRequestHex, v.desktopToPhoneKeyHex, null)).toThrow();
  });

  it('§2 vault unlock: Argon2id(password, salt, scheme) unwraps the vault key (AES-256-GCM, no AAD)', async () => {
    const argon2 = (await import('argon2')).default;
    const v = vectors.vaultUnlock;
    const params = vectors.passwordKdf.params;
    const wrappingKey = await argon2.hash(v.password, {
      type: argon2.argon2id,
      salt: Buffer.from(v.authRecord.passwordSalt, 'base64'),
      timeCost: params.timeCost,
      memoryCost: params.memoryCost,
      parallelism: params.parallelism,
      hashLength: 32,
      raw: true
    });
    expect(wrappingKey.toString('hex')).toBe(v.wrappingKeyHex);
    const w = v.authRecord.wrappedVaultKeyByPassword;
    const decipher = crypto.createDecipheriv('aes-256-gcm', wrappingKey, Buffer.from(w.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(w.tag, 'base64'));
    const unwrapped = Buffer.concat([decipher.update(Buffer.from(w.encrypted, 'base64')), decipher.final()]);
    expect(unwrapped.toString('hex')).toBe(vectors.vaultKeyHex);
  });

  it('§3 encrypted field (suite 3): "\\x00pse\\x03" b64(iv) "." b64(tag) "." b64(ct) under HKDF(vaultKey, field info), AAD binds row and column', () => {
    const v = vectors.databaseField;
    const key = hkdf(vaultKey, 'papersafeai:local-vault', 'papersafeai:field-cipher:v3');
    expect(key.toString('hex')).toBe(v.fieldKeyHex);
    expect(v.stored.startsWith('\x00pse\x03')).toBe(true);
    const [iv, tag, ct] = v.stored.slice(5).split('.').map((part) => Buffer.from(part, 'base64'));
    const open = (fields) => gcmOpen({ key, iv, tag, ciphertext: ct, aad: aad({ component: 'vault-v3', ...v.context, ...fields }) });
    expect(open({}).toString('utf8')).toBe(v.plaintext);
    expect(() => open({ primaryKey: ['doc-2'] })).toThrow();
    expect(() => open({ recordType: 'other_column' })).toThrow();
  });

  it('§4 reuse and note digests: HKDF(openKey, salt=label, info="papersafeai:credentials:v1") then HMAC-SHA256', () => {
    const v = vectors.credentialDigests;
    expect(v.openKeyHex).toBe(vectors.credentialOpenHalf.keyHex);
    const openKey = Buffer.from(v.openKeyHex, 'hex');
    const sub = (label) => Buffer.from(crypto.hkdfSync('sha256', openKey, Buffer.from(label), Buffer.from('papersafeai:credentials:v1'), 32));
    expect(crypto.createHmac('sha256', sub(v.reuseLabel)).update(v.password).digest('hex')).toBe(v.passwordDigest);
    expect(crypto.createHmac('sha256', sub(v.noteIndexLabel)).update(v.noteToken.toLowerCase()).digest('hex').slice(0, 12)).toBe(v.noteTokenDigest);
  });

  it('§2 biometric blob: AES-256-GCM under HKDF(hardware secret, salt, "papersafeai-vault-key-wrap-v1")', () => {
    const { blob, hardwareSecretHex } = vectors.biometricWrap;
    expect(blob.version).toBe(1);
    const key = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(hardwareSecretHex, 'hex'), Buffer.from(blob.salt, 'base64'), Buffer.from('papersafeai-vault-key-wrap-v1'), 32));
    const opened = gcmOpenNoAad(key, Buffer.from(blob.iv, 'base64'), Buffer.from(blob.tag, 'base64'), Buffer.from(blob.ciphertext, 'base64'));
    expect(opened.toString('hex')).toBe(vectors.vaultKeyHex);
  });
});

function gcmOpenNoAad(key, iv, tag, ciphertext) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
