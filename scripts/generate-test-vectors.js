#!/usr/bin/env node
'use strict';

/**
 * Writes test-vectors/vault-core-v1.json: fixed inputs, and the exact bytes the
 * core produces from them, for every format an outside implementation would
 * need to read. Randomness is replaced by a deterministic stream so the file is
 * reproducible; `--check` regenerates in memory and fails if the committed file
 * differs (a format change that was not meant to be one).
 *
 * The keys here are TEST keys. They protect nothing.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { nodeAdapter } = require('../src/node');
require('./example-record-types').registerExamples(require('../src/crypto/aad'), require('../src/backup/bundle'));
const { deriveDbKeyHex, DB_KEY_SALT, DB_KEY_INFO } = require('../src/crypto/db-key');
const vaultCipher = require('../src/crypto/vault-cipher');
const documentKey = require('../src/crypto/document-key');
const { deriveAuthorityKeys, SALT: CATALOG_SALT } = require('../src/sync/catalog/keys');
const { sealRecord } = require('../src/sync/catalog/seal');
const { KDF_SCHEMES, CURRENT_KDF_SCHEME } = require('../src/kdf/vault-kdf');
const pairing = require('../src/pairing/transport');
const authRecord = require('../src/kdf/auth-record');
const fieldCipher = require('../src/crypto/field-cipher');
const credentialKeys = require('../src/crypto/credential-keys');
const hardwareWrap = require('../src/crypto/hardware-wrap');
const { responseBindingAad } = require('../src/pairing/response-binding');
const session = require('../src/pairing/session');

const OUT = path.join(__dirname, '..', 'test-vectors', 'vault-core-v1.json');
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const text = (value) => new TextEncoder().encode(value);
const VAULT_ID = 'vault-test-0001';

/** SHA-256(label:counter) stream: reproducible, obviously not random. */
function deterministicAdapter(label) {
  let counter = 0;
  return {
    ...nodeAdapter,
    randomBytes(length) {
      const out = Buffer.alloc(Math.ceil(length / 32) * 32);
      for (let offset = 0; offset < length; offset += 32) {
        crypto.createHash('sha256').update(`${label}:${counter++}`).digest().copy(out, offset);
      }
      return out.subarray(0, length);
    }
  };
}

async function build() {
  const vaultKey = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');

  const credentialOpenKey = nodeAdapter.hkdfSha256({
    key: vaultKey, salt: vaultCipher.CREDENTIAL_KEY_SALT, info: vaultCipher.CREDENTIAL_KEY_INFO, length: 32
  });
  const credentialPlain = text(JSON.stringify({ username: 'alice@example.com', url: 'https://example.com' }));
  const credential = vaultCipher.sealCredentialHalf(
    credentialPlain, credentialOpenKey, { vaultId: VAULT_ID, itemId: 'item-1', half: 'open' }, deterministicAdapter('cred')
  );

  const dek = Buffer.from('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf', 'hex');
  const wrapped = documentKey.wrapDocumentKey(dek, vaultKey, deterministicAdapter('dek'), { vaultId: VAULT_ID, documentId: 'doc-1' });

  const catalogKeys = deriveAuthorityKeys(vaultKey, nodeAdapter);
  const recordContext = { vaultId: VAULT_ID, recordType: 'record', primaryKey: ['record-1'] };
  const recordValue = { name: 'Taxes', parent: null };
  const sealed = sealRecord(recordContext, recordValue, catalogKeys.payload.key, deterministicAdapter('catalog'));

  const password = 'correct horse battery staple';
  const passwordSalt = Buffer.from('505152535455565758595a5b5c5d5e5f', 'hex');
  const kdfParams = authRecord.kdfParamsFor({});
  const wrappingKey = await authRecord.deriveWrappingKey(password, passwordSalt, kdfParams, nodeAdapter);
  const wrappedVaultKey = authRecord.wrapKey(vaultKey, wrappingKey, deterministicAdapter('vault-wrap'));

  const pairingSecret = Buffer.from('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', 'hex');
  const transportKey = pairing.deriveTransportKey(pairingSecret, nodeAdapter);
  const requestBody = text(JSON.stringify({ items: [] }));
  const sealedBody = pairing.sealTransport(requestBody, transportKey, deterministicAdapter('transport'));
  const authHeader = pairing.buildAuthHeader(pairingSecret, 'device-1', {
    method: 'POST', url: 'http://192.168.1.20:39501/organization/tags?x=1', body: sealedBody
  }, deterministicAdapter('auth'), { now: Date.UTC(2026, 9, 1), installId: 'install-1' });
  const nonce = pairing.parseAuthHeader(authHeader).nonce;
  const bindingAad = responseBindingAad('POST', '/organization/tags?x=1', nonce);
  const boundAnswer = pairing.sealTransport(text('{"ok":true}'), transportKey, deterministicAdapter('answer'), { aad: text(bindingAad) });

  // §8 (sync sessions): the RFC 7748 §6.1 key pairs stand in for the two ephemeral keys.
  const fingerprint = pairing.pairingFingerprint(pairingSecret, nodeAdapter);
  const phonePrivate = Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex');
  const desktopPrivate = Buffer.from('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex');
  const phonePublic = Buffer.from('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex');
  const desktopPublic = Buffer.from('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'hex');
  const sessionId = Buffer.from('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf', 'hex');
  const sessionContext = { phonePublic, desktopPublic, sessionId, fingerprint, deviceId: 'device-1' };
  const sessionKeys = session.deriveSessionKeys({ ...sessionContext, privateKey: phonePrivate, peerPublic: desktopPublic }, nodeAdapter);
  // Version 2 (device identity keys): fixed identity keys, public halves computed.
  const x25519Public = (raw) => crypto.createPublicKey(crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), raw]), format: 'der', type: 'pkcs8'
  })).export({ format: 'der', type: 'spki' }).subarray(12);
  const phoneIdentityPrivate = Buffer.from(`a8${'ab'.repeat(30)}6b`, 'hex');
  const desktopIdentityPrivate = Buffer.from(`c8${'cd'.repeat(30)}4d`, 'hex');
  const phoneIdentityPublic = x25519Public(phoneIdentityPrivate);
  const desktopIdentityPublic = x25519Public(desktopIdentityPrivate);
  const identityKeys = session.deriveSessionKeys({
    ...sessionContext, privateKey: phonePrivate,
    identity: { role: 'phone', privateKey: phoneIdentityPrivate, phoneIdentity: phoneIdentityPublic, desktopIdentity: desktopIdentityPublic }
  }, nodeAdapter);
  const sessionRequestBody = text(JSON.stringify({ items: ['secret'] }));
  const sessionSealedRequest = pairing.sealTransport(sessionRequestBody, sessionKeys.phoneToDesktop, deterministicAdapter('session-request'));
  const sessionAnswerAad = session.sessionResponseAad('POST', '/organization/tags', '00112233445566778899aabbccddeeff', hex(sessionId));
  const sessionSealedAnswer = pairing.sealTransport(text('{"ok":true}'), sessionKeys.desktopToPhone, deterministicAdapter('session-answer'), { aad: sessionAnswerAad });

  return {
    description: 'PaperSafeAI vault-core test vectors. TEST KEYS ONLY. See SPEC.md for each format.',
    version: 1,
    vaultKeyHex: hex(vaultKey),
    vaultId: VAULT_ID,
    passwordKdf: { spec: 'SPEC.md §2', scheme: CURRENT_KDF_SCHEME, params: KDF_SCHEMES[CURRENT_KDF_SCHEME] },
    vaultUnlock: {
      spec: 'SPEC.md §2',
      authRecord: {
        kdfScheme: CURRENT_KDF_SCHEME,
        passwordSalt: passwordSalt.toString('base64'),
        wrappedVaultKeyByPassword: wrappedVaultKey
      },
      password,
      wrappingKeyHex: hex(wrappingKey)
    },
    biometricWrap: {
      spec: 'SPEC.md §2',
      hardwareSecretHex: '6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80',
      blob: hardwareWrap.sealWithHardwareSecret({
        key: vaultKey,
        secret: Buffer.from('6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80', 'hex'),
        challenge: hardwareWrap.newChallenge(deterministicAdapter('challenge')),
        provider: 'test'
      }, deterministicAdapter('biometric'))
    },
    databaseKey: {
      spec: 'SPEC.md §3',
      salt: DB_KEY_SALT,
      info: DB_KEY_INFO,
      keyHex: deriveDbKeyHex(vaultKey, nodeAdapter)
    },
    databaseField: {
      spec: 'SPEC.md §3',
      fieldKeyHex: hex(fieldCipher.deriveFieldKey(vaultKey, nodeAdapter)),
      context: { vaultId: VAULT_ID, recordType: 'example_column', primaryKey: ['doc-1'] },
      plaintext: 'Passport number X1234567',
      stored: fieldCipher.sealField('Passport number X1234567', fieldCipher.deriveFieldKey(vaultKey, nodeAdapter),
        { vaultId: VAULT_ID, recordType: 'example_column', primaryKey: ['doc-1'] }, deterministicAdapter('field'))
    },
    credentialOpenHalf: {
      spec: 'SPEC.md §4',
      hkdfSalt: vaultCipher.CREDENTIAL_KEY_SALT,
      hkdfInfo: vaultCipher.CREDENTIAL_KEY_INFO,
      keyHex: hex(credentialOpenKey),
      itemId: 'item-1',
      half: 'open',
      aad: Buffer.from(vaultCipher.credentialAad({ vaultId: VAULT_ID, itemId: 'item-1', half: 'open' })).toString('utf8'),
      plaintext: Buffer.from(credentialPlain).toString('utf8'),
      ivHex: hex(credential.iv),
      ciphertextHex: hex(credential.ciphertext),
      tagHex: hex(credential.tag)
    },
    credentialDigests: {
      spec: 'SPEC.md §4',
      openKeyHex: hex(credentialKeys.deriveOpenPayloadKey(vaultKey, nodeAdapter)),
      reuseLabel: credentialKeys.REUSE_DIGEST_LABEL,
      noteIndexLabel: credentialKeys.NOTE_INDEX_LABEL,
      password: 'hunter2-but-longer',
      passwordDigest: credentialKeys.passwordReuseDigest(credentialKeys.deriveOpenPayloadKey(vaultKey, nodeAdapter), 'hunter2-but-longer', nodeAdapter),
      noteToken: 'Locker',
      noteTokenDigest: credentialKeys.noteTokenDigest(
        credentialKeys.deriveNoteIndexKey(credentialKeys.deriveOpenPayloadKey(vaultKey, nodeAdapter), nodeAdapter), 'Locker', nodeAdapter)
    },
    documentKey: {
      spec: 'SPEC.md §5',
      documentId: 'doc-1',
      wrapKeySalt: documentKey.DOCUMENT_WRAP_KEY_SALT,
      wrapKeyInfo: documentKey.DOCUMENT_WRAP_KEY_INFO,
      aad: Buffer.from(vaultCipher.documentKeyAad({ vaultId: VAULT_ID, documentId: 'doc-1' })).toString('utf8'),
      dekHex: hex(dek),
      wrappedBase64: wrapped
    },
    catalogRecord: {
      spec: 'SPEC.md §7',
      hkdfSalt: CATALOG_SALT,
      keys: Object.fromEntries(Object.entries(catalogKeys).map(([name, k]) => [name, { info: k.id, keyHex: hex(k.key) }])),
      context: recordContext,
      value: recordValue,
      envelopeHex: hex(sealed)
    },
    pairingTransport: {
      spec: 'SPEC.md §8',
      pairingSecretHex: hex(pairingSecret),
      transportKeyInfo: pairing.TRANSPORT_KEY_INFO,
      transportKeyHex: hex(transportKey),
      fingerprintInfo: pairing.FINGERPRINT_INFO,
      fingerprint: pairing.pairingFingerprint(pairingSecret, nodeAdapter),
      body: Buffer.from(requestBody).toString('utf8'),
      sealedBodyHex: hex(sealedBody),
      request: { method: 'POST', target: '/organization/tags?x=1', deviceId: 'device-1' },
      authorization: authHeader,
      responseBindingAad: bindingAad,
      boundAnswer: '{"ok":true}',
      boundAnswerHex: hex(boundAnswer)
    },
    pairingSession: {
      spec: 'SPEC.md §8 (sync sessions)',
      pairingSecretHex: hex(pairingSecret),
      fingerprint,
      deviceId: 'device-1',
      phonePrivateHex: hex(phonePrivate),
      phonePublicHex: hex(phonePublic),
      desktopPrivateHex: hex(desktopPrivate),
      desktopPublicHex: hex(desktopPublic),
      sessionIdHex: hex(sessionId),
      openRequest: Buffer.from(session.encodeOpenRequest(phonePublic)).toString('utf8'),
      openAnswer: Buffer.from(session.encodeOpenAnswer({ sessionId, desktopPublic, expiresIn: 3600 })).toString('utf8'),
      phoneToDesktopKeyHex: hex(sessionKeys.phoneToDesktop),
      desktopToPhoneKeyHex: hex(sessionKeys.desktopToPhone),
      requestBody: Buffer.from(sessionRequestBody).toString('utf8'),
      sealedRequestHex: hex(sessionSealedRequest),
      answer: { method: 'POST', target: '/organization/tags', nonce: '00112233445566778899aabbccddeeff', body: '{"ok":true}' },
      sealedAnswerHex: hex(sessionSealedAnswer),
      identity: {
        spec: 'SPEC.md §8 (sync sessions, version 2)',
        phoneIdentityPrivateHex: hex(phoneIdentityPrivate),
        phoneIdentityPublicHex: hex(phoneIdentityPublic),
        desktopIdentityPrivateHex: hex(desktopIdentityPrivate),
        desktopIdentityPublicHex: hex(desktopIdentityPublic),
        openRequest: Buffer.from(session.encodeOpenRequest(phonePublic, { identityPublic: phoneIdentityPublic })).toString('utf8'),
        openAnswer: Buffer.from(session.encodeOpenAnswer({ sessionId, desktopPublic, expiresIn: 3600, identityPublic: desktopIdentityPublic })).toString('utf8'),
        phoneToDesktopKeyHex: hex(identityKeys.phoneToDesktop),
        desktopToPhoneKeyHex: hex(identityKeys.desktopToPhone)
      }
    }
  };
}

(async () => {
  const json = `${JSON.stringify(await build(), null, 2)}\n`;
  if (process.argv.includes('--check')) {
    const committed = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : '';
    if (committed !== json) {
      console.error('test-vectors/vault-core-v1.json is out of date: a format changed. If that was intended it is a new format version (SPEC.md), not an edit.');
      process.exit(1);
    }
    console.log('test vectors up to date');
  } else {
    fs.mkdirSync(path.dirname(OUT), { recursive: true });
    fs.writeFileSync(OUT, json);
    console.log(`wrote ${path.relative(process.cwd(), OUT)}`);
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
