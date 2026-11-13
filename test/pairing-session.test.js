import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { createRequire } from 'node:module';
import { createReactNativeAdapter } from '../src/platform/react-native.js';

const require = createRequire(import.meta.url);
const session = require('../src/pairing/session');
const transport = require('../src/pairing/transport');
const { nodeAdapter } = require('../src/node');

const rn = createReactNativeAdapter({ quickCrypto: crypto, gzip: zlib.gzipSync, gunzip: zlib.gunzipSync });
const secret = transport.generatePairingSecret(nodeAdapter);
const fingerprint = transport.pairingFingerprint(secret, nodeAdapter);

/** One full open, phone on `phoneAdapter`, desktop on `desktopAdapter`. */
function openSession(phoneAdapter, desktopAdapter) {
  const phone = session.createEphemeral(phoneAdapter);
  const { phonePublic } = session.parseOpenRequest(session.encodeOpenRequest(phone.publicKey));
  const desktop = session.createEphemeral(desktopAdapter);
  const sessionId = session.createSessionId(desktopAdapter);
  const answer = session.parseOpenAnswer(session.encodeOpenAnswer({ sessionId, desktopPublic: desktop.publicKey, expiresIn: 3600 }));
  const context = { phonePublic, desktopPublic: answer.desktopPublic, sessionId: answer.sessionId, fingerprint, deviceId: 'device-1' };
  const desktopKeys = session.deriveSessionKeys({ ...context, privateKey: desktop.privateKey, peerPublic: phonePublic }, desktopAdapter);
  const phoneKeys = session.deriveSessionKeys({ ...context, privateKey: phone.privateKey, peerPublic: answer.desktopPublic }, phoneAdapter);
  return { phoneKeys, desktopKeys, context };
}

describe('sync sessions (SPEC.md §8 (sync sessions))', () => {
  it.each([
    ['node ↔ node', nodeAdapter, nodeAdapter],
    ['phone adapter ↔ node', rn, nodeAdapter],
  ])('both sides derive the same two keys (%s)', (_, a, b) => {
    const { phoneKeys, desktopKeys } = openSession(a, b);
    expect(Buffer.from(phoneKeys.phoneToDesktop)).toEqual(Buffer.from(desktopKeys.phoneToDesktop));
    expect(Buffer.from(phoneKeys.desktopToPhone)).toEqual(Buffer.from(desktopKeys.desktopToPhone));
    expect(Buffer.from(phoneKeys.phoneToDesktop)).not.toEqual(Buffer.from(phoneKeys.desktopToPhone));
  });

  it('each session gets fresh keys, unrelated to the pairing transport key', () => {
    const one = openSession(nodeAdapter, nodeAdapter).phoneKeys.phoneToDesktop;
    const two = openSession(nodeAdapter, nodeAdapter).phoneKeys.phoneToDesktop;
    expect(Buffer.from(one)).not.toEqual(Buffer.from(two));
    expect(Buffer.from(one)).not.toEqual(Buffer.from(transport.deriveTransportKey(secret, nodeAdapter)));
  });

  it('matches RFC 7748 §6.1 on both adapters', () => {
    const alice = Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex');
    const bobPub = Buffer.from('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'hex');
    for (const adapter of [nodeAdapter, rn]) {
      expect(Buffer.from(adapter.x25519SharedSecret(new Uint8Array(alice), new Uint8Array(bobPub))).toString('hex'))
        .toBe('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');
    }
  });

  it('refuses a low-order peer key (all-zero shared secret)', () => {
    const phone = session.createEphemeral(nodeAdapter);
    const zero = new Uint8Array(32);
    expect(() => session.deriveSessionKeys({
      privateKey: phone.privateKey, peerPublic: zero, phonePublic: phone.publicKey, desktopPublic: zero,
      sessionId: new Uint8Array(16), fingerprint, deviceId: 'device-1'
    }, nodeAdapter)).toThrow(/no secret|low-order/);
  });

  it('a request box never opens as an answer, and an answer is bound to its request and session', () => {
    const { phoneKeys, desktopKeys, context } = openSession(nodeAdapter, nodeAdapter);
    const request = transport.sealTransport(new TextEncoder().encode('{"a":1}'), phoneKeys.phoneToDesktop, nodeAdapter);
    expect(() => transport.openTransport(request, phoneKeys.desktopToPhone, nodeAdapter)).toThrow();
    expect(new TextDecoder().decode(transport.openTransport(request, desktopKeys.phoneToDesktop, nodeAdapter))).toBe('{"a":1}');
    const idHex = Buffer.from(context.sessionId).toString('hex');
    const aad = session.sessionResponseAad('GET', '/delta?x=1', 'aa'.repeat(16), idHex);
    const answer = transport.sealTransport(new TextEncoder().encode('{}'), desktopKeys.desktopToPhone, nodeAdapter, { aad });
    expect(() => transport.openTransport(answer, phoneKeys.desktopToPhone, nodeAdapter, { aad: session.sessionResponseAad('GET', '/delta?x=2', 'aa'.repeat(16), idHex) })).toThrow();
    expect(() => transport.openTransport(answer, phoneKeys.desktopToPhone, nodeAdapter, { aad: session.sessionResponseAad('GET', '/delta?x=1', 'aa'.repeat(16), 'bb'.repeat(16)) })).toThrow();
    expect(new TextDecoder().decode(transport.openTransport(answer, phoneKeys.desktopToPhone, nodeAdapter, { aad }))).toBe('{}');
  });

  it('the transcript binds pairing and device: another fingerprint or device id gives other keys', () => {
    const phone = session.createEphemeral(nodeAdapter);
    const desktop = session.createEphemeral(nodeAdapter);
    const base = { privateKey: phone.privateKey, peerPublic: desktop.publicKey, phonePublic: phone.publicKey, desktopPublic: desktop.publicKey, sessionId: new Uint8Array(16).fill(1), fingerprint, deviceId: 'device-1' };
    const k = (over) => Buffer.from(session.deriveSessionKeys({ ...base, ...over }, nodeAdapter).phoneToDesktop).toString('hex');
    expect(k({})).not.toBe(k({ deviceId: 'device-2' }));
    expect(k({})).not.toBe(k({ fingerprint: '0'.repeat(32) }));
    expect(() => k({ deviceId: 'a\nb' })).toThrow();
  });

  it('parsers refuse anything but the exact shapes', () => {
    const bad = ['', '[]', '{"v":2,"pub":"' + '00'.repeat(32) + '"}', '{"v":1,"pub":"' + '0'.repeat(63) + '"}', '{"v":1,"pub":"' + 'AA'.repeat(32) + '"}'];
    for (const body of bad) expect(() => session.parseOpenRequest(new TextEncoder().encode(body))).toThrow();
    const answer = (o) => new TextEncoder().encode(JSON.stringify({ v: 1, id: 'ab'.repeat(16), pub: 'cd'.repeat(32), expiresIn: 60, ...o }));
    expect(session.parseOpenAnswer(answer({})).expiresIn).toBe(60);
    for (const o of [{ id: 'ab' }, { pub: null }, { expiresIn: 0 }, { expiresIn: 1.5 }, { v: '1' }]) expect(() => session.parseOpenAnswer(answer(o))).toThrow();
    expect(session.parseSessionHeader('ab'.repeat(16))).toBe('ab'.repeat(16));
    expect(session.parseSessionHeader('AB'.repeat(16))).toBeNull();
    expect(session.parseSessionHeader(undefined)).toBeNull();
  });
});

describe('sync sessions with device identity keys (version 2)', () => {
  const phoneId = session.createIdentityKey(nodeAdapter);
  const desktopId = session.createIdentityKey(nodeAdapter);

  /** One v2 open. `phoneIdentity`/`desktopIdentity` are what each side holds; `pinned*` what the other believes. */
  function openV2({ phoneSide = phoneId, desktopSide = desktopId, desktopPinsPhone = phoneId.publicKey, phonePinsDesktop = desktopId.publicKey, phoneAdapter = nodeAdapter } = {}) {
    const phone = session.createEphemeral(phoneAdapter);
    const req = session.parseOpenRequest(session.encodeOpenRequest(phone.publicKey, { identityPublic: phoneSide.publicKey }));
    expect(req.version).toBe(2);
    const desktop = session.createEphemeral(nodeAdapter);
    const sessionId = session.createSessionId(nodeAdapter);
    const ans = session.parseOpenAnswer(session.encodeOpenAnswer({ sessionId, desktopPublic: desktop.publicKey, expiresIn: 60, identityPublic: desktopSide.publicKey }));
    expect(ans.version).toBe(2);
    const base = { phonePublic: req.phonePublic, desktopPublic: ans.desktopPublic, sessionId: ans.sessionId, fingerprint, deviceId: 'device-1' };
    const desktopKeys = session.deriveSessionKeys({ ...base, privateKey: desktop.privateKey, identity: {
      role: 'desktop', privateKey: desktopSide.privateKey, phoneIdentity: desktopPinsPhone, desktopIdentity: desktopSide.publicKey } }, nodeAdapter);
    const phoneKeys = session.deriveSessionKeys({ ...base, privateKey: phone.privateKey, identity: {
      role: 'phone', privateKey: phoneSide.privateKey, phoneIdentity: phoneSide.publicKey, desktopIdentity: phonePinsDesktop } }, phoneAdapter);
    return { phoneKeys, desktopKeys };
  }
  const same = (a, b) => Buffer.from(a.phoneToDesktop).equals(Buffer.from(b.phoneToDesktop))
    && Buffer.from(a.desktopToPhone).equals(Buffer.from(b.desktopToPhone));

  it.each([['node', nodeAdapter], ['phone adapter', rn]])('the real phone and desktop derive the same keys (%s phone)', (_, adapter) => {
    const { phoneKeys, desktopKeys } = openV2({ phoneAdapter: adapter });
    expect(same(phoneKeys, desktopKeys)).toBe(true);
  });

  it('a phone impostor holding the pairing secret but not the phone key derives other keys', () => {
    const impostor = session.createIdentityKey(nodeAdapter);
    // It presents its own key; the desktop uses the key it pinned.
    const { phoneKeys, desktopKeys } = openV2({ phoneSide: impostor });
    expect(same(phoneKeys, desktopKeys)).toBe(false);
    // Claiming the real phone's public key does not help without its private key.
    const claimed = { privateKey: impostor.privateKey, publicKey: phoneId.publicKey };
    expect(same(...Object.values(openV2({ phoneSide: claimed })))).toBe(false);
  });

  it('a desktop impostor holding the pairing secret but not the desktop key derives other keys', () => {
    const impostor = session.createIdentityKey(nodeAdapter);
    const claimed = { privateKey: impostor.privateKey, publicKey: desktopId.publicKey };
    expect(same(...Object.values(openV2({ desktopSide: claimed })))).toBe(false);
    expect(same(...Object.values(openV2({ desktopSide: impostor })))).toBe(false);
  });

  it('version 2 keys differ from version 1 keys for the same exchange', () => {
    const phone = session.createEphemeral(nodeAdapter);
    const desktop = session.createEphemeral(nodeAdapter);
    const base = { phonePublic: phone.publicKey, desktopPublic: desktop.publicKey, sessionId: new Uint8Array(16).fill(7), fingerprint, deviceId: 'device-1' };
    const v1 = session.deriveSessionKeys({ ...base, privateKey: phone.privateKey, peerPublic: desktop.publicKey }, nodeAdapter);
    const v2 = session.deriveSessionKeys({ ...base, privateKey: phone.privateKey, identity: {
      role: 'phone', privateKey: phoneId.privateKey, phoneIdentity: phoneId.publicKey, desktopIdentity: desktopId.publicKey } }, nodeAdapter);
    expect(Buffer.from(v1.phoneToDesktop).equals(Buffer.from(v2.phoneToDesktop))).toBe(false);
  });

  it('parses both open versions and refuses a v2 body without its identity key', () => {
    const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
    expect(session.parseOpenRequest(enc({ v: 1, pub: 'ab'.repeat(32) })).phoneIdentity).toBeNull();
    expect(() => session.parseOpenRequest(enc({ v: 2, pub: 'ab'.repeat(32) }))).toThrow();
    expect(() => session.parseOpenAnswer(enc({ v: 2, id: 'ab'.repeat(16), pub: 'cd'.repeat(32), expiresIn: 60 }))).toThrow();
    expect(session.sameIdentity(phoneId.publicKey, new Uint8Array(phoneId.publicKey))).toBe(true);
    expect(session.sameIdentity(phoneId.publicKey, desktopId.publicKey)).toBe(false);
  });
});

describe('pairing QR v3', () => {
  const qr = { deviceId: 'd', secret, fingerprint, ip: '10.0.0.2', port: 39501 };
  it('carries the desktop identity key and reads back', () => {
    const key = session.createIdentityKey(nodeAdapter).publicKey;
    const payload = transport.buildPairingQrPayload({ ...qr, identityKey: key });
    expect(payload.v).toBe(3);
    expect(transport.parsePairingQr(JSON.stringify(payload)).spk).toBe(Buffer.from(key).toString('hex'));
  });
  it('v2 is unchanged, and a v3 without a valid key is refused', () => {
    expect(transport.buildPairingQrPayload(qr).v).toBe(2);
    expect(transport.parsePairingQr(JSON.stringify(transport.buildPairingQrPayload(qr))).spk).toBeUndefined();
    const bad = { ...transport.buildPairingQrPayload(qr), v: 3, spk: 'xyz' };
    expect(() => transport.parsePairingQr(JSON.stringify(bad))).toThrow(/identity key/);
    expect(() => transport.parsePairingQr(JSON.stringify({ ...bad, v: 4 }))).toThrow(/newer version/);
  });
});
