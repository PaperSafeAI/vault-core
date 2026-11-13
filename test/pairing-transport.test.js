import { describe, it, expect } from 'vitest';
import { nodeAdapter as adapter } from '../src/node/index.js';
import * as t from '../src/pairing/transport.js';

const SECRET = 'ab'.repeat(32);
const KEY = t.deriveTransportKey(SECRET, adapter);
const sign = (overrides = {}) => {
  const body = new TextEncoder().encode('{"a":1}');
  const header = t.buildAuthHeader(SECRET, 'dev-1', { method: 'post', url: 'http://10.0.0.2:39501/tags?q=1', body, ...overrides }, adapter);
  return { body, params: t.parseAuthHeader(header) };
};
const check = (params, request) => t.verifyRequestSignature(SECRET, { sig: params.sig, ts: params.ts, nonce: params.nonce, ...request }, adapter);

describe('pairing and transport', () => {
  it('derives the same key from the hex QR form and from bytes', () => {
    expect(Buffer.from(t.deriveTransportKey(Buffer.from(SECRET, 'hex'), adapter))).toEqual(Buffer.from(KEY));
    expect(() => t.deriveTransportKey('abcd', adapter)).toThrow(/32 bytes/);
  });

  it('round-trips a sealed body and refuses any tampering', () => {
    const sealed = t.sealTransport(new TextEncoder().encode('hello'), KEY, adapter);
    expect(new TextDecoder().decode(t.openTransport(sealed, KEY, adapter))).toBe('hello');
    sealed[sealed.length - 1] ^= 1;
    expect(() => t.openTransport(sealed, KEY, adapter)).toThrow();
    expect(() => t.openTransport(new Uint8Array(27), KEY, adapter)).toThrow(/too short/);
  });

  it('never reuses a nonce', () => {
    const a = t.sealTransport(new Uint8Array([1]), KEY, adapter);
    const b = t.sealTransport(new Uint8Array([1]), KEY, adapter);
    expect(Buffer.from(a.subarray(0, 12))).not.toEqual(Buffer.from(b.subarray(0, 12)));
  });

  it('accepts the signed request and nothing else', () => {
    const { body, params } = sign();
    const bodyHash = t.bodyHashHex(body, adapter);
    const request = { method: 'POST', requestTarget: '/tags?q=1', bodyHash };
    expect(check(params, request)).toBe(true);
    expect(check(params, { ...request, requestTarget: '/db' })).toBe(false);
    expect(check(params, { ...request, method: 'GET' })).toBe(false);
    expect(check(params, { ...request, bodyHash: t.bodyHashHex(new Uint8Array([9]), adapter) })).toBe(false);
    expect(check({ ...params, nonce: '00'.repeat(16) }, request)).toBe(false);
    expect(check({ ...params, sig: 'not-hex' }, request)).toBe(false);
    expect(t.verifyRequestSignature('cd'.repeat(32), { ...params, ...request }, adapter)).toBe(false);
  });

  it('parses only well-formed headers', () => {
    expect(t.parseAuthHeader('Bearer x')).toBeNull();
    expect(t.parseAuthHeader('PapersafeHMAC ts=1,nonce=2')).toBeNull();
    expect(t.parseAuthHeader(undefined)).toBeNull();
  });

  it('writes a QR the parser accepts, and explains a newer one', () => {
    const fp = t.pairingFingerprint(SECRET, adapter);
    const qr = t.buildPairingQrPayload({ deviceId: 'dev-1', secret: Buffer.from(SECRET, 'hex'), fingerprint: fp, ip: '10.0.0.2', port: 39501 });
    expect(t.parsePairingQr(JSON.stringify(qr))).toEqual({ v: 2, id: 'dev-1', secret: SECRET, fp, ip: '10.0.0.2', port: 39501 });
    expect(() => t.parsePairingQr(JSON.stringify({ ...qr, v: 4 }))).toThrow(/newer version/);
    expect(() => t.parsePairingQr(JSON.stringify({ ...qr, secret: 'zz' }))).toThrow(/pairing secret/);
    expect(() => t.parsePairingQr('nope')).toThrow(/valid JSON/);
  });

  it('adds the install id outside the signature, and the parser keeps it', () => {
    const body = new Uint8Array(0);
    const header = t.buildAuthHeader(SECRET, 'dev-1', { method: 'GET', url: 'http://h/x', body }, adapter, { installId: 'inst-9' });
    const params = t.parseAuthHeader(header);
    expect(params.inst).toBe('inst-9');
    expect(check(params, { method: 'GET', requestTarget: '/x', bodyHash: t.bodyHashHex(body, adapter) })).toBe(true);
  });

  it('binds an answer to its request when asked (response binding AAD)', async () => {
    const { responseBindingAad } = await import('../src/pairing/response-binding.js');
    const aad = new TextEncoder().encode(responseBindingAad('get', '/delta?since=1', 'ab'.repeat(16)));
    const sealed = t.sealTransport(new TextEncoder().encode('ok'), KEY, adapter, { aad });
    expect(new TextDecoder().decode(t.openTransport(sealed, KEY, adapter, { aad }))).toBe('ok');
    expect(() => t.openTransport(sealed, KEY, adapter)).toThrow();
    const other = new TextEncoder().encode(responseBindingAad('GET', '/delta?since=2', 'ab'.repeat(16)));
    expect(() => t.openTransport(sealed, KEY, adapter, { aad: other })).toThrow();
  });
});

