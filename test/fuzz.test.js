/**
 * Fuzz and property tests for everything that reads attacker-reachable input:
 * backup archives, sync bodies, auth headers, pairing QR codes, stored fields
 * and credentials, catalogue envelopes, browser-bridge frames.
 *
 * Properties, for every reader:
 *   1. Malformed input is REJECTED with an Error — never accepted as data,
 *      never a crash of another kind, never a hang.
 *   2. What a writer produced round-trips, and flipping any single bit of it
 *      is rejected.
 *
 * The generator is a seeded PRNG (no dependency), so a failure prints the seed
 * and case number and reproduces exactly: FUZZ_SEED=<seed> npx vitest run test/fuzz.test.js
 */
import './setup.mjs'; // example record types (scripts/example-record-types.js)
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { nodeAdapter as adapter } from '../src/node/index.js';
import * as transport from '../src/pairing/transport.js';
import * as session from '../src/pairing/session.js';
import { parseStrict } from '../src/sync/catalog/canonical-json.js';
import { sealRecord, openRecord } from '../src/sync/catalog/seal.js';
import { deriveAuthorityKeys } from '../src/sync/catalog/keys.js';
import { sealCredentialHalf, openCredentialHalf, parseCredentialIv } from '../src/crypto/vault-cipher.js';
import { wrapDocumentKey, unwrapDocumentKey, generateDocumentKey } from '../src/crypto/document-key.js';
import * as field from '../src/crypto/field-cipher.js';
import { normaliseRecoveryKey } from '../src/kdf/auth-record.js';
import * as hardware from '../src/crypto/hardware-wrap.js';
import { assembleBundle, deserializeBundle, parseEnvelope, assertKdfCost } from '../src/backup/index.js';
import * as bridge from '../src/bridge/bridge-crypto.mjs';

const SEED = Number(process.env.FUZZ_SEED || 0x5eed);
const CASES = Number(process.env.FUZZ_CASES || 300);

/** mulberry32: small, fast, deterministic. Not for keys — for test inputs. */
function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function generators(seed) {
  const rand = prng(seed);
  const int = (n) => Math.floor(rand() * n);
  const bytes = (max = 96) => { const out = new Uint8Array(int(max)); for (let i = 0; i < out.length; i++) out[i] = int(256); return out; };
  const ALPHABET = Array.from('abcAZ09 ,.=:;{}[]"\\\n\t\u0000é\u{1F600}+/-_PapersafeHMAC ts nonce sig id inst'); // whole code points: a split emoji is a lone surrogate, which canonical JSON rejects by design
  const text = (max = 80) => Array.from({ length: int(max) }, () => ALPHABET[int(ALPHABET.length)] ?? 'x').join('');
  const scalar = () => [null, undefined, true, false, 0, -1, 1e308, NaN, '', text(12), [], {}][int(12)];
  const json = (depth = 0) => {
    const r = int(depth > 3 ? 4 : 7);
    if (r < 4) return scalar();
    if (r < 5) return Array.from({ length: int(4) }, () => json(depth + 1));
    return Object.fromEntries(Array.from({ length: int(5) }, () => [text(8), json(depth + 1)]));
  };
  const flipBit = (value) => { const out = new Uint8Array(value); const i = int(out.length * 8); out[i >> 3] ^= 1 << (i & 7); return out; };
  return { rand, int, bytes, text, json, flipBit };
}

/** Run `body(gen, n)` CASES times; on failure, say which case and seed. */
function forAll(name, body) {
  const gen = generators(SEED);
  for (let n = 0; n < CASES; n++) {
    try {
      body(gen, n);
    } catch (error) {
      throw new Error(`${name}: case ${n} failed (FUZZ_SEED=${SEED}): ${error.message}`);
    }
  }
}

/** The call must throw an Error (and not loop). */
function rejects(fn) {
  let threw = null;
  try {
    fn();
  } catch (error) {
    threw = error;
  }
  if (!(threw instanceof Error)) throw new Error('accepted malformed input instead of rejecting it');
}

const KEY = crypto.randomBytes(32);
const VAULT_KEY = crypto.randomBytes(32);
const VAULT_ID = 'vault-fuzz';

describe('fuzz: readers reject malformed input with an Error', () => {
  it('transport.openTransport (sync bodies, both directions)', () => {
    forAll('openTransport', ({ bytes }) => rejects(() => transport.openTransport(bytes(), KEY, adapter)));
  });

  it('session.parseOpenRequest / parseOpenAnswer (§8 (sync sessions) open bodies)', () => {
    const enc = new TextEncoder();
    forAll('session open bodies', ({ bytes, json, int }) => {
      const input = int(2) ? bytes() : enc.encode(JSON.stringify(json()) ?? '');
      rejects(() => session.parseOpenRequest(input));
      rejects(() => session.parseOpenAnswer(input));
    });
  });

  it('session.parseSessionHeader returns null or 32 lower-case hex, never throws', () => {
    forAll('parseSessionHeader', ({ text }) => {
      const out = session.parseSessionHeader(text(40));
      if (out !== null) expect(out).toMatch(/^[0-9a-f]{32}$/);
    });
  });

  it('transport.parseAuthHeader returns null or the four fields, never throws', () => {
    forAll('parseAuthHeader', ({ text, int }) => {
      const header = int(2) ? text() : `PapersafeHMAC ${text()}`;
      const out = transport.parseAuthHeader(header);
      if (out !== null) {
        for (const k of ['ts', 'nonce', 'sig', 'id']) expect(typeof out[k]).toBe('string');
      }
    });
  });

  it('transport.verifyRequestSignature is false for anything but the real signature', () => {
    const request = { method: 'GET', requestTarget: '/x', ts: '1', nonce: 'aa', bodyHash: transport.bodyHashHex(new Uint8Array(0), adapter) };
    forAll('verifyRequestSignature', ({ text }) => {
      expect(transport.verifyRequestSignature('ab'.repeat(32), { ...request, sig: text(70) }, adapter)).toBe(false);
    });
  });

  it('transport.parsePairingQr throws a readable Error or returns a well-formed payload', () => {
    forAll('parsePairingQr', ({ json, text, int }) => {
      const raw = int(3) ? JSON.stringify(json()) : text();
      let out;
      try {
        out = transport.parsePairingQr(raw);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect(error.message.length).toBeGreaterThan(0);
        return;
      }
      expect(out.v).toBe(2);
      expect(out.secret).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  it('canonical JSON parseStrict', () => {
    forAll('parseStrict', ({ text, json, int }) => {
      const raw = int(2) ? text() : JSON.stringify(json()) + (int(2) ? text(3) : '');
      try {
        parseStrict(raw);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }
    });
  });

  it('catalogue openRecord', () => {
    const { payload } = deriveAuthorityKeys(VAULT_KEY, adapter);
    const context = { vaultId: VAULT_ID, recordType: 'record', primaryKey: ['f'] };
    forAll('openRecord', ({ bytes }) => rejects(() => openRecord(context, bytes(), payload.key, adapter)));
  });

  it('parseCredentialIv / openCredentialHalf', () => {
    forAll('openCredentialHalf', ({ bytes }) => {
      rejects(() => openCredentialHalf({
        ciphertext: bytes(), iv: bytes(16), tag: bytes(20), key: KEY, vaultId: VAULT_ID, itemId: 'i', half: 'open'
      }, adapter));
      try { parseCredentialIv(bytes(16)); } catch (error) { expect(error).toBeInstanceOf(Error); }
    });
  });

  it('unwrapDocumentKey', () => {
    forAll('unwrapDocumentKey', ({ bytes, text, int }) => {
      const wrapped = int(2) ? adapter.toBase64(bytes()) : text();
      rejects(() => unwrapDocumentKey(wrapped, VAULT_KEY, adapter, { vaultId: VAULT_ID, documentId: 'd' }));
    });
  });

  it('field openField', () => {
    const fieldKey = field.deriveFieldKey(VAULT_KEY, adapter);
    const context = { vaultId: VAULT_ID, recordType: 'example_column', primaryKey: ['d'] };
    forAll('openField', ({ text, int, bytes }) => {
      const prefix = [field.FIELD_PREFIX, `${field.FIELD_MARKER}\x01`, field.FIELD_MARKER, ''][int(4)];
      const body = int(2) ? text() : [bytes(16), bytes(20), bytes()].map((b) => adapter.toBase64(b)).join('.');
      rejects(() => field.openField(prefix + body, fieldKey, context, adapter));
    });
  });

  it('hardware.openWithHardwareSecret', () => {
    forAll('openWithHardwareSecret', ({ bytes, json, int }) => {
      const blob = int(2) ? json() : {
        version: 1, challenge: adapter.toBase64(bytes()), salt: adapter.toBase64(bytes()),
        iv: adapter.toBase64(bytes(16)), tag: adapter.toBase64(bytes(20)), ciphertext: adapter.toBase64(bytes())
      };
      rejects(() => hardware.openWithHardwareSecret(blob, bytes(40), adapter));
    });
  });

  it('normaliseRecoveryKey returns null or the canonical form', () => {
    forAll('normaliseRecoveryKey', ({ text, json, int }) => {
      const out = normaliseRecoveryKey(int(4) ? text(60) : json());
      if (out !== null) expect(out).toMatch(/^[0-9A-F]{4}(-[0-9A-F]{4}){5}$/);
    });
  });

  it('backup parseEnvelope / assertKdfCost', () => {
    forAll('parseEnvelope', ({ text, json, int }) => {
      const raw = int(2) ? text(120) : JSON.stringify(json());
      try { parseEnvelope(raw); } catch (error) { expect(error).toBeInstanceOf(Error); }
      try { assertKdfCost(json()); } catch (error) { expect(error).toBeInstanceOf(Error); }
    });
  });

  it('backup deserializeBundle (v1 JSON and v2 binary)', () => {
    const real = new Uint8Array(adapter.utf8ToBytes(JSON.stringify(assembleBundle({
      files: [{ relativePath: 'a.txt', bytes: Buffer.from('hello') }], createdAt: '2026-01-01T00:00:00.000Z'
    }, adapter))));
    forAll('deserializeBundle', ({ bytes, int, flipBit }) => {
      const input = int(2) ? bytes(200) : flipBit(real);
      try { deserializeBundle(input, adapter); } catch (error) { expect(error).toBeInstanceOf(Error); }
    });
  });

  it('bridge open (extension ↔ desktop frames)', async () => {
    const a = await bridge.generateKeyPair();
    const b = await bridge.generateKeyPair();
    const key = await bridge.deriveSessionKey({ privateKey: a.privateKey, peerPublicKey: b.publicKey, clientNonce: bridge.toBase64(bridge.randomBytes(16)), serverNonce: bridge.toBase64(bridge.randomBytes(16)) });
    const gen = generators(SEED);
    for (let n = 0; n < 100; n++) {
      const frame = gen.int(2) ? gen.json() : { t: 'enc', seq: gen.int(3), iv: bridge.toBase64(gen.bytes(16)), ct: bridge.toBase64(gen.bytes()) };
      await expect(bridge.open(key, frame, { direction: 'c2s', expectedSeq: 0 })).rejects.toBeInstanceOf(Error);
    }
  });
});

describe('properties: round-trip, and any single flipped bit is rejected', () => {
  it('transport bodies (with and without response binding)', () => {
    forAll('transport', ({ bytes, flipBit, int }) => {
      const plain = bytes(200);
      const aad = int(2) ? bytes(40) : null;
      const sealed = transport.sealTransport(plain, KEY, adapter, { aad });
      expect(Buffer.from(transport.openTransport(sealed, KEY, adapter, { aad }))).toEqual(Buffer.from(plain));
      rejects(() => transport.openTransport(flipBit(sealed), KEY, adapter, { aad }));
    });
  });

  it('catalogue records', () => {
    const { payload } = deriveAuthorityKeys(VAULT_KEY, adapter);
    forAll('catalogue', ({ text, flipBit }) => {
      const context = { vaultId: VAULT_ID, recordType: 'record', primaryKey: [text(10) || 'k'] };
      const value = { name: text(30) };
      const sealed = sealRecord(context, value, payload.key, adapter);
      expect(openRecord(context, sealed, payload.key, adapter)).toEqual(value);
      rejects(() => openRecord(context, flipBit(sealed), payload.key, adapter));
    });
  });

  it('credential halves', () => {
    forAll('credential', ({ bytes, flipBit, int }) => {
      const binding = { vaultId: VAULT_ID, itemId: `item-${int(1e6)}`, half: int(2) ? 'open' : 'secret' };
      const plain = bytes(100);
      const sealed = sealCredentialHalf(plain, KEY, binding, adapter);
      expect(Buffer.from(openCredentialHalf({ ...sealed, key: KEY, ...binding }, adapter))).toEqual(Buffer.from(plain));
      const which = ['ciphertext', 'iv', 'tag'][int(3)];
      if (sealed[which].length === 0) return;
      rejects(() => openCredentialHalf({ ...sealed, [which]: flipBit(sealed[which]), key: KEY, ...binding }, adapter));
    });
  });

  it('document keys', () => {
    forAll('documentKey', ({ int, flipBit }) => {
      const binding = { vaultId: VAULT_ID, documentId: `doc-${int(1e6)}` };
      const dek = generateDocumentKey(adapter);
      const wrapped = wrapDocumentKey(dek, VAULT_KEY, adapter, binding);
      expect(Buffer.from(unwrapDocumentKey(wrapped, VAULT_KEY, adapter, binding))).toEqual(Buffer.from(dek));
      const bad = adapter.toBase64(flipBit(adapter.fromBase64(wrapped)));
      rejects(() => unwrapDocumentKey(bad, VAULT_KEY, adapter, binding));
    });
  });

  it('encrypted fields', () => {
    const fieldKey = field.deriveFieldKey(VAULT_KEY, adapter);
    forAll('field', ({ text, int, flipBit }) => {
      const context = { vaultId: VAULT_ID, recordType: 'other_column', primaryKey: [`d${int(99)}`, `${int(99)}`] };
      const value = text(100) || 'x';
      const stored = field.sealField(value, fieldKey, context, adapter);
      expect(field.openField(stored, fieldKey, context, adapter)).toBe(value);
      const ct = adapter.fromBase64(stored.slice(field.FIELD_PREFIX.length).split('.')[2]);
      if (ct.length === 0) return;
      const parts = stored.slice(field.FIELD_PREFIX.length).split('.');
      const tampered = `${field.FIELD_PREFIX}${parts[0]}.${parts[1]}.${adapter.toBase64(flipBit(ct))}`;
      rejects(() => field.openField(tampered, fieldKey, context, adapter));
    });
  });
});
