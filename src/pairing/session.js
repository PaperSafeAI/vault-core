'use strict';

/**
 * Forward-secret sync sessions between a paired phone and the desktop.
 * SPEC.md §8 (sync sessions). ON-WIRE FORMAT: every constant below is shared by a desktop and
 * a phone that may be on different app versions — change one only as a new
 * version, never in place.
 *
 * Without a session every body is sealed under the pairing's fixed transport
 * key (./transport.js), so traffic recorded today is readable by whoever learns
 * the pairing secret later. A session puts a fresh X25519 exchange in front:
 *
 *   phone   → POST /session/open   { v:1, pub: hex(E_p) }      (signed and sealed as today)
 *   desktop → { v:1, id: hex(sessionId 16), pub: hex(E_d), expiresIn }
 *             sealed under the transport key, bound to the request (response binding)
 *
 *   shared = X25519(e_p, E_d) = X25519(e_d, E_p)      (refused if all zero)
 *   th     = SHA-256("psai-sess-v1\n" fingerprint "\n" deviceId "\n" hex(sessionId) "\n" hex(E_p) "\n" hex(E_d))
 *   k_p2d  = HKDF-SHA256(shared, salt=th, info="papersafe-session-v1 phone->desktop", 32)
 *   k_d2p  = HKDF-SHA256(shared, salt=th, info="papersafe-session-v1 desktop->phone", 32)
 *
 * Both sides drop the ephemeral private keys once the keys are derived and
 * keep the session only in memory. A later request names it with the header
 * `x-papersafe-session: hex(sessionId)`, is still signed with the pairing secret
 * exactly as before (signature, timestamp window and nonce replay unchanged),
 * and its body is sealed under k_p2d. The answer is sealed under k_d2p, always
 * with the AAD sessionResponseAad(...) below. Two directional keys mean a
 * request can never be reflected back as an answer.
 *
 * A leaked pairing secret still lets its holder impersonate either side to
 * open NEW sessions; it no longer opens sessions recorded before.
 *
 * VERSION 2 adds device identity keys (protocol 8.3 identityKeys). Each device
 * has a long-term X25519 key (s_p/S_p on the phone, s_d/S_d on the desktop);
 * each pins the other's public key (the desktop's arrives in QR v3, or on first
 * use). The open carries them, and the session keys need all three exchanges:
 *
 *   phone   → { v:2, pub: hex(E_p), spk: hex(S_p) }
 *   desktop → { v:2, id, pub: hex(E_d), spk: hex(S_d), expiresIn }
 *
 *   ikm   = X25519(e_p, E_d) || X25519(s_p, E_d) || X25519(e_p, S_d)
 *   th    = SHA-256("psai-sess-v2\n" fingerprint "\n" deviceId "\n" hex(sessionId) "\n" hex(E_p) "\n" hex(E_d) "\n" hex(S_p) "\n" hex(S_d))
 *   k_p2d = HKDF-SHA256(ikm, salt=th, info="papersafe-session-v2 phone->desktop", 32), k_d2p likewise
 *
 * so only the holder of s_p can be the phone and only the holder of s_d the
 * desktop: an impostor with the pairing secret derives other keys and its
 * first sealed body fails to open. The first exchange is ephemeral on both
 * sides, so forward secrecy is unchanged.
 */
// No require of ./transport: the phone app copies that file in under another
// name, so this module stands alone.

const SESSION_VERSION = 1;
/** Sessions with device identity keys (protocol 8.3). */
const SESSION_VERSION_IDENTITY = 2;
/** The sync protocol feature (8.3) under which the apps use version 2. */
const IDENTITY_FEATURE = 'identityKeys';
/** The refusal when a device presents an identity key other than the one pinned. */
const IDENTITY_MISMATCH_CODE = 'identity_mismatch';
/** The sync protocol feature (8.2) a desktop advertises for sessions. */
const SESSION_FEATURE = 'sessionKeys';
const SESSION_OPEN_ROUTE = '/session/open';
// Lower case: Node hands the desktop its request headers lower-cased.
const SESSION_HEADER = 'x-papersafe-session';
/** The refusal code for an unknown or expired session; the phone opens a new one. */
const SESSION_EXPIRED_CODE = 'session_expired';
/** Desktop-side lifetime: dropped after this long unused, and after this long in all. */
const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_MAX_MS = 60 * 60 * 1000;

const SESSION_ID_LENGTH = 16;
const X25519_KEY_LENGTH = 32;
const TRANSCRIPT_LABEL = 'psai-sess-v1';
const KEY_INFO_PHONE_TO_DESKTOP = 'papersafe-session-v1 phone->desktop';
const KEY_INFO_DESKTOP_TO_PHONE = 'papersafe-session-v1 desktop->phone';
const TRANSCRIPT_LABEL_V2 = 'psai-sess-v2';
const KEY_INFO_V2_PHONE_TO_DESKTOP = 'papersafe-session-v2 phone->desktop';
const KEY_INFO_V2_DESKTOP_TO_PHONE = 'papersafe-session-v2 desktop->phone';
const RESPONSE_AAD_LABEL = 'psai-resp-v2';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function toHex(bytes) {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function hexOfLength(value, length, what) {
  if (typeof value !== 'string' || value.length !== length * 2 || !/^[0-9a-f]+$/.test(value)) {
    throw new Error(`session: ${what} must be ${length} bytes of lower-case hex.`);
  }
  return fromHex(value);
}

function bytesOfLength(value, length, what) {
  if (!(value instanceof Uint8Array) || value.length !== length) throw new Error(`session: ${what} must be ${length} bytes.`);
  return value;
}

function parseJsonObject(bytes, what) {
  let parsed;
  try {
    parsed = JSON.parse(decoder.decode(new Uint8Array(bytes)));
  } catch {
    throw new Error(`session: ${what} is not JSON.`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`session: ${what} is not an object.`);
  if (parsed.v !== SESSION_VERSION && parsed.v !== SESSION_VERSION_IDENTITY) throw new Error(`session: unsupported ${what} version.`);
  return parsed;
}

/** A fresh ephemeral key pair. The private key is the adapter's opaque handle; use it once. */
function createEphemeral(adapter) {
  const pair = adapter.x25519GenerateKeyPair();
  bytesOfLength(pair && pair.publicKey, X25519_KEY_LENGTH, 'an X25519 public key');
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(pair.publicKey) };
}

/**
 * A device's long-term identity key. Unlike an ephemeral key, its private half
 * is returned as 32 raw bytes, for the caller to keep in the OS keystore.
 */
function createIdentityKey(adapter) {
  const pair = adapter.x25519GenerateKeyPair({ exportPrivate: true });
  bytesOfLength(pair && pair.publicKey, X25519_KEY_LENGTH, 'an X25519 public key');
  bytesOfLength(pair && pair.privateKey, X25519_KEY_LENGTH, 'an exported X25519 private key');
  return { privateKey: new Uint8Array(pair.privateKey), publicKey: new Uint8Array(pair.publicKey) };
}

/** A fresh random session id (desktop). */
function createSessionId(adapter) {
  return new Uint8Array(bytesOfLength(new Uint8Array(adapter.randomBytes(SESSION_ID_LENGTH)), SESSION_ID_LENGTH, 'a session id'));
}

/**
 * The phone's /session/open body (plaintext; sealed under the transport key
 * like any body). Version 2 when the phone's identity key is given.
 *
 * @param {Uint8Array} phonePublic
 * @param {{ identityPublic?: Uint8Array | null }} [options]
 * @returns {Uint8Array}
 */
function encodeOpenRequest(phonePublic, { identityPublic = null } = {}) {
  const pub = toHex(bytesOfLength(phonePublic, X25519_KEY_LENGTH, 'the phone key'));
  if (!identityPublic) return encoder.encode(JSON.stringify({ v: SESSION_VERSION, pub }));
  return encoder.encode(JSON.stringify({
    v: SESSION_VERSION_IDENTITY, pub, spk: toHex(bytesOfLength(identityPublic, X25519_KEY_LENGTH, 'the phone identity key'))
  }));
}

/** `{ version, phonePublic, phoneIdentity }` from a /session/open body (`phoneIdentity` null in v1). Throws on anything else. */
function parseOpenRequest(bytes) {
  const p = parseJsonObject(bytes, 'open request');
  return {
    version: p.v,
    phonePublic: hexOfLength(p.pub, X25519_KEY_LENGTH, 'pub'),
    phoneIdentity: p.v === SESSION_VERSION_IDENTITY ? hexOfLength(p.spk, X25519_KEY_LENGTH, 'spk') : null
  };
}

/**
 * The desktop's answer (plaintext; sealed under the transport key with
 * response binding). Version 2 when the desktop's identity key is given.
 *
 * @param {{ sessionId: Uint8Array, desktopPublic: Uint8Array, expiresIn: number, identityPublic?: Uint8Array | null }} answer
 * @returns {Uint8Array}
 */
function encodeOpenAnswer({ sessionId, desktopPublic, expiresIn, identityPublic = null }) {
  if (!Number.isInteger(expiresIn) || expiresIn < 1) throw new Error('session: expiresIn must be a positive whole number of seconds.');
  const answer = {
    v: identityPublic ? SESSION_VERSION_IDENTITY : SESSION_VERSION,
    id: toHex(bytesOfLength(sessionId, SESSION_ID_LENGTH, 'the session id')),
    pub: toHex(bytesOfLength(desktopPublic, X25519_KEY_LENGTH, 'the desktop key')),
    ...(identityPublic ? { spk: toHex(bytesOfLength(identityPublic, X25519_KEY_LENGTH, 'the desktop identity key')) } : {}),
    expiresIn
  };
  return encoder.encode(JSON.stringify(answer));
}

/** `{ version, sessionId, desktopPublic, desktopIdentity, expiresIn }` from the desktop's answer. Throws on anything else. */
function parseOpenAnswer(bytes) {
  const p = parseJsonObject(bytes, 'open answer');
  if (!Number.isInteger(p.expiresIn) || p.expiresIn < 1) throw new Error('session: expiresIn must be a positive whole number of seconds.');
  return {
    version: p.v,
    sessionId: hexOfLength(p.id, SESSION_ID_LENGTH, 'id'),
    desktopPublic: hexOfLength(p.pub, X25519_KEY_LENGTH, 'pub'),
    desktopIdentity: p.v === SESSION_VERSION_IDENTITY ? hexOfLength(p.spk, X25519_KEY_LENGTH, 'spk') : null,
    expiresIn: p.expiresIn
  };
}

/** The transcript hash both keys are salted with: binds the pairing, device, session and both public keys. */
function sessionTranscript({ fingerprint, deviceId, sessionId, phonePublic, desktopPublic }, adapter) {
  if (typeof fingerprint !== 'string' || !/^[0-9a-f]{32}$/.test(fingerprint)) throw new Error('session: a pairing fingerprint is required.');
  if (typeof deviceId !== 'string' || !deviceId || /[\n\r]/.test(deviceId)) throw new Error('session: a device id without line breaks is required.');
  const text = [
    TRANSCRIPT_LABEL,
    fingerprint,
    deviceId,
    toHex(bytesOfLength(sessionId, SESSION_ID_LENGTH, 'the session id')),
    toHex(bytesOfLength(phonePublic, X25519_KEY_LENGTH, 'the phone key')),
    toHex(bytesOfLength(desktopPublic, X25519_KEY_LENGTH, 'the desktop key'))
  ].join('\n');
  return new Uint8Array(adapter.sha256(encoder.encode(text)));
}

/** One X25519 exchange. Throws when it fails or yields all zeros (a low-order peer key). */
function exchange(privateKey, peerPublic, adapter) {
  bytesOfLength(peerPublic, X25519_KEY_LENGTH, 'the peer key');
  let shared;
  try {
    shared = new Uint8Array(adapter.x25519SharedSecret(privateKey, peerPublic));
  } catch {
    // OpenSSL refuses a low-order key itself; other libraries return zeros (below).
    throw new Error('session: the key exchange produced no secret (a low-order or invalid public key).');
  }
  bytesOfLength(shared, X25519_KEY_LENGTH, 'the X25519 output');
  let any = 0;
  for (const byte of shared) any |= byte;
  if (any === 0) throw new Error('session: the key exchange produced no secret (a low-order public key).');
  return shared;
}

/** Version 2's transcript: version 1's fields, then both identity keys. */
function sessionTranscriptV2({ fingerprint, deviceId, sessionId, phonePublic, desktopPublic, phoneIdentity, desktopIdentity }, adapter) {
  if (typeof fingerprint !== 'string' || !/^[0-9a-f]{32}$/.test(fingerprint)) throw new Error('session: a pairing fingerprint is required.');
  if (typeof deviceId !== 'string' || !deviceId || /[\n\r]/.test(deviceId)) throw new Error('session: a device id without line breaks is required.');
  const text = [
    TRANSCRIPT_LABEL_V2,
    fingerprint,
    deviceId,
    toHex(bytesOfLength(sessionId, SESSION_ID_LENGTH, 'the session id')),
    toHex(bytesOfLength(phonePublic, X25519_KEY_LENGTH, 'the phone key')),
    toHex(bytesOfLength(desktopPublic, X25519_KEY_LENGTH, 'the desktop key')),
    toHex(bytesOfLength(phoneIdentity, X25519_KEY_LENGTH, 'the phone identity key')),
    toHex(bytesOfLength(desktopIdentity, X25519_KEY_LENGTH, 'the desktop identity key'))
  ].join('\n');
  return new Uint8Array(adapter.sha256(encoder.encode(text)));
}

/**
 * The two session keys. Both sides get the same `{ phoneToDesktop, desktopToPhone }`.
 *
 * Version 1: `privateKey` is this side's ephemeral key, `peerPublic` the
 * other's. Version 2 adds `identity: { role: 'phone'|'desktop', privateKey,
 * phoneIdentity, desktopIdentity }` — this side's identity private key (raw)
 * and both identity public keys — and mixes in the two exchanges that need them.
 *
 * @param {{ privateKey: any, peerPublic?: Uint8Array, phonePublic: Uint8Array, desktopPublic: Uint8Array,
 *   sessionId: Uint8Array, fingerprint: string, deviceId: string,
 *   identity?: { role: 'phone' | 'desktop', privateKey: Uint8Array, phoneIdentity: Uint8Array, desktopIdentity: Uint8Array } | null }} args
 * @param {object} adapter
 * @returns {{ phoneToDesktop: Uint8Array, desktopToPhone: Uint8Array }}
 */
function deriveSessionKeys({ privateKey, peerPublic, phonePublic, desktopPublic, sessionId, fingerprint, deviceId, identity = null }, adapter) {
  if (!identity) {
    const salt = sessionTranscript({ fingerprint, deviceId, sessionId, phonePublic, desktopPublic }, adapter);
    const shared = exchange(privateKey, peerPublic, adapter);
    const derive = (info) => new Uint8Array(adapter.hkdfSha256({ key: shared, salt, info: encoder.encode(info), length: 32 }));
    const keys = { phoneToDesktop: derive(KEY_INFO_PHONE_TO_DESKTOP), desktopToPhone: derive(KEY_INFO_DESKTOP_TO_PHONE) };
    shared.fill(0);
    return keys;
  }
  const { role, phoneIdentity, desktopIdentity } = identity;
  if (role !== 'phone' && role !== 'desktop') throw new Error('session: identity.role must be "phone" or "desktop".');
  const salt = sessionTranscriptV2({ fingerprint, deviceId, sessionId, phonePublic, desktopPublic, phoneIdentity, desktopIdentity }, adapter);
  // The same three values from either side, in the same order:
  //   ee = X25519(e_p, E_d)   se = X25519(s_p, E_d)   es = X25519(e_p, S_d)
  const parts = role === 'phone'
    ? [exchange(privateKey, desktopPublic, adapter), exchange(identity.privateKey, desktopPublic, adapter), exchange(privateKey, desktopIdentity, adapter)]
    : [exchange(privateKey, phonePublic, adapter), exchange(privateKey, phoneIdentity, adapter), exchange(identity.privateKey, phonePublic, adapter)];
  const ikm = new Uint8Array(X25519_KEY_LENGTH * 3);
  parts.forEach((part, i) => { ikm.set(part, i * X25519_KEY_LENGTH); part.fill(0); });
  const derive = (info) => new Uint8Array(adapter.hkdfSha256({ key: ikm, salt, info: encoder.encode(info), length: 32 }));
  const keys = { phoneToDesktop: derive(KEY_INFO_V2_PHONE_TO_DESKTOP), desktopToPhone: derive(KEY_INFO_V2_DESKTOP_TO_PHONE) };
  ikm.fill(0);
  return keys;
}

/** Equal identity keys (public values; a plain comparison is fine). */
function sameIdentity(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

/** The AAD every answer within a session is sealed with (UTF-8). `requestTarget` is path + query, as signed. */
function sessionResponseAad(method, requestTarget, nonce, sessionIdHex) {
  return encoder.encode(`${RESPONSE_AAD_LABEL}\n${String(method).toUpperCase()}\n${requestTarget}\n${nonce}\n${sessionIdHex}`);
}

/** The session id from a request header value, or null when it is not one. */
function parseSessionHeader(value) {
  const text = String(value || '');
  return /^[0-9a-f]{32}$/.test(text) ? text : null;
}

module.exports = {
  SESSION_VERSION,
  SESSION_VERSION_IDENTITY,
  IDENTITY_FEATURE,
  IDENTITY_MISMATCH_CODE,
  createIdentityKey,
  sessionTranscriptV2,
  sameIdentity,
  SESSION_FEATURE,
  SESSION_OPEN_ROUTE,
  SESSION_HEADER,
  SESSION_EXPIRED_CODE,
  SESSION_IDLE_MS,
  SESSION_MAX_MS,
  SESSION_ID_LENGTH,
  X25519_KEY_LENGTH,
  createEphemeral,
  createSessionId,
  encodeOpenRequest,
  parseOpenRequest,
  encodeOpenAnswer,
  parseOpenAnswer,
  sessionTranscript,
  deriveSessionKeys,
  sessionResponseAad,
  parseSessionHeader
};
