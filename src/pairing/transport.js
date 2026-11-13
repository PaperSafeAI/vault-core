'use strict';

/**
 * Pairing a phone with the desktop, and protecting every request between them.
 * SPEC.md §8. ON-WIRE FORMAT: every constant below is shared by a desktop and
 * a phone that may be on different app versions — change one only as a new
 * version, never in place.
 *
 * Pairing: the desktop shows a QR code holding a fresh random 32-byte pairing
 * secret. Nothing else is exchanged; the secret never travels over the
 * network. From it both sides derive:
 *
 *   transport key = HMAC-SHA256(secret, "papersafe-transport-v2")
 *   fingerprint   = hex(HMAC-SHA256(secret, "papersafe-fp-v1"))[0..32]
 *
 * Every request is signed:
 *
 *   Authorization: PapersafeHMAC ts=<epoch s>,nonce=<hex32>,sig=<hex64>,id=<deviceId>[,inst=<installId>]
 *   sig = HMAC-SHA256(secret, "PSHMAC-v3\n<METHOD>\n<path+query>\n<ts>\n<nonce>\n<hex sha256(body)>")
 *
 * — bound to the method, exact target and body, so a captured header cannot be
 * replayed onto another route. The desktop also refuses a ts outside its window
 * and any nonce it has seen. Request and response bodies are sealed under the
 * transport key:
 *
 *   [12-byte nonce][16-byte GCM tag][AES-256-GCM ciphertext]
 *
 * with no AAD, except an answer to a request that asked for response binding
 * (./response-binding.js), which is sealed with that request's binding as AAD.
 *
 * `inst` names the phone install. It is outside the signature on purpose (the
 * HMAC input is fixed by the format) and is no security boundary: it lets the
 * desktop bind a pairing to the first install that uses it.
 *
 * Platform-free like the rest of the core. The adapter supplies:
 *   randomBytes(n), hmacSha256(key, bytes), sha256(bytes),
 *   aesGcmSeal({ plaintext, key, iv }), aesGcmOpen({ ciphertext, key, iv, tag })
 */

const PAIRING_QR_VERSION = 2;
/**
 * QR v3 adds `spk`, the desktop's identity public key (session.js version 2),
 * so the phone knows the real desktop before its first request. Read now;
 * written once the phone build that reads it is live.
 */
const PAIRING_QR_VERSION_IDENTITY = 3;
const PAIRING_SECRET_LENGTH = 32;
const TRANSPORT_KEY_INFO = 'papersafe-transport-v2';
const FINGERPRINT_INFO = 'papersafe-fp-v1';
const FINGERPRINT_HEX_LENGTH = 32;
const SIGNING_VERSION = 'PSHMAC-v3';
const AUTH_SCHEME = 'PapersafeHMAC';
const REQUEST_NONCE_LENGTH = 16;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = NONCE_LENGTH + TAG_LENGTH;

const encoder = new TextEncoder();

function toHex(bytes) {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

function fromHex(hex) {
  const text = String(hex || '');
  if (!/^(?:[0-9a-f]{2})*$/i.test(text)) throw new Error('Expected a hex string.');
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** A pairing secret as bytes, from bytes or its 64-character hex form (the QR's). */
function secretBytes(secret) {
  const bytes = typeof secret === 'string' ? fromHex(secret) : new Uint8Array(secret || []);
  if (bytes.length !== PAIRING_SECRET_LENGTH) throw new Error('A pairing secret must be 32 bytes.');
  return bytes;
}

function hmac(secret, text, adapter) {
  const out = adapter.hmacSha256(secretBytes(secret), encoder.encode(text));
  if (!out || out.length !== 32) throw new Error('HMAC adapter must return 32 bytes.');
  return new Uint8Array(out);
}

/** A fresh pairing secret. Shown once, in the QR code; never sent over the network. */
function generatePairingSecret(adapter) {
  const secret = adapter.randomBytes(PAIRING_SECRET_LENGTH);
  if (!secret || secret.length !== PAIRING_SECRET_LENGTH) throw new Error('Could not generate a pairing secret.');
  return new Uint8Array(secret);
}

/** The AES-256-GCM key for request and response bodies. */
function deriveTransportKey(secret, adapter) {
  return hmac(secret, TRANSPORT_KEY_INFO, adapter);
}

/** What the desktop advertises on the LAN so the phone can find it; reveals nothing of the secret. */
function pairingFingerprint(secret, adapter) {
  return toHex(hmac(secret, FINGERPRINT_INFO, adapter)).slice(0, FINGERPRINT_HEX_LENGTH);
}

/** Path + query of a URL; Node's `req.url` on the receiving side. */
function requestTargetOf(url) {
  return String(url).replace(/^https?:\/\/[^/]+/i, '');
}

function buildSigningString({ method, requestTarget, ts, nonce, bodyHashHex }) {
  return `${SIGNING_VERSION}\n${method}\n${requestTarget}\n${ts}\n${nonce}\n${bodyHashHex}`;
}

function bodyHashHex(body, adapter) {
  return toHex(adapter.sha256(body ? new Uint8Array(body) : new Uint8Array(0)));
}

/** The signature over one request, hex. */
function signRequest(secret, { method, requestTarget, ts, nonce, bodyHash }, adapter) {
  return toHex(hmac(secret, buildSigningString({
    method: String(method).toUpperCase(), requestTarget, ts: String(ts), nonce, bodyHashHex: bodyHash
  }), adapter));
}

/**
 * The Authorization header for a request to the paired desktop.
 * `body` is the bytes actually sent — for a sealed body, the SEALED bytes.
 *
 * @param {string|Uint8Array} secret
 * @param {string} deviceId
 * @param {{ method: string, url: string, body?: Uint8Array }} request
 * @param {object} adapter
 * @param {{ now?: number, installId?: string }} [options]
 * @returns {string}
 */
function buildAuthHeader(secret, deviceId, { method, url, body }, adapter, { now = Date.now(), installId = '' } = {}) {
  const ts = String(Math.floor(now / 1000));
  const nonce = toHex(adapter.randomBytes(REQUEST_NONCE_LENGTH));
  const sig = signRequest(secret, {
    method, requestTarget: requestTargetOf(url), ts, nonce, bodyHash: bodyHashHex(body, adapter)
  }, adapter);
  const inst = installId ? `,inst=${installId}` : '';
  return `${AUTH_SCHEME} ts=${ts},nonce=${nonce},sig=${sig},id=${deviceId}${inst}`;
}

/** `{ ts, nonce, sig, id[, inst] }` from an Authorization header, or null if it is not one. */
function parseAuthHeader(header) {
  const text = String(header || '');
  if (!text.startsWith(`${AUTH_SCHEME} `)) return null;
  const params = {};
  for (const part of text.slice(AUTH_SCHEME.length + 1).split(',')) {
    const [k, v] = part.trim().split('=');
    if (k && v !== undefined) params[k.trim()] = v.trim();
  }
  if (!params.ts || !params.nonce || !params.sig || !params.id) return null;
  return params;
}

/** Equal-length comparison whose time does not depend on where the inputs differ. */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * True when `sig` is this request's signature under `secret`. Checks the
 * signature only: the timestamp window and nonce replay are the receiver's
 * (they need its clock and its record of spent nonces).
 */
function verifyRequestSignature(secret, { sig, method, requestTarget, ts, nonce, bodyHash }, adapter) {
  let given;
  try {
    given = fromHex(sig);
  } catch {
    return false;
  }
  const expected = fromHex(signRequest(secret, { method, requestTarget, ts, nonce, bodyHash }, adapter));
  return constantTimeEqual(given, expected);
}

/**
 * Seal a body: [nonce 12][tag 16][ciphertext]. A fresh random nonce every call
 * is not optional — the transport key lives as long as the pairing, and GCM
 * loses confidentiality, not just integrity, if a nonce repeats under one key.
 *
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} transportKey
 * @param {object} adapter
 * @param {{ aad?: Uint8Array | null }} [options]
 * @returns {Uint8Array}
 */
function sealTransport(plaintext, transportKey, adapter, { aad = null } = {}) {
  const iv = adapter.randomBytes(NONCE_LENGTH);
  const { ciphertext, tag } = adapter.aesGcmSeal({ plaintext: new Uint8Array(plaintext), key: transportKey, iv, aad: aad || null });
  if (!tag || tag.length !== TAG_LENGTH) throw new Error('AES-GCM adapter returned a bad tag.');
  const out = new Uint8Array(HEADER_LENGTH + ciphertext.length);
  out.set(iv, 0);
  out.set(tag, NONCE_LENGTH);
  out.set(ciphertext, HEADER_LENGTH);
  return out;
}

/**
 * Open a sealed body (with the response binding as `aad` when the request
 * asked for one). Throws if it is too short or fails authentication.
 *
 * @param {Uint8Array} sealed
 * @param {Uint8Array} transportKey
 * @param {object} adapter
 * @param {{ aad?: Uint8Array | null }} [options]
 * @returns {Uint8Array}
 */
function openTransport(sealed, transportKey, adapter, { aad = null } = {}) {
  const bytes = new Uint8Array(sealed);
  if (bytes.length < HEADER_LENGTH) throw new Error('Encrypted body too short.');
  return new Uint8Array(adapter.aesGcmOpen({
    ciphertext: bytes.subarray(HEADER_LENGTH),
    key: transportKey,
    iv: bytes.subarray(0, NONCE_LENGTH),
    tag: bytes.subarray(NONCE_LENGTH, HEADER_LENGTH),
    aad: aad || null
  }));
}

/** The QR payload the desktop shows: v3 when the desktop's identity key is given, else v2. */
function buildPairingQrPayload({ deviceId, secret, fingerprint, ip, port, identityKey = null }) {
  const payload = { v: PAIRING_QR_VERSION, id: deviceId, secret: toHex(secretBytes(secret)), fp: fingerprint, ip, port };
  if (!identityKey) return payload;
  const spk = new Uint8Array(identityKey);
  if (spk.length !== 32) throw new Error('A desktop identity key must be 32 bytes.');
  return { ...payload, v: PAIRING_QR_VERSION_IDENTITY, spk: toHex(spk) };
}

/** Validate a scanned QR. Throws a message fit to show the user. */
function parsePairingQr(raw) {
  let p;
  try {
    p = JSON.parse(raw);
  } catch {
    throw new Error('QR code does not contain valid JSON.');
  }
  if (!p || typeof p !== 'object') throw new Error('Not a pairing QR code.');
  // A later PaperSafe's QR carries the same device fields under a higher `v`:
  // say "update", not "wrong code".
  if (typeof p.v === 'number' && p.v > PAIRING_QR_VERSION_IDENTITY && typeof p.id === 'string' && typeof p.fp === 'string') {
    throw new Error('This QR code needs a newer version of PaperSafe. Update the app and try again.');
  }
  if (p.v !== PAIRING_QR_VERSION && p.v !== PAIRING_QR_VERSION_IDENTITY) throw new Error('Not a pairing QR code.');
  if (p.v === PAIRING_QR_VERSION_IDENTITY && (typeof p.spk !== 'string' || !/^[0-9a-f]{64}$/.test(p.spk))) {
    throw new Error('Invalid computer identity key in QR.');
  }
  if (typeof p.id !== 'string' || !p.id) throw new Error('Missing device ID in QR.');
  if (typeof p.secret !== 'string' || !/^[0-9a-f]{64}$/.test(p.secret)) throw new Error('Invalid pairing secret in QR.');
  if (typeof p.fp !== 'string' || !p.fp) throw new Error('Missing fingerprint in QR.');
  if (typeof p.ip !== 'string' || !p.ip) throw new Error('Missing IP in QR.');
  if (typeof p.port !== 'number' || p.port < 1 || p.port > 65535) throw new Error('Invalid port in QR.');
  return p;
}

module.exports = {
  PAIRING_QR_VERSION,
  PAIRING_QR_VERSION_IDENTITY,
  TRANSPORT_KEY_INFO,
  FINGERPRINT_INFO,
  SIGNING_VERSION,
  AUTH_SCHEME,
  NONCE_LENGTH,
  TAG_LENGTH,
  HEADER_LENGTH,
  generatePairingSecret,
  deriveTransportKey,
  pairingFingerprint,
  requestTargetOf,
  buildSigningString,
  bodyHashHex,
  signRequest,
  buildAuthHeader,
  parseAuthHeader,
  verifyRequestSignature,
  sealTransport,
  openTransport,
  buildPairingQrPayload,
  parsePairingQr,
  toHex,
  fromHex
};
