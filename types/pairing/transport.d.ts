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
export const PAIRING_QR_VERSION: 2;
/**
 * QR v3 adds `spk`, the desktop's identity public key (session.js version 2),
 * so the phone knows the real desktop before its first request. Read now;
 * written once the phone build that reads it is live.
 */
export const PAIRING_QR_VERSION_IDENTITY: 3;
export const TRANSPORT_KEY_INFO: "papersafe-transport-v2";
export const FINGERPRINT_INFO: "papersafe-fp-v1";
export const SIGNING_VERSION: "PSHMAC-v3";
export const AUTH_SCHEME: "PapersafeHMAC";
export const NONCE_LENGTH: 12;
export const TAG_LENGTH: 16;
export const HEADER_LENGTH: number;
/** A fresh pairing secret. Shown once, in the QR code; never sent over the network. */
export function generatePairingSecret(adapter: any): Uint8Array<any>;
/** The AES-256-GCM key for request and response bodies. */
export function deriveTransportKey(secret: any, adapter: any): Uint8Array<any>;
/** What the desktop advertises on the LAN so the phone can find it; reveals nothing of the secret. */
export function pairingFingerprint(secret: any, adapter: any): string;
/** Path + query of a URL; Node's `req.url` on the receiving side. */
export function requestTargetOf(url: any): string;
export function buildSigningString({ method, requestTarget, ts, nonce, bodyHashHex }: {
    method: any;
    requestTarget: any;
    ts: any;
    nonce: any;
    bodyHashHex: any;
}): string;
export function bodyHashHex(body: any, adapter: any): string;
/** The signature over one request, hex. */
export function signRequest(secret: any, { method, requestTarget, ts, nonce, bodyHash }: {
    method: any;
    requestTarget: any;
    ts: any;
    nonce: any;
    bodyHash: any;
}, adapter: any): string;
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
export function buildAuthHeader(secret: string | Uint8Array, deviceId: string, { method, url, body }: {
    method: string;
    url: string;
    body?: Uint8Array;
}, adapter: object, { now, installId }?: {
    now?: number;
    installId?: string;
}): string;
/** `{ ts, nonce, sig, id[, inst] }` from an Authorization header, or null if it is not one. */
export function parseAuthHeader(header: any): {};
/**
 * True when `sig` is this request's signature under `secret`. Checks the
 * signature only: the timestamp window and nonce replay are the receiver's
 * (they need its clock and its record of spent nonces).
 */
export function verifyRequestSignature(secret: any, { sig, method, requestTarget, ts, nonce, bodyHash }: {
    sig: any;
    method: any;
    requestTarget: any;
    ts: any;
    nonce: any;
    bodyHash: any;
}, adapter: any): boolean;
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
export function sealTransport(plaintext: Uint8Array, transportKey: Uint8Array, adapter: object, { aad }?: {
    aad?: Uint8Array | null;
}): Uint8Array;
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
export function openTransport(sealed: Uint8Array, transportKey: Uint8Array, adapter: object, { aad }?: {
    aad?: Uint8Array | null;
}): Uint8Array;
/** The QR payload the desktop shows: v3 when the desktop's identity key is given, else v2. */
export function buildPairingQrPayload({ deviceId, secret, fingerprint, ip, port, identityKey }: {
    deviceId: any;
    secret: any;
    fingerprint: any;
    ip: any;
    port: any;
    identityKey?: any;
}): {
    v: number;
    id: any;
    secret: string;
    fp: any;
    ip: any;
    port: any;
};
/** Validate a scanned QR. Throws a message fit to show the user. */
export function parsePairingQr(raw: any): any;
export function toHex(bytes: any): string;
export function fromHex(hex: any): Uint8Array<ArrayBuffer>;
