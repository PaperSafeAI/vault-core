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
export const SESSION_VERSION: 1;
/** Sessions with device identity keys (protocol 8.3). */
export const SESSION_VERSION_IDENTITY: 2;
/** The sync protocol feature (8.3) under which the apps use version 2. */
export const IDENTITY_FEATURE: "identityKeys";
/** The refusal when a device presents an identity key other than the one pinned. */
export const IDENTITY_MISMATCH_CODE: "identity_mismatch";
/**
 * A device's long-term identity key. Unlike an ephemeral key, its private half
 * is returned as 32 raw bytes, for the caller to keep in the OS keystore.
 */
export function createIdentityKey(adapter: any): {
    privateKey: Uint8Array<any>;
    publicKey: Uint8Array<any>;
};
/** Version 2's transcript: version 1's fields, then both identity keys. */
export function sessionTranscriptV2({ fingerprint, deviceId, sessionId, phonePublic, desktopPublic, phoneIdentity, desktopIdentity }: {
    fingerprint: any;
    deviceId: any;
    sessionId: any;
    phonePublic: any;
    desktopPublic: any;
    phoneIdentity: any;
    desktopIdentity: any;
}, adapter: any): Uint8Array<any>;
/** Equal identity keys (public values; a plain comparison is fine). */
export function sameIdentity(a: any, b: any): boolean;
/** The sync protocol feature (8.2) a desktop advertises for sessions. */
export const SESSION_FEATURE: "sessionKeys";
export const SESSION_OPEN_ROUTE: "/session/open";
export const SESSION_HEADER: "x-papersafe-session";
/** The refusal code for an unknown or expired session; the phone opens a new one. */
export const SESSION_EXPIRED_CODE: "session_expired";
/** Desktop-side lifetime: dropped after this long unused, and after this long in all. */
export const SESSION_IDLE_MS: number;
export const SESSION_MAX_MS: number;
export const SESSION_ID_LENGTH: 16;
export const X25519_KEY_LENGTH: 32;
/** A fresh ephemeral key pair. The private key is the adapter's opaque handle; use it once. */
export function createEphemeral(adapter: any): {
    privateKey: any;
    publicKey: Uint8Array<any>;
};
/** A fresh random session id (desktop). */
export function createSessionId(adapter: any): Uint8Array<ArrayBuffer>;
/**
 * The phone's /session/open body (plaintext; sealed under the transport key
 * like any body). Version 2 when the phone's identity key is given.
 *
 * @param {Uint8Array} phonePublic
 * @param {{ identityPublic?: Uint8Array | null }} [options]
 * @returns {Uint8Array}
 */
export function encodeOpenRequest(phonePublic: Uint8Array, { identityPublic }?: {
    identityPublic?: Uint8Array | null;
}): Uint8Array;
/** `{ version, phonePublic, phoneIdentity }` from a /session/open body (`phoneIdentity` null in v1). Throws on anything else. */
export function parseOpenRequest(bytes: any): {
    version: any;
    phonePublic: Uint8Array<ArrayBuffer>;
    phoneIdentity: Uint8Array<ArrayBuffer>;
};
/**
 * The desktop's answer (plaintext; sealed under the transport key with
 * response binding). Version 2 when the desktop's identity key is given.
 *
 * @param {{ sessionId: Uint8Array, desktopPublic: Uint8Array, expiresIn: number, identityPublic?: Uint8Array | null }} answer
 * @returns {Uint8Array}
 */
export function encodeOpenAnswer({ sessionId, desktopPublic, expiresIn, identityPublic }: {
    sessionId: Uint8Array;
    desktopPublic: Uint8Array;
    expiresIn: number;
    identityPublic?: Uint8Array | null;
}): Uint8Array;
/** `{ version, sessionId, desktopPublic, desktopIdentity, expiresIn }` from the desktop's answer. Throws on anything else. */
export function parseOpenAnswer(bytes: any): {
    version: any;
    sessionId: Uint8Array<ArrayBuffer>;
    desktopPublic: Uint8Array<ArrayBuffer>;
    desktopIdentity: Uint8Array<ArrayBuffer>;
    expiresIn: any;
};
/** The transcript hash both keys are salted with: binds the pairing, device, session and both public keys. */
export function sessionTranscript({ fingerprint, deviceId, sessionId, phonePublic, desktopPublic }: {
    fingerprint: any;
    deviceId: any;
    sessionId: any;
    phonePublic: any;
    desktopPublic: any;
}, adapter: any): Uint8Array<any>;
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
export function deriveSessionKeys({ privateKey, peerPublic, phonePublic, desktopPublic, sessionId, fingerprint, deviceId, identity }: {
    privateKey: any;
    peerPublic?: Uint8Array;
    phonePublic: Uint8Array;
    desktopPublic: Uint8Array;
    sessionId: Uint8Array;
    fingerprint: string;
    deviceId: string;
    identity?: {
        role: "phone" | "desktop";
        privateKey: Uint8Array;
        phoneIdentity: Uint8Array;
        desktopIdentity: Uint8Array;
    } | null;
}, adapter: object): {
    phoneToDesktop: Uint8Array;
    desktopToPhone: Uint8Array;
};
/** The AAD every answer within a session is sealed with (UTF-8). `requestTarget` is path + query, as signed. */
export function sessionResponseAad(method: any, requestTarget: any, nonce: any, sessionIdHex: any): Uint8Array<ArrayBuffer>;
/** The session id from a request header value, or null when it is not one. */
export function parseSessionHeader(value: any): string;
