/**
 * Agree on a version with a peer's handshake message. Both sides run this, so
 * both land on the same answer: min(our max, their max), provided each side's
 * max meets the other's minimum.
 *   { ok: true, version }            — proceed at `version`
 *   { ok: false, reason: 'peer_outdated' }  — the peer must update
 *   { ok: false, reason: 'self_outdated' }  — we must update
 */
export function negotiateProtocol(peer: any): {
    ok: boolean;
    reason: string;
    version?: undefined;
} | {
    ok: boolean;
    version: number;
    reason?: undefined;
};
export function toBase64(bytes: any): string;
export function fromBase64(value: any): Uint8Array<ArrayBuffer>;
export function randomBytes(length: any): Uint8Array<any>;
/**
 * @param {boolean} extractablePrivate - false in the extension so the identity
 *   key is unexportable; the desktop's ephemeral keys don't need export either.
 */
export function generateKeyPair(extractablePrivate?: boolean): Promise<CryptoKeyPair>;
export function exportPublicKey(publicKey: any): Promise<string>;
export function importPublicKey(base64: any): Promise<CryptoKey>;
/** Stable identifier for a peer's public key, shown to the user when pairing. */
export function fingerprint(publicKeyBase64: any): Promise<string>;
/** Short, human-comparable form: 8 groups of 4 hex chars. */
export function shortFingerprint(hex: any): string;
/**
 * ECDH -> HKDF-SHA256 -> AES-256-GCM session key.
 * Both nonces are mixed into the salt so each session gets a distinct key even
 * with the same long-lived identity key.
 */
export function deriveSessionKey({ privateKey, peerPublicKey, clientNonce, serverNonce }: {
    privateKey: any;
    peerPublicKey: any;
    clientNonce: any;
    serverNonce: any;
}): Promise<CryptoKey>;
export function seal(sessionKey: any, payload: any, { direction, seq }: {
    direction: any;
    seq: any;
}): Promise<{
    t: string;
    seq: any;
    iv: string;
    ct: string;
}>;
export function open(sessionKey: any, frame: any, { direction, expectedSeq, now }: {
    direction: any;
    expectedSeq: any;
    now?: number;
}): Promise<any>;
/**
 * End-to-end encryption for the browser-extension <-> desktop bridge.
 *
 * Part of the open-source core (@papersafeailabs/vault-core, SPEC.md §9).
 *
 * Written against WebCrypto ONLY, so the identical implementation runs in the
 * Electron main process (Node's global `crypto.subtle`) and in the extension
 * service worker. The extension ships a byte-identical copy (an extension
 * can't import from outside its own folder), and the app build fails if the
 * two drift.
 *
 * ── Design ────────────────────────────────────────────────────────────────
 * Identity   The extension generates a NON-EXTRACTABLE ECDH P-256 key pair and
 *            keeps it in IndexedDB. The private key can never be read back out
 *            by script — not by the page, not by the extension itself, not by
 *            malware scraping extension storage. Its public key is what the
 *            desktop pins during pairing.
 * Pairing    On first contact the desktop asks the user to approve, then pins
 *            SHA-256(extension public key). A different extension — or a
 *            tampered copy of ours — produces a different fingerprint and is
 *            rejected without another explicit approval.
 * Session    The desktop generates a FRESH ephemeral key pair per connection.
 *            The shared secret is ECDH(extension identity, desktop ephemeral),
 *            so nothing the desktop stores can decrypt past sessions (forward
 *            secrecy on the desktop side only). The extension's identity key
 *            takes part in every session: code able to USE that key (it cannot
 *            be exported), together with recorded frames, could recompute past
 *            session keys. The desktop has no identity key, so the extension
 *            relies on the OS (native-messaging host registration, a user-only
 *            socket) to know it reached the real desktop. SPEC.md §12.
 * Keys       HKDF-SHA256(shared secret, salt = clientNonce||serverNonce,
 *            info = protocol label) -> 256-bit AES-GCM key.
 * Messages   AES-256-GCM with a random 96-bit IV. The sequence number and
 *            direction are bound in as additional authenticated data, so a
 *            message cannot be replayed, reordered, or reflected back at its
 *            sender. A timestamp bounds how long a captured frame stays valid.
 *
 * NOTE: the master password is deliberately NOT part of this. The browser never
 * holds vault keys; encryption here protects the channel, while authorisation
 * still requires explicit user consent on the desktop.
 */
export const PROTOCOL: "papersafeai-bridge-v1";
export const MAX_CLOCK_SKEW_MS: 60000;
export const BRIDGE_PROTOCOL_VERSION: 2;
export const MIN_SUPPORTED_PROTOCOL: 1;
