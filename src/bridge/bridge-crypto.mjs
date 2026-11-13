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

export const PROTOCOL = 'papersafeai-bridge-v1';
export const MAX_CLOCK_SKEW_MS = 60_000;

// ── protocol versioning ────────────────────────────────────────────────────
// Both handshake messages carry { protocolVersion, minSupportedProtocol }.
// Bump BRIDGE_PROTOCOL_VERSION on any wire change; raise MIN_SUPPORTED_PROTOCOL
// only when an old peer must be turned away. A peer that sends no version is
// version 1 (the original, unversioned handshake).
// v2: handshake reply adds an optional `pro` boolean (toolbar icon). Additive.
export const BRIDGE_PROTOCOL_VERSION = 2;
export const MIN_SUPPORTED_PROTOCOL = 1;

/**
 * Agree on a version with a peer's handshake message. Both sides run this, so
 * both land on the same answer: min(our max, their max), provided each side's
 * max meets the other's minimum.
 *   { ok: true, version }            — proceed at `version`
 *   { ok: false, reason: 'peer_outdated' }  — the peer must update
 *   { ok: false, reason: 'self_outdated' }  — we must update
 */
export function negotiateProtocol(peer) {
  const asVersion = (v) => (Number.isInteger(v) && v > 0 ? v : 1);
  const peerVersion = asVersion(peer?.protocolVersion);
  const peerMin = asVersion(peer?.minSupportedProtocol);
  if (peerVersion < MIN_SUPPORTED_PROTOCOL) return { ok: false, reason: 'peer_outdated' };
  if (BRIDGE_PROTOCOL_VERSION < peerMin) return { ok: false, reason: 'self_outdated' };
  return { ok: true, version: Math.min(peerVersion, BRIDGE_PROTOCOL_VERSION) };
}

const subtle = () => globalThis.crypto.subtle;
const CURVE = { name: 'ECDH', namedCurve: 'P-256' };

// ── encoding helpers ───────────────────────────────────────────────────────
export function toBase64(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(value) {
  const binary = atob(String(value || ''));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function randomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

// ── keys ───────────────────────────────────────────────────────────────────
/**
 * @param {boolean} extractablePrivate - false in the extension so the identity
 *   key is unexportable; the desktop's ephemeral keys don't need export either.
 */
export async function generateKeyPair(extractablePrivate = false) {
  return subtle().generateKey(CURVE, extractablePrivate, ['deriveBits']);
}

export async function exportPublicKey(publicKey) {
  return toBase64(await subtle().exportKey('raw', publicKey));
}

export async function importPublicKey(base64) {
  return subtle().importKey('raw', fromBase64(base64), CURVE, false, []);
}

/** Stable identifier for a peer's public key, shown to the user when pairing. */
export async function fingerprint(publicKeyBase64) {
  const digest = await subtle().digest('SHA-256', fromBase64(publicKeyBase64));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Short, human-comparable form: 8 groups of 4 hex chars. */
export function shortFingerprint(hex) {
  return String(hex || '').slice(0, 32).toUpperCase().match(/.{1,4}/g)?.join('-') || '';
}

/**
 * ECDH -> HKDF-SHA256 -> AES-256-GCM session key.
 * Both nonces are mixed into the salt so each session gets a distinct key even
 * with the same long-lived identity key.
 */
export async function deriveSessionKey({ privateKey, peerPublicKey, clientNonce, serverNonce }) {
  const sharedBits = await subtle().deriveBits(
    { name: 'ECDH', public: peerPublicKey }, privateKey, 256
  );
  const hkdfKey = await subtle().importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  const salt = new Uint8Array([...fromBase64(clientNonce), ...fromBase64(serverNonce)]);
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(PROTOCOL) },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ── framing ────────────────────────────────────────────────────────────────
// direction + seq are authenticated (not encrypted) so a frame can't be
// replayed, reordered, or reflected back to whoever sent it.
function aad(direction, seq) {
  return encoder.encode(`${PROTOCOL}|${direction}|${seq}`);
}

export async function seal(sessionKey, payload, { direction, seq }) {
  const iv = randomBytes(12);
  const plaintext = encoder.encode(JSON.stringify({ payload, ts: Date.now() }));
  const ciphertext = await subtle().encrypt(
    { name: 'AES-GCM', iv, additionalData: aad(direction, seq) }, sessionKey, plaintext
  );
  return { t: 'enc', seq, iv: toBase64(iv), ct: toBase64(ciphertext) };
}

export async function open(sessionKey, frame, { direction, expectedSeq, now = Date.now() }) {
  if (!frame || frame.t !== 'enc') {
    throw new Error('not an encrypted frame');
  }
  if (!Number.isInteger(frame.seq) || frame.seq !== expectedSeq) {
    // Strictly increasing per direction: blocks replay and reordering.
    throw new Error('unexpected sequence number');
  }
  const plaintext = await subtle().decrypt(
    { name: 'AES-GCM', iv: fromBase64(frame.iv), additionalData: aad(direction, frame.seq) },
    sessionKey,
    fromBase64(frame.ct)
  );
  const decoded = JSON.parse(decoder.decode(plaintext));
  if (typeof decoded.ts !== 'number' || Math.abs(now - decoded.ts) > MAX_CLOCK_SKEW_MS) {
    throw new Error('stale frame');
  }
  return decoded.payload;
}
