'use strict';

/**
 * Sealing for catalogue `*_cipher` columns (SPEC.md §7).
 *
 * Envelope: `[1B version=1][12B iv][16B tag][ciphertext]` under the catalogue
 * payload key, with MANDATORY associated data (AAD) built by the app-wide
 * builder (../../crypto/aad.js): canonical JSON of
 *   { component: "catalogue-v1", vaultId, recordType, primaryKey, generation? }
 * So a sealed value moved to another row, record type, vault or history
 * generation fails authentication instead of being read as that row's data.
 *
 * AAD is only a protection if the platform's AES-GCM actually binds it. An
 * adapter that takes no `aad` would silently drop it, so every adapter is checked once, before its first use, by a self-test that
 * must fail to open under the wrong AAD (assertBindsAad).
 *
 * Adapter: randomBytes(n), aesGcmSeal({plaintext, key, iv, aad}) -> {ciphertext, tag},
 * aesGcmOpen({ciphertext, key, iv, tag, aad}) -> plaintext (throws on failure).
 * Opening fails closed: wrong AAD, bad tag, unknown version or bad plaintext
 * all throw; nothing partial is returned.
 */

const { canonicalize, utf8, parseStrict } = require('./canonical-json');
const { buildAad, assertBindsAad, COMPONENT_CATALOGUE } = require('../../crypto/aad');

const VERSION = 1;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER = 1 + IV_LENGTH + TAG_LENGTH;

/**
 * The catalogue's AAD is the app-wide scheme (../../crypto/aad.js) under
 * component 'catalogue-v1'. Its bytes are exactly what catalogue sync sealed
 * with before the shared builder: the pinned envelope vector in seal.test.js
 * proves nothing already sealed moved.
 */
function aadFor({ vaultId, recordType, primaryKey, generation }) {
  return buildAad({ component: COMPONENT_CATALOGUE, vaultId, recordType, primaryKey, generation });
}

/** Seal a JSON-compatible value. Returns the envelope bytes for a BLOB column. */
function sealRecord(context, value, payloadKey, adapter) {
  assertBindsAad(adapter);
  const aad = aadFor(context);
  const iv = adapter.randomBytes(IV_LENGTH);
  const { ciphertext, tag } = adapter.aesGcmSeal({ plaintext: utf8(canonicalize(value)), key: payloadKey, iv, aad });
  if (!tag || tag.length !== TAG_LENGTH) throw new Error('AES-GCM adapter returned a bad tag');
  const out = new Uint8Array(HEADER + ciphertext.length);
  out[0] = VERSION;
  out.set(iv, 1);
  out.set(tag, 1 + IV_LENGTH);
  out.set(ciphertext, HEADER);
  return out;
}

/** Open a sealed value for the same context. Throws on any mismatch. */
function openRecord(context, envelope, payloadKey, adapter) {
  assertBindsAad(adapter);
  const bytes = envelope instanceof Uint8Array ? envelope : new Uint8Array(envelope);
  if (bytes.length < HEADER || bytes[0] !== VERSION) throw new Error('not a catalogue envelope');
  const plaintext = adapter.aesGcmOpen({
    ciphertext: bytes.subarray(HEADER),
    key: payloadKey,
    iv: bytes.subarray(1, 1 + IV_LENGTH),
    tag: bytes.subarray(1 + IV_LENGTH, HEADER),
    aad: aadFor(context),
  });
  return parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
}

/** HMAC-SHA256 closure under a derived key, for name indexes and receipt digests. */
function hmacWith(key, adapter) {
  return (bytes) => {
    const out = adapter.hmacSha256(key, bytes);
    if (!out || out.length !== 32) throw new Error('HMAC adapter must return 32 bytes');
    return new Uint8Array(out);
  };
}

module.exports = { VERSION, sealRecord, openRecord, assertBindsAad, hmacWith };
