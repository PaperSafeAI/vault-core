'use strict';

/**
 * Binding an encrypted LAN answer to the request it answers. Opt-in.
 *
 * Every answer is AES-GCM under the pairing's transport key, which never
 * changes, and nothing in it named the request. So anyone on the LAN could
 * record an answer and play it to the phone later — an old delta, an old
 * "accepted" for a push still queued — and it decrypted.
 *
 * A desktop that can bind advertises `capabilities.responseBinding: 1` in its
 * handshake. A phone that has seen that sends `x-papersafe-bind: 1`, and the
 * desktop then seals that request's answer with this AAD: the method and
 * target the request's HMAC covers, and the HMAC nonce, which the desktop
 * accepts once. An answer recorded for another request fails its tag. With no
 * header nothing changes, byte for byte, so phones that predate this are
 * untouched. A capability the desktop advertises, not a protocol number.
 */
const RESPONSE_BINDING_CAPABILITY = 'responseBinding';
const RESPONSE_BINDING_VERSION = 1;
// Lower case: Node hands the desktop its request headers lower-cased.
const RESPONSE_BINDING_HEADER = 'x-papersafe-bind';

/** The AAD, as text (UTF-8 on the wire). `requestTarget` is path + query, as signed. */
function responseBindingAad(method, requestTarget, nonce) {
  return `psai-resp-v1\n${String(method).toUpperCase()}\n${requestTarget}\n${nonce}`;
}

module.exports = {
  RESPONSE_BINDING_CAPABILITY,
  RESPONSE_BINDING_VERSION,
  RESPONSE_BINDING_HEADER,
  responseBindingAad,
};
