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
export const RESPONSE_BINDING_CAPABILITY: "responseBinding";
export const RESPONSE_BINDING_VERSION: 1;
export const RESPONSE_BINDING_HEADER: "x-papersafe-bind";
/** The AAD, as text (UTF-8 on the wire). `requestTarget` is path + query, as signed. */
export function responseBindingAad(method: any, requestTarget: any, nonce: any): string;
