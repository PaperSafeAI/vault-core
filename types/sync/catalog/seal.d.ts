export const VERSION: 1;
/** Seal a JSON-compatible value. Returns the envelope bytes for a BLOB column. */
export function sealRecord(context: any, value: any, payloadKey: any, adapter: any): Uint8Array<any>;
/** Open a sealed value for the same context. Throws on any mismatch. */
export function openRecord(context: any, envelope: any, payloadKey: any, adapter: any): any;
import { assertBindsAad } from "../../crypto/aad";
/** HMAC-SHA256 closure under a derived key, for name indexes and receipt digests. */
export function hmacWith(key: any, adapter: any): (bytes: any) => Uint8Array<any>;
export { assertBindsAad };
