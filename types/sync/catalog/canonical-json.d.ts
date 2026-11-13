/**
 * Strict decoding and canonical encoding for catalogue sync (SPEC.md §7).
 *
 * Why not JSON.parse / JSON.stringify:
 *  - JSON.parse keeps the LAST of two duplicate keys. Two parsers that disagree
 *    about which duplicate wins read the same bytes as different commands, and a
 *    receipt digest computed over one would vouch for the other.
 *  - JSON.parse accepts 1.5, 1e3, -0 and lone surrogates. The contract admits
 *    none of them, and each has a platform-dependent round trip.
 *  - JSON.stringify keeps insertion order, so two devices that built the same
 *    object in a different order would hash different bytes.
 *
 * Canonical JSON v1: object keys sorted by UTF-16 code unit order (the default
 * JavaScript string sort), arrays in order, no whitespace, JSON string escaping
 * with no optional slash escaping, integers only, no -0.
 *
 * Nesting is bounded (MAX_DEPTH) so hostile input cannot exhaust the stack of a
 * recursive decoder.
 *
 * Pure and dependency-free: both platforms run this exact file.
 */
export const MAX_DEPTH: 128;
export class CanonicalJsonError extends Error {
    constructor(message: any, position: any);
}
/**
 * Parse text under the catalogue's strict JSON rules.
 * Throws CanonicalJsonError on duplicate keys, lone surrogates, non-integer or
 * unsafe numbers, -0, excessive nesting or trailing content.
 */
export function parseStrict(text: any): any;
/**
 * Canonical JSON v1 text for a value. Throws CanonicalJsonError for anything
 * the contract does not admit, rather than silently coercing it.
 */
export function canonicalize(value: any): any;
/** Canonical JSON v1 bytes for a value. */
export function canonicalBytes(value: any): Uint8Array<ArrayBuffer>;
/** UTF-8 bytes of a string. */
export function utf8(text: any): Uint8Array<ArrayBuffer>;
/** Byte length of a string once UTF-8 encoded. */
export function utf8Length(text: any): number;
export function isPlainObject(value: any): boolean;
export function hasLoneSurrogate(s: any): boolean;
