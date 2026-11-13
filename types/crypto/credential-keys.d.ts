export const REUSE_DIGEST_LABEL: "papersafeai:credentials:reuse-digest";
export const NOTE_INDEX_LABEL: "papersafeai:credentials:note-index";
export const NOTE_DIGEST_LENGTH: 12;
/** The key that seals the open half of every credential. */
export function deriveOpenPayloadKey(vaultKey: any, adapter: any): Uint8Array<any>;
/** The key behind password-reuse digests. */
export function deriveReuseDigestKey(openKey: any, adapter: any): Uint8Array<any>;
/** Digest that is equal for equal passwords within one vault, and nothing more. */
export function passwordReuseDigest(openKey: any, password: any, adapter: any): string;
/** The key behind secure-note search digests. */
export function deriveNoteIndexKey(openKey: any, adapter: any): Uint8Array<any>;
/** Search digest of one word of a secure note (case-insensitive). */
export function noteTokenDigest(noteIndexKey: any, token: any, adapter: any): string;
