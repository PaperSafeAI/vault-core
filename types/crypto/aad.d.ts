/**
 * Refuse an AES-GCM adapter that does not bind AAD. AAD is only a protection if
 * the platform's AES-GCM actually feeds it to the tag; an adapter that drops the
 * `aad` argument would seal everything unbound and nothing would notice. Checked
 * once per adapter object, before its first use: a value sealed under one AAD
 * must fail to open under another.
 *
 * Adapter: randomBytes(n), aesGcmSeal({plaintext, key, iv, aad}) -> {ciphertext, tag},
 * aesGcmOpen({ciphertext, key, iv, tag, aad}) -> plaintext (throws on failure).
 */
export function assertBindsAad(adapter: any): void;
export const COMPONENT_CATALOGUE: "catalogue-v1";
export const COMPONENT_VAULT: "vault-v3";
/**
 * The AAD bytes for one sealed value. Throws on anything the registry does not
 * describe exactly.
 *
 * @param {{ component: string, vaultId: string, recordType: string, primaryKey: string[], part?: string | null, generation?: string | null }} context
 * @returns {Uint8Array}
 */
export function buildAad({ component, vaultId, recordType, primaryKey, part, generation }?: {
    component: string;
    vaultId: string;
    recordType: string;
    primaryKey: string[];
    part?: string | null;
    generation?: string | null;
}): Uint8Array;
/**
 * Register record types for a component: `{ name: { generation?: boolean,
 * parts?: string[] } }`. Registering the same rule again is a no-op (an app may
 * load its registration from more than one place); registering a name with a
 * different rule throws, so a name can never change meaning.
 *
 * @param {string} component
 * @param {Record<string, { generation?: boolean, parts?: string[] | null }>} types
 */
export function registerRecordTypes(component: string, types: Record<string, {
    generation?: boolean;
    parts?: string[] | null;
}>): void;
/**
 * A snapshot of the registry, `{ component: { recordType: rule } }`.
 *
 * @returns {Record<string, Record<string, { generation: boolean, parts: readonly string[] | null }>>}
 */
export function registeredRecordTypes(): Record<string, Record<string, {
    generation: boolean;
    parts: readonly string[] | null;
}>>;
/** Whether a registered record type of `component` is bound to a generation. */
export function isGenerationBound(component: any, recordType: any): boolean;
