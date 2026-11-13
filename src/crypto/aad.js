'use strict';

/**
 * The ONE way this app builds AES-GCM associated data (AAD) for anything sealed
 * under a key derived from the vault key. Both apps, desktop and phone, run
 * this same file.
 *
 * AAD names WHERE a ciphertext belongs. A sealed value copied to another row,
 * another half of a row, another record type or another vault then fails its
 * tag check instead of being read as that place's data.
 *
 * ## The bytes
 *
 * Canonical JSON (../sync/catalog/canonical-json.js: sorted keys, no
 * whitespace, strict string escaping) of
 *
 *   { component, vaultId, recordType, primaryKey, part?, generation? }
 *
 *   component   the scheme and its version, from the closed list below
 *               ('catalogue-v1', 'vault-v3'). A new scheme is a new component.
 *   vaultId     the vault's identity: random, made once per vault
 *   recordType  what kind of record, registered for the component (the
 *               package's own, or the app's via registerRecordTypes)
 *   primaryKey  the record's key, a non-empty array of non-empty strings
 *   part        which part of a record, where a record has several (a
 *               credential's `open` and `secret` halves); forbidden otherwise
 *   generation  the catalogue history generation, for the record types that
 *               are bound to one; forbidden otherwise
 *
 * These are exactly the AAD fields catalogue sync already sealed with, so every
 * catalogue record keeps its bytes: the catalogue's `component:
 * 'catalogue-v1'` IS its scheme version, and a separate `v` field would have
 * forced re-sealing commands the phone has already sent, which it keeps
 * immutable. The vault cipher (cipher suite 3) is the same scheme under
 * component 'vault-v3'.
 *
 * ## Why this is unambiguous (domain separation)
 *
 * Canonical JSON is injective: two different objects never encode to the same
 * bytes (strings are quoted and escaped, keys are sorted, arrays keep their
 * length and order). An optional field is either present or absent, never
 * empty. So two AADs are equal only when every field is equal — no choice of
 * ids can make a credential's open half look like its secret half, a wrapped
 * document key look like a credential, or a catalogue record look like either.
 * test/aad.test.js enumerates every registered (component,
 * recordType, part) and checks this.
 *
 * Validation is strict and throws: an unknown component, record type or part, a
 * missing vaultId, an empty key, or a generation where none belongs is a
 * programming error, and sealing under a guessed context would be worse than
 * not sealing.
 */

const { canonicalize, utf8 } = require('../sync/catalog/canonical-json');

const COMPONENT_CATALOGUE = 'catalogue-v1';
const COMPONENT_VAULT = 'vault-v3';

/**
 * The registry: for each component, each record type says whether it takes a
 * generation and which parts (if any) it has. The package registers only the
 * types its own modules seal (credentials and document keys); an app registers
 * the rest (its catalogue records, its encrypted columns) with
 * registerRecordTypes before it seals them. Add to it; never repurpose a name.
 */
// One registry per process, kept on a global symbol: a bundler or test runner
// may load this file more than once, and a type registered through one copy
// must be known to every other.
const REGISTRY_KEY = Symbol.for('@papersafeailabs/vault-core/aad-registry');
const REGISTRY = globalThis[REGISTRY_KEY] || (globalThis[REGISTRY_KEY] = {
  [COMPONENT_CATALOGUE]: Object.create(null),
  [COMPONENT_VAULT]: Object.create(null),
});

const RECORD_TYPE_NAME = /^[a-z][a-z0-9_]*$/;

function sameRule(a, b) {
  return a.generation === b.generation
    && JSON.stringify(a.parts) === JSON.stringify(b.parts);
}

/**
 * Register record types for a component: `{ name: { generation?: boolean,
 * parts?: string[] } }`. Registering the same rule again is a no-op (an app may
 * load its registration from more than one place); registering a name with a
 * different rule throws, so a name can never change meaning.
 *
 * @param {string} component
 * @param {Record<string, { generation?: boolean, parts?: string[] | null }>} types
 */
function registerRecordTypes(component, types) {
  const registry = Object.prototype.hasOwnProperty.call(REGISTRY, component) ? REGISTRY[component] : null;
  if (!registry) throw new TypeError(`unknown AAD component "${component}"`);
  for (const [name, spec] of Object.entries(types || {})) {
    if (!RECORD_TYPE_NAME.test(name)) throw new TypeError(`bad record type name "${name}"`);
    const parts = spec && spec.parts ? [...spec.parts] : null;
    if (parts && (parts.length === 0 || !parts.every((p) => RECORD_TYPE_NAME.test(p)) || new Set(parts).size !== parts.length)) {
      throw new TypeError(`bad parts for record type "${name}"`);
    }
    const rule = Object.freeze({ generation: Boolean(spec && spec.generation), parts: parts && Object.freeze(parts) });
    const existing = registry[name];
    if (existing) {
      if (!sameRule(existing, rule)) throw new TypeError(`record type "${name}" is already registered with another rule`);
      continue;
    }
    registry[name] = rule;
  }
}

/**
 * A snapshot of the registry, `{ component: { recordType: rule } }`.
 *
 * @returns {Record<string, Record<string, { generation: boolean, parts: readonly string[] | null }>>}
 */
function registeredRecordTypes() {
  return Object.fromEntries(Object.entries(REGISTRY).map(([c, types]) => [c, { ...types }]));
}

/** Whether a registered record type of `component` is bound to a generation. */
function isGenerationBound(component, recordType) {
  const types = Object.prototype.hasOwnProperty.call(REGISTRY, component) ? REGISTRY[component] : null;
  const rule = types && Object.prototype.hasOwnProperty.call(types, recordType) ? types[recordType] : null;
  return Boolean(rule && rule.generation);
}

registerRecordTypes(COMPONENT_VAULT, {
  // A credential's `open` and `secret` halves (./vault-cipher.js).
  credential: { parts: ['open', 'secret'] },
  // A wrapped per-document key, bound to the DOCUMENT id (./document-key.js).
  document_key: {},
});


function nonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

/**
 * The AAD bytes for one sealed value. Throws on anything the registry does not
 * describe exactly.
 *
 * @param {{ component: string, vaultId: string, recordType: string, primaryKey: string[], part?: string | null, generation?: string | null }} context
 * @returns {Uint8Array}
 */
function buildAad({ component, vaultId, recordType, primaryKey, part, generation } = {}) {
  const types = Object.prototype.hasOwnProperty.call(REGISTRY, component) ? REGISTRY[component] : null;
  if (!types) throw new TypeError(`unknown AAD component "${component}"`);
  if (!nonEmptyString(vaultId)) throw new TypeError('seal needs a vaultId');
  const rule = typeof recordType === 'string' && Object.prototype.hasOwnProperty.call(types, recordType) ? types[recordType] : null;
  if (!rule) {
    throw new TypeError(component === COMPONENT_CATALOGUE
      ? `unknown catalogue record type "${recordType}"`
      : `unknown ${component} record type "${recordType}"`);
  }
  if (!Array.isArray(primaryKey) || primaryKey.length === 0) throw new TypeError('seal needs a primaryKey array');
  if (!primaryKey.every(nonEmptyString)) throw new TypeError('every primaryKey element must be a non-empty string');

  const aad = { component, vaultId, recordType, primaryKey: [...primaryKey] };
  if (rule.parts) {
    if (!rule.parts.includes(part)) throw new TypeError(`${recordType} needs a part (${rule.parts.join(' | ')}), got "${part}"`);
    aad.part = part;
  } else if (part !== undefined && part !== null) {
    throw new TypeError(`${recordType} records have no parts`);
  }
  if (rule.generation) {
    if (!nonEmptyString(generation)) throw new TypeError(`${recordType} records are bound to a generation`);
    aad.generation = generation;
  }
  // A generation passed for a live record is ignored rather than refused: the
  // catalogue's callers pass one uniformly, and live projections are defined to
  // be generation-free (a history reset must not change their identity).
  return utf8(canonicalize(aad));
}

const verifiedAdapters = new WeakSet();

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
function assertBindsAad(adapter) {
  if (verifiedAdapters.has(adapter)) return;
  const key = adapter.randomBytes(32);
  const iv = adapter.randomBytes(12);
  const { ciphertext, tag } = adapter.aesGcmSeal({ plaintext: utf8('aad-self-test'), key, iv, aad: utf8('a') });
  let opened = false;
  try {
    adapter.aesGcmOpen({ ciphertext, key, iv, tag, aad: utf8('b') });
    opened = true;
  } catch { /* expected: the wrong AAD must not open */ }
  if (opened) throw new Error('sealing refused: this AES-GCM adapter ignores associated data');
  verifiedAdapters.add(adapter);
}

module.exports = {
  assertBindsAad,
  COMPONENT_CATALOGUE,
  COMPONENT_VAULT,
  buildAad,
  registerRecordTypes,
  registeredRecordTypes,
  isGenerationBound,
};
