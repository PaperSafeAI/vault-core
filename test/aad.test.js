/**
 * The one AAD builder: exact bytes, strict validation, and the domain
 * separation guarantee — no two different places can ever produce equal AAD.
 */
import './setup.mjs'; // example record types (scripts/example-record-types.js)
import { describe, it, expect } from 'vitest';
import { buildAad, registeredRecordTypes, registerRecordTypes, COMPONENT_CATALOGUE, COMPONENT_VAULT } from '../src/crypto/aad.js';
import { canonicalize } from '../src/sync/catalog/canonical-json.js';

const text = (bytes) => Buffer.from(bytes).toString('utf8');

/** Every (component, recordType, part, generation?) the registry admits, for one set of ids. */
function everyContext(vaultId, primaryKey, generation) {
  const out = [];
  for (const [component, types] of Object.entries(registeredRecordTypes())) {
    for (const [recordType, rule] of Object.entries(types)) {
      for (const part of rule.parts || [undefined]) {
        out.push({ component, vaultId, recordType, primaryKey, part, generation: rule.generation ? generation : undefined });
      }
    }
  }
  return out;
}

describe('the bytes', () => {
  it('are the canonical JSON of the context, generation included where bound', () => {
    const before = canonicalize({ component: 'catalogue-v1', vaultId: 'v', recordType: 'log_entry', primaryKey: ['1', '0'], generation: 'g' });
    expect(text(buildAad({ component: COMPONENT_CATALOGUE, vaultId: 'v', recordType: 'log_entry', primaryKey: ['1', '0'], generation: 'g' })))
      .toBe(before);
    expect(text(buildAad({ component: COMPONENT_CATALOGUE, vaultId: 'v', recordType: 'record', primaryKey: ['f', 'i'] })))
      .toBe('{"component":"catalogue-v1","primaryKey":["f","i"],"recordType":"record","vaultId":"v"}');
  });

  it('pins the vault-v3 forms', () => {
    expect(text(buildAad({ component: COMPONENT_VAULT, vaultId: 'v', recordType: 'credential', primaryKey: ['i'], part: 'secret' })))
      .toBe('{"component":"vault-v3","part":"secret","primaryKey":["i"],"recordType":"credential","vaultId":"v"}');
    expect(text(buildAad({ component: COMPONENT_VAULT, vaultId: 'v', recordType: 'document_key', primaryKey: ['d'] })))
      .toBe('{"component":"vault-v3","primaryKey":["d"],"recordType":"document_key","vaultId":"v"}');
  });

  it('leaves a live catalogue record generation-free even when a generation is passed', () => {
    expect(text(buildAad({ component: COMPONENT_CATALOGUE, vaultId: 'v', recordType: 'record', primaryKey: ['f'], generation: 'g' })))
      .not.toContain('generation');
  });
});

describe('registration', () => {
  it('admits a type once, accepts the same rule again, and refuses a changed rule', () => {
    registerRecordTypes(COMPONENT_VAULT, { reg_test: {} });
    expect(() => registerRecordTypes(COMPONENT_VAULT, { reg_test: {} })).not.toThrow();
    expect(() => registerRecordTypes(COMPONENT_VAULT, { reg_test: { generation: true } })).toThrow(/another rule/);
    expect(() => registerRecordTypes(COMPONENT_VAULT, { reg_test: { parts: ['a', 'b'] } })).toThrow(/another rule/);
  });

  it('refuses a credential redefined, bad names and bad parts', () => {
    expect(() => registerRecordTypes(COMPONENT_VAULT, { credential: {} })).toThrow(/another rule/);
    expect(() => registerRecordTypes('vault-v2', { x: {} })).toThrow(/unknown AAD component/);
    for (const name of ['', 'Upper', '1x', 'a-b', 'a b', '__proto__']) {
      expect(() => registerRecordTypes(COMPONENT_VAULT, { [name]: {} }), name).toThrow(/bad record type name/);
    }
    expect(() => registerRecordTypes(COMPONENT_VAULT, { p1: { parts: [] } })).toThrow(/bad parts/);
    expect(() => registerRecordTypes(COMPONENT_VAULT, { p2: { parts: ['a', 'a'] } })).toThrow(/bad parts/);
  });

  it('a snapshot cannot change the registry', () => {
    const snapshot = registeredRecordTypes();
    snapshot[COMPONENT_VAULT].injected = { generation: false, parts: null };
    expect(() => buildAad({ component: COMPONENT_VAULT, vaultId: 'v', recordType: 'injected', primaryKey: ['k'] })).toThrow(/unknown/);
  });
});

describe('validation fails closed', () => {
  const ok = { component: COMPONENT_VAULT, vaultId: 'v', recordType: 'credential', primaryKey: ['i'], part: 'open' };
  it.each([
    ['unknown component', { ...ok, component: 'vault-v2' }, /unknown AAD component/],
    ['inherited property as component', { ...ok, component: 'toString' }, /unknown AAD component/],
    ['missing vaultId', { ...ok, vaultId: '' }, /vaultId/],
    ['non-string vaultId', { ...ok, vaultId: 7 }, /vaultId/],
    ['unknown record type', { ...ok, recordType: 'record' }, /unknown vault-v3 record type/],
    ['inherited record type', { ...ok, recordType: 'constructor' }, /record type/],
    ['missing part', { ...ok, part: undefined }, /needs a part/],
    ['unknown part', { ...ok, part: 'both' }, /needs a part/],
    ['part where none belongs', { ...ok, recordType: 'document_key', part: 'open' }, /no parts/],
    ['empty key', { ...ok, primaryKey: [] }, /primaryKey/],
    ['empty key element', { ...ok, primaryKey: [''] }, /non-empty string/],
    ['numeric key element', { ...ok, primaryKey: [1] }, /non-empty string/],
    ['key not an array', { ...ok, primaryKey: 'i' }, /primaryKey/],
    ['generation-bound record without one', { component: COMPONENT_CATALOGUE, vaultId: 'v', recordType: 'log_entry', primaryKey: ['1'] }, /generation/],
  ])('%s', (_name, context, error) => {
    expect(() => buildAad(context)).toThrow(error);
  });
});

describe('domain separation: no two places share an AAD', () => {
  it('every registered (component, recordType, part) gives distinct bytes for the same ids', () => {
    const contexts = everyContext('vault-1', ['same-id'], 'gen-1');
    const seen = new Map();
    for (const context of contexts) {
      const key = text(buildAad(context));
      expect(seen.has(key), `${JSON.stringify(context)} collides with ${JSON.stringify(seen.get(key))}`).toBe(false);
      seen.set(key, context);
    }
    expect(seen.size).toBe(contexts.length);
    expect(seen.size).toBeGreaterThan(8);
  });

  it('ids that try to smuggle separators or JSON do not collide', () => {
    // Every hostile id shape against every other, across two vaults and two
    // generations, over every registered context.
    const ids = ['a', 'a|open', 'a","part":"open', 'a\\', 'a"', '["a"]', 'a b', 'a\u0000', 'é', 'é', 'cred:v2|a|open'];
    const keys = [...ids.map((i) => [i]), ['a', 'b'], ['a,b'], ['a', 'b', 'c'], ['a","b']];
    const seen = new Set();
    let count = 0;
    for (const vaultId of ['vault-1', 'vault-1|x']) {
      for (const generation of ['g1', 'g2']) {
        for (const primaryKey of keys) {
          for (const context of everyContext(vaultId, primaryKey, generation)) {
            if (!context.generation && generation === 'g2') continue; // same context as g1
            seen.add(text(buildAad(context)));
            count += 1;
          }
        }
      }
    }
    expect(seen.size).toBe(count);
  });

  it('no AAD equals a suite-2 string, so an old seal can never verify under the new scheme', () => {
    for (const context of everyContext('v', ['a'], 'g')) {
      const bytes = text(buildAad(context));
      expect(bytes.startsWith('{')).toBe(true);
      expect(bytes).not.toMatch(/^(cred|dek):v2\|/);
    }
  });
});
