/**
 * Strict decoding and canonical encoding.
 *
 * Two devices must read the same bytes as the same command and encode the same
 * command as the same bytes, or a receipt digest vouches for something other
 * than what was executed. Each case below is a way the platform JSON functions
 * would let them disagree.
 */
import { describe, it, expect } from 'vitest';
import { parseStrict, canonicalize, utf8Length, MAX_DEPTH } from '../src/sync/catalog/canonical-json.js';

describe('parseStrict', () => {
  it('parses ordinary JSON', () => {
    expect(parseStrict(' {"a":[1,-2,true,false,null,"x\\n\\u00e9"]} ')).toEqual({ a: [1, -2, true, false, null, 'x\né'] });
  });

  it('refuses a duplicate key instead of letting the last one win', () => {
    expect(() => parseStrict('{"name":"Taxes","name":"Medical"}')).toThrow(/duplicate key/);
  });

  it.each([['1.5'], ['1e3'], ['1E3'], ['-0'], ['9007199254740992'], ['01'], ['+1'], ['NaN'], ['Infinity']])(
    'refuses the number %s', (text) => {
      expect(() => parseStrict(text)).toThrow();
    });

  it('refuses a lone surrogate, raw control characters and trailing content', () => {
    expect(() => parseStrict('"\\ud800"')).toThrow(/lone surrogate/);
    expect(() => parseStrict('"\\udc00x"')).toThrow(/lone surrogate/);
    expect(() => parseStrict('"a\u0001"')).toThrow(/control/);
    expect(() => parseStrict('{} {}')).toThrow(/trailing/);
    expect(parseStrict('"\\ud83d\\ude00"')).toBe('\u{1F600}');
  });

  it('keeps "__proto__" as data rather than changing the prototype', () => {
    const value = parseStrict('{"__proto__":{"polluted":true}}');
    expect(Object.getPrototypeOf(value)).toBe(Object.prototype);
    expect(Object.keys(value)).toEqual(['__proto__']);
    expect({}.polluted).toBeUndefined();
  });

  it('bounds nesting so hostile input cannot exhaust the stack', () => {
    expect(() => parseStrict('['.repeat(MAX_DEPTH + 2) + ']'.repeat(MAX_DEPTH + 2))).toThrow(/nesting/);
    expect(() => parseStrict('['.repeat(MAX_DEPTH) + ']'.repeat(MAX_DEPTH))).not.toThrow();
  });
});

describe('canonicalize', () => {
  it('sorts keys by UTF-16 code unit, keeps array order, adds no whitespace and does not escape "/"', () => {
    expect(canonicalize({ z: '/', 'é': 'é', a: '\u{1F600}', 'ÿ': 1, list: [3, 1, 2] }))
      .toBe('{"a":"\u{1F600}","list":[3,1,2],"z":"/","é":"é","ÿ":1}');
  });

  it('gives two insertion orders of the same object the same bytes', () => {
    expect(canonicalize({ b: 1, a: { d: 2, c: 3 } })).toBe(canonicalize({ a: { c: 3, d: 2 }, b: 1 }));
  });

  it.each([[1.5], [-0], [NaN], [Infinity], [2 ** 53], [undefined], [() => 1], [new Date(0)], ['\ud800']])(
    'refuses %s rather than coercing it', (value) => {
      expect(() => canonicalize({ v: value })).toThrow();
    });

  it('round-trips through parseStrict', () => {
    const text = canonicalize({ n: -42, s: 'tab\tquote"', nested: [{}, [], null] });
    expect(canonicalize(parseStrict(text))).toBe(text);
  });

  it('measures UTF-8 bytes, not UTF-16 units', () => {
    expect(utf8Length('é')).toBe(2);
    expect(utf8Length('\u{1F600}')).toBe(4);
  });
});
