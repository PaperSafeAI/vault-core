'use strict';

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

const MAX_DEPTH = 128;

class CanonicalJsonError extends Error {
  constructor(message, position) {
    super(position === undefined ? message : `${message} at ${position}`);
    this.name = 'CanonicalJsonError';
  }
}

function hasLoneSurrogate(s) {
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i += 1;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/** Own-property assignment that is safe for keys such as "__proto__". */
function define(obj, key, value) {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

/**
 * Parse text under the catalogue's strict JSON rules.
 * Throws CanonicalJsonError on duplicate keys, lone surrogates, non-integer or
 * unsafe numbers, -0, excessive nesting or trailing content.
 */
function parseStrict(text) {
  if (typeof text !== 'string') throw new CanonicalJsonError('input is not a string');
  let i = 0;

  const fail = (message) => { throw new CanonicalJsonError(message, i); };
  const skipWhitespace = () => {
    while (i < text.length) {
      const c = text[i];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') i += 1;
      else break;
    }
  };

  const parseString = () => {
    i += 1; // opening quote
    let out = '';
    while (true) {
      if (i >= text.length) fail('unterminated string');
      const c = text[i];
      if (c === '"') { i += 1; break; }
      if (c === '\\') {
        const e = text[i + 1];
        i += 2;
        if (e === '"') out += '"';
        else if (e === '\\') out += '\\';
        else if (e === '/') out += '/';
        else if (e === 'b') out += '\b';
        else if (e === 'f') out += '\f';
        else if (e === 'n') out += '\n';
        else if (e === 'r') out += '\r';
        else if (e === 't') out += '\t';
        else if (e === 'u') {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('invalid unicode escape');
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else {
          fail('invalid escape');
        }
        continue;
      }
      if (c.charCodeAt(0) < 0x20) fail('unescaped control character');
      out += c;
      i += 1;
    }
    if (hasLoneSurrogate(out)) fail('lone surrogate');
    return out;
  };

  const parseNumber = () => {
    const match = /^-?(0|[1-9][0-9]*)([.eE])?/.exec(text.slice(i, i + 32));
    if (!match) fail('invalid number');
    if (match[2]) fail('non-integer number');
    const literal = match[0];
    if (literal === '-0') fail('negative zero');
    const n = Number(literal);
    if (!Number.isSafeInteger(n)) fail('unsafe integer');
    i += literal.length;
    return n;
  };

  const parseValue = (depth) => {
    if (depth > MAX_DEPTH) fail('nesting too deep');
    skipWhitespace();
    const c = text[i];
    if (c === '{') {
      i += 1;
      const obj = {};
      const seen = new Set();
      skipWhitespace();
      if (text[i] === '}') { i += 1; return obj; }
      while (true) {
        skipWhitespace();
        if (text[i] !== '"') fail('expected object key');
        const key = parseString();
        if (seen.has(key)) fail(`duplicate key "${key}"`);
        seen.add(key);
        skipWhitespace();
        if (text[i] !== ':') fail('expected ":"');
        i += 1;
        define(obj, key, parseValue(depth + 1));
        skipWhitespace();
        if (text[i] === ',') { i += 1; continue; }
        if (text[i] === '}') { i += 1; return obj; }
        fail('expected "," or "}"');
      }
    }
    if (c === '[') {
      i += 1;
      const arr = [];
      skipWhitespace();
      if (text[i] === ']') { i += 1; return arr; }
      while (true) {
        arr.push(parseValue(depth + 1));
        skipWhitespace();
        if (text[i] === ',') { i += 1; continue; }
        if (text[i] === ']') { i += 1; return arr; }
        fail('expected "," or "]"');
      }
    }
    if (c === '"') return parseString();
    if (c === '-' || (c >= '0' && c <= '9')) return parseNumber();
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    return fail('unexpected token');
  };

  const value = parseValue(0);
  skipWhitespace();
  if (i !== text.length) fail('trailing content');
  return value;
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Canonical JSON v1 text for a value. Throws CanonicalJsonError for anything
 * the contract does not admit, rather than silently coercing it.
 */
function canonicalize(value) {
  const encode = (v, depth) => {
    if (depth > MAX_DEPTH) throw new CanonicalJsonError('nesting too deep');
    if (v === null) return 'null';
    if (v === true) return 'true';
    if (v === false) return 'false';
    if (typeof v === 'string') {
      if (hasLoneSurrogate(v)) throw new CanonicalJsonError('lone surrogate');
      return JSON.stringify(v);
    }
    if (typeof v === 'number') {
      if (!Number.isSafeInteger(v)) throw new CanonicalJsonError('non-integer or unsafe number');
      if (Object.is(v, -0)) throw new CanonicalJsonError('negative zero');
      return String(v);
    }
    if (Array.isArray(v)) return `[${v.map((item) => encode(item, depth + 1)).join(',')}]`;
    if (isPlainObject(v)) {
      const keys = Object.keys(v).sort();
      return `{${keys.map((k) => {
        if (hasLoneSurrogate(k)) throw new CanonicalJsonError('lone surrogate');
        return `${JSON.stringify(k)}:${encode(v[k], depth + 1)}`;
      }).join(',')}}`;
    }
    throw new CanonicalJsonError(`unsupported value of type ${typeof v}`);
  };
  return encode(value, 0);
}

/** UTF-8 bytes of a string. */
function utf8(text) {
  return new TextEncoder().encode(text);
}

/** Canonical JSON v1 bytes for a value. */
function canonicalBytes(value) {
  return utf8(canonicalize(value));
}

/** Byte length of a string once UTF-8 encoded. */
function utf8Length(text) {
  return utf8(text).length;
}

module.exports = {
  MAX_DEPTH, CanonicalJsonError, parseStrict, canonicalize, canonicalBytes, utf8, utf8Length,
  isPlainObject, hasLoneSurrogate,
};
