/**
 * This package is published on its own, so it must stand on its own: nothing
 * in it may reach into the private app, and only src/node/ may touch Node's
 * built-ins (everything else is copied to the phone, which has none).
 */
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ALLOWED_PACKAGES = new Set(['argon2', 'vitest']);
/**
 * Dev dependencies only tests may import. fflate is the phone's gzip library:
 * the adapter is handed it, never imports it, and its tests run against the
 * real one.
 */
const TEST_ONLY_PACKAGES = new Set(['fflate']);
const TEST_DIR = path.join(ROOT, 'test') + path.sep;

function filesUnder(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === 'node_modules' ? [] : filesUnder(full);
    return /\.(c|m)?js$/.test(entry.name) ? [full] : [];
  });
}

function specifiers(file) {
  const text = fs.readFileSync(file, 'utf8');
  return [...text.matchAll(/(?:require\(|from\s+|import\()\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
}

const files = ['src', 'bin', 'scripts', 'test'].flatMap((dir) => filesUnder(path.join(ROOT, dir)));

describe('package boundary', () => {
  it('never imports from outside the package', () => {
    for (const file of files) {
      for (const spec of specifiers(file)) {
        if (!spec.startsWith('.')) continue;
        const target = path.resolve(path.dirname(file), spec);
        expect(target.startsWith(ROOT + path.sep), `${path.relative(ROOT, file)} imports ${spec}`).toBe(true);
      }
    }
  });

  it('depends on no package except the optional argon2', () => {
    for (const file of files) {
      for (const spec of specifiers(file)) {
        if (spec.startsWith('.') || spec.startsWith('node:')) continue;
        const name = spec.split('/')[0];
        const allowed = ALLOWED_PACKAGES.has(name) || (file.startsWith(TEST_DIR) && TEST_ONLY_PACKAGES.has(name));
        expect(allowed, `${path.relative(ROOT, file)} imports ${spec}`).toBe(true);
      }
    }
  });

  it('keeps Node built-ins in src/node/ (the rest also runs on the phone)', () => {
    for (const file of filesUnder(path.join(ROOT, 'src'))) {
      if (file.startsWith(path.join(ROOT, 'src', 'node') + path.sep)) continue;
      const builtins = specifiers(file).filter((spec) => spec.startsWith('node:') || spec === 'crypto' || spec === 'fs');
      expect(builtins, path.relative(ROOT, file)).toEqual([]);
    }
  });
});
