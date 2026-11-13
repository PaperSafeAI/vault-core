#!/usr/bin/env node
'use strict';

/**
 * Generates types/ (TypeScript declarations) from the JSDoc in src/.
 *
 *   node scripts/build-types.js           write types/
 *   node scripts/build-types.js --check   fail if types/ is out of date
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const TYPES = path.join(ROOT, 'types');

function tscBin() {
  try {
    return require.resolve('typescript/bin/tsc', { paths: [ROOT] });
  } catch {
    throw new Error('Building the declarations needs the "typescript" dev dependency (npm install).');
  }
}

function generate(outDir) {
  fs.rmSync(outDir, { recursive: true, force: true });
  execFileSync(process.execPath, [tscBin(), '-p', path.join(ROOT, 'tsconfig.types.json'), '--declarationDir', outDir], { stdio: 'inherit' });
}

function listFiles(dir, prefix = '') {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    return entry.isDirectory() ? listFiles(path.join(dir, entry.name), rel) : [rel];
  }).sort();
}

if (process.argv.includes('--check')) {
  // The reserved directory is kept (private, mode 0700) for the whole check and
  // everything goes beneath it: deleting and re-creating it would let another
  // local user claim the name in between.
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-core-types-'));
  const tmp = path.join(parent, 'types');
  try {
    generate(tmp);
    // A consumer without skipLibCheck compiles these declarations too, so they
    // must be valid TypeScript on their own, not only what tsc happened to emit.
    const strict = path.join(parent, 'tsconfig.strict.json');
    fs.writeFileSync(strict, JSON.stringify({
      compilerOptions: {
        noEmit: true, strict: true, skipLibCheck: false, module: 'nodenext', moduleResolution: 'nodenext',
        target: 'es2022', lib: ['es2022', 'dom'], types: ['node'], typeRoots: [path.dirname(path.dirname(require.resolve('@types/node/package.json', { paths: [ROOT] })))]
      },
      include: ['types/**/*.d.ts', 'types/**/*.d.mts']
    }));
    try {
      execFileSync(process.execPath, [tscBin(), '-p', strict], { stdio: 'inherit' });
    } catch {
      throw new Error('types/ does not compile with skipLibCheck off: add JSDoc types for the parameters above.');
    }
    const want = listFiles(tmp);
    const have = listFiles(TYPES);
    const stale = want.length !== have.length || want.some((file, i) => (
      file !== have[i] || fs.readFileSync(path.join(tmp, file), 'utf8') !== fs.readFileSync(path.join(TYPES, file), 'utf8')
    ));
    if (stale) throw new Error('types/ is out of date: run `npm run types` and commit it.');
    console.log('types up to date');
  } catch (error) {
    // Reported here, after `finally` has removed the temporary directory.
    console.error(error.message);
    process.exitCode = 1;
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
} else {
  generate(TYPES);
  console.log('wrote types/');
}
