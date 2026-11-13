#!/usr/bin/env node
/**
 * Release this package: set the version, check, commit, tag, push.
 *
 *   npm run release -- <version> [--dry-run]
 *
 * Pushing the tag `v<version>` runs .github/workflows/release.yml, which runs
 * every check again, scans the history for secrets and publishes to npm with
 * provenance.
 *
 * Refuses unless: on `main`, the tree is clean, the version is valid semver and
 * not lower than the current one, its tag does not exist, and CHANGELOG.md has
 * a `## <version>` section (release notes are written by a person). The version
 * is written to package.json, package-lock.json and src/version.js (the version
 * the apps show), types/ is regenerated, then lint, tests, vector and type
 * checks run before anything is committed. `--dry-run` stops before the commit
 * and puts the files back.
 *
 * Apps that include this repository as a submodule then move their pointer to
 * the new commit (PaperSafeAI: see its docs/security/VAULT_CORE_OPEN_SOURCE.md).
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FILES = {
  pkg: path.join(ROOT, 'package.json'),
  lock: path.join(ROOT, 'package-lock.json'),
  version: path.join(ROOT, 'src/version.js'),
  changelog: path.join(ROOT, 'CHANGELOG.md'),
};

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const version = args.find((a) => !a.startsWith('--'));

function fail(message) {
  console.error(`release: ${message}`);
  process.exit(1);
}
function run(cmd, cmdArgs) {
  return execFileSync(cmd, cmdArgs, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }).trim();
}
function step(cmd, cmdArgs) {
  console.log(`release: ${cmd} ${cmdArgs.join(' ')}`);
  execFileSync(cmd, cmdArgs, { cwd: ROOT, stdio: 'inherit' });
}

const SEMVER = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/;
if (!version || !SEMVER.test(version)) fail('usage: npm run release -- <version> [--dry-run], e.g. 1.0.1');

function compare(a, b) {
  const [, ...x] = SEMVER.exec(a);
  const [, ...y] = SEMVER.exec(b);
  for (let i = 0; i < 3; i += 1) if (Number(x[i]) !== Number(y[i])) return Number(x[i]) - Number(y[i]);
  if (x[3] === y[3]) return 0;
  if (!x[3]) return 1; // a release is above its pre-releases
  if (!y[3]) return -1;
  return x[3] < y[3] ? -1 : 1;
}

const branch = run('git', ['rev-parse', '--abbrev-ref', 'HEAD']);
if (branch !== 'main') fail(`releases are cut from main (on ${branch}).`);
if (run('git', ['status', '--porcelain'])) fail('the working tree has changes; commit or stash them first.');

const tag = `v${version}`;
if (run('git', ['tag', '--list', tag])) fail(`${tag} already exists locally.`);
if (run('git', ['ls-remote', '--tags', 'origin', `refs/tags/${tag}`])) fail(`${tag} already exists on origin.`);

const pkg = JSON.parse(fs.readFileSync(FILES.pkg, 'utf8'));
if (compare(version, pkg.version) < 0) fail(`${version} is lower than the current ${pkg.version}.`);

const changelog = fs.readFileSync(FILES.changelog, 'utf8');
if (!new RegExp(`^## ${version.replace(/\./g, '\\.')}\\s*$`, 'm').test(changelog)) {
  fail(`CHANGELOG.md has no "## ${version}" section; write the release notes first.`);
}

// The tree was clean, so putting everything back is a checkout.
function restore() {
  run('git', ['checkout', '--', '.']);
}

try {
  if (version !== pkg.version) {
    const before = pkg.version;
    pkg.version = version;
    fs.writeFileSync(FILES.pkg, `${JSON.stringify(pkg, null, 2)}\n`);
    const lock = JSON.parse(fs.readFileSync(FILES.lock, 'utf8'));
    lock.version = version;
    if (lock.packages && lock.packages['']) lock.packages[''].version = version;
    fs.writeFileSync(FILES.lock, `${JSON.stringify(lock, null, 2)}\n`);
    const source = fs.readFileSync(FILES.version, 'utf8');
    const updated = source.replace(/const VERSION = '[^']*';/, `const VERSION = '${version}';`);
    if (updated === source) fail('src/version.js has no VERSION line to update.');
    fs.writeFileSync(FILES.version, updated);
    console.log(`release: version ${before} -> ${version}`);
    // The declarations carry the version string too.
    step('npm', ['run', 'types']);
  } else {
    console.log(`release: version already ${version} (first release of it)`);
  }

  step('npm', ['ci', '--no-audit', '--no-fund']);
  step('npm', ['run', 'lint']);
  step('npm', ['test']);
  step('npm', ['run', 'vectors:check']);
  step('npm', ['run', 'types:check']);
} catch (error) {
  restore();
  fail(`checks failed, files put back (${error.message.split('\n')[0]}).`);
}

if (dryRun) {
  restore();
  console.log(`release: dry run passed; would commit, tag ${tag} and push. Files put back.`);
  process.exit(0);
}

if (run('git', ['status', '--porcelain'])) {
  step('git', ['add', '-A']);
  step('git', ['commit', '-s', '-m', `v${version}`]);
}
step('git', ['tag', '-a', tag, '-m', `@papersafeailabs/vault-core v${version}`]);
step('git', ['push', 'origin', 'main', tag]);
console.log(`release: pushed ${tag}. The Release workflow publishes it; watch it in Actions.`);
