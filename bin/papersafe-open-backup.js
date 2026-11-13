#!/usr/bin/env node
'use strict';

/**
 * Open a PaperSafeAI encrypted backup without the app.
 *
 *   papersafe-open-backup <backup-file> <output-dir> [--show-db-key]
 *
 * The passphrase is read from PAPERSAFE_BACKUP_PASSPHRASE or, if that is not
 * set, from the first line of standard input. Nothing is sent anywhere: this
 * runs entirely offline, with the same code the app uses (src/backup/).
 *
 * What comes out is the backup's files as the app stored them: the vault
 * database and the encrypted document blobs. On desktop the database is
 * SQLCipher; --show-db-key prints the key that opens it (keep it secret).
 */
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { readHidden } = require('./terminal-input');
const {
  parseEnvelope,
  openEnvelope,
  assertBundleIntact,
  normalizeRelativePath,
  databaseCipherOf
} = require('../src/backup');
const { nodeAdapter } = require('../src/node');

function usage(message) {
  if (message) console.error(`error: ${message}\n`);
  console.error('usage: papersafe-open-backup <backup-file> <output-dir> [--show-db-key]');
  console.error('       passphrase from PAPERSAFE_BACKUP_PASSPHRASE or the first line of stdin');
  process.exit(2);
}

async function readPassphrase() {
  if (process.env.PAPERSAFE_BACKUP_PASSPHRASE) return process.env.PAPERSAFE_BACKUP_PASSPHRASE;
  // On a terminal the passphrase is never shown; piped input is read as a line.
  if (process.stdin.isTTY) return readHidden('Backup passphrase: ');
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  for await (const line of rl) {
    rl.close();
    return line;
  }
  return '';
}

/** Resolve a bundle path under `root`, refusing anything that would escape it. */
function safeTarget(root, relativePath) {
  const clean = normalizeRelativePath(relativePath);
  const target = path.resolve(root, clean);
  if (target !== root && !target.startsWith(root + path.sep)) {
    throw new Error(`Backup entry escapes the output directory: ${relativePath}`);
  }
  return target;
}

async function main() {
  const args = process.argv.slice(2);
  const showDbKey = args.includes('--show-db-key');
  const [input, output] = args.filter((arg) => !arg.startsWith('--'));
  if (!input || !output) usage();
  // POSIX mode bits do not establish owner-only Windows ACLs. Refuse before
  // reading a backup or passphrase; never write plaintext under a false promise.
  if (process.platform === 'win32') {
    throw new Error('Windows extraction is not supported: owner-only ACL protection is not implemented. Use macOS or Linux with a private POSIX output directory.');
  }
  if (!fs.existsSync(input)) usage(`no such file: ${input}`);

  // The output directory must be new: it is created below, owner-only, and
  // nothing else can have put a link in it in the meantime.
  const root = path.resolve(output);
  if (fs.existsSync(root)) usage(`output directory already exists (give a new one): ${output}`);

  const envelope = parseEnvelope(fs.readFileSync(input, 'utf8'));
  const passphrase = await readPassphrase();
  const bundle = await openEnvelope(envelope, passphrase, nodeAdapter);
  // Every manifest file is checked against its size and SHA-256 hash before a
  // single byte is written, and only those files are written: a file the
  // manifest does not list was never checked, so it is reported and skipped.
  const { unlisted } = assertBundleIntact(bundle, nodeAdapter);
  const listed = new Set(bundle.manifest.files.map((entry) => normalizeRelativePath(entry.relativePath)));

  // Created here and only here (not recursive: an existing directory, or a link
  // planted at the name since the check above, is an error), mode 0700.
  fs.mkdirSync(root, { mode: 0o700 });
  let written = 0;
  const done = new Set();
  for (const file of bundle.files) {
    const relativePath = normalizeRelativePath(file.relativePath);
    if (!listed.has(relativePath) || done.has(relativePath)) continue;
    done.add(relativePath);
    const target = safeTarget(root, relativePath);
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    // 'wx': create, never overwrite, never follow a link at the name.
    fs.writeFileSync(target, nodeAdapter.fromBase64(file.contentBase64), { mode: 0o600, flag: 'wx' });
    written += 1;
  }

  console.log(`Opened backup created ${bundle.createdAt || '(unknown date)'}`);
  console.log(`  files written: ${written} → ${root}`);
  if (unlisted.length > 0) {
    console.log(`  skipped (not in the manifest, so not checked): ${unlisted.join(', ')}`);
  }
  console.log(`  database cipher: ${databaseCipherOf(bundle)}`);
  if (bundle.dbKeyHex) {
    console.log(showDbKey
      ? `  database key (SQLCipher, raw hex): ${bundle.dbKeyHex}`
      : '  database key: present (re-run with --show-db-key to print it)');
  }
}

main().catch((error) => {
  console.error(`error: ${error.message}`);
  process.exit(1);
});
