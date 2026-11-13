/**
 * The "no lock-in" promise, tested: a backup the app's own code sealed is
 * opened by the standalone CLI, offline, with only the passphrase.
 */
import './setup.mjs'; // example record types (scripts/example-record-types.js)
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { nodeAdapter as adapter } from '../src/node/index.js';
import { assembleBundle, sealBundle, DATABASE_CIPHERS } from '../src/backup/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(here, '..', 'bin', 'papersafe-open-backup.js');
const PASSPHRASE = 'correct horse battery staple';

async function writeArchive(dir, files) {
  const bundle = assembleBundle({
    files: files.map(([relativePath, text]) => ({ relativePath, bytes: Buffer.from(text) })),
    dbKeyHex: 'b'.repeat(64),
    databaseCipher: DATABASE_CIPHERS.SQLCIPHER,
    createdAt: '2026-10-01T00:00:00.000Z'
  }, adapter);
  const archive = path.join(dir, 'vault.backup');
  fs.writeFileSync(archive, JSON.stringify(await sealBundle(bundle, PASSPHRASE, adapter)));
  return archive;
}

function run(args, passphrase) {
  return execFileSync(process.execPath, [CLI, ...args], {
    env: { ...process.env, PAPERSAFE_BACKUP_PASSPHRASE: passphrase },
    stdio: 'pipe'
  }).toString();
}

describe('papersafe-open-backup', () => {
  it('refuses Windows extraction before reading the backup or creating output', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-core-win-refusal-'));
    try {
      const out = path.join(dir, 'out');
      const archive = path.join(dir, 'missing.backup');
      const result = spawnSync(process.execPath, ['-e', `
        Object.defineProperty(process, 'platform', { value: 'win32' });
        process.argv = [process.execPath, ${JSON.stringify(CLI)}, ${JSON.stringify(archive)}, ${JSON.stringify(out)}];
        require(${JSON.stringify(CLI)});
      `], { encoding: 'utf8', env: { ...process.env, PAPERSAFE_BACKUP_PASSPHRASE: '' } });
      expect(result.status).not.toBe(0);
      expect(result.stderr).toMatch(/Windows extraction is not supported.*owner-only/i);
      expect(fs.existsSync(out)).toBe(false);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('writes every file of a backup sealed by the app code, byte for byte', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-core-cli-'));
    const archive = await writeArchive(dir, [['data/vault.db', 'SQLite format 3\0 db'], ['documents/a.enc', 'blob-a']]);
    const out = path.join(dir, 'out');

    const stdout = run([archive, out], PASSPHRASE);

    expect(fs.readFileSync(path.join(out, 'data/vault.db'), 'utf8')).toBe('SQLite format 3\0 db');
    expect(fs.readFileSync(path.join(out, 'documents/a.enc'), 'utf8')).toBe('blob-a');
    expect(stdout).toContain('files written: 2');
    expect(stdout).not.toContain('b'.repeat(64));
    expect(run([archive, path.join(dir, 'out2'), '--show-db-key'], PASSPHRASE)).toContain('b'.repeat(64));
  });

  it('writes only files the manifest lists and checks, and reports any other', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-core-cli-'));
    const bundle = assembleBundle({
      files: [{ relativePath: 'documents/a.enc', bytes: Buffer.from('blob-a') }],
      createdAt: '2026-10-01T00:00:00.000Z'
    }, adapter);
    // Present in the archive, in no manifest: nothing vouches for it.
    bundle.files.push({ relativePath: 'documents/planted.enc', contentBase64: Buffer.from('planted').toString('base64') });
    const archive = path.join(dir, 'vault.backup');
    fs.writeFileSync(archive, JSON.stringify(await sealBundle(bundle, PASSPHRASE, adapter)));
    const out = path.join(dir, 'out');

    const stdout = run([archive, out], PASSPHRASE);

    expect(fs.readFileSync(path.join(out, 'documents/a.enc'), 'utf8')).toBe('blob-a');
    expect(fs.existsSync(path.join(out, 'documents/planted.enc'))).toBe(false);
    expect(stdout).toContain('files written: 1');
    expect(stdout).toContain('skipped (not in the manifest, so not checked): documents/planted.enc');
  });

  it('writes only into a new, owner-only directory', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-core-cli-'));
    const archive = await writeArchive(dir, [['documents/a.enc', 'blob-a']]);

    // An existing directory, even an empty one, is refused before anything is read.
    const existing = path.join(dir, 'existing');
    fs.mkdirSync(existing);
    expect(() => run([archive, existing], PASSPHRASE)).toThrow(/already exists/);
    expect(fs.readdirSync(existing)).toEqual([]);

    const out = path.join(dir, 'out');
    run([archive, out], PASSPHRASE);
    if (process.platform !== 'win32') {
      expect(fs.statSync(out).mode & 0o777).toBe(0o700);
      expect(fs.statSync(path.join(out, 'documents')).mode & 0o777).toBe(0o700);
      expect(fs.statSync(path.join(out, 'documents/a.enc')).mode & 0o777).toBe(0o600);
    }
  });

  it('refuses a wrong passphrase and writes nothing', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-core-cli-'));
    const archive = await writeArchive(dir, [['documents/a.enc', 'blob-a']]);
    const out = path.join(dir, 'out');
    expect(() => run([archive, out], 'wrong passphrase entirely')).toThrow(/incorrect|corrupted/);
    expect(fs.existsSync(out)).toBe(false);
  });
});
