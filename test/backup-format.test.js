/**
 * The shared backup format.
 *
 * This is the code with the longest failure delay in the product: a mistake
 * here does not surface when it is made, it surfaces years later when someone
 * reaches for the only copy of their documents. So the tests are written
 * against the properties that matter then, not the shape of the code now —
 * round trips, refusals, and the guarantee that an old archive still opens.
 *
 * They run against the REAL desktop adapter (Node crypto, real Argon2, real
 * gzip), because a mocked cipher proves nothing about a format whose whole job
 * is to be readable by a different program on a different machine.
 */
import './setup.mjs'; // example record types (scripts/example-record-types.js)
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { nodeAdapter as adapter } from '../src/node/index.js';
import {
  assembleBundle,
  verifyBundle,
  assertBundleIntact,
  normalizeRelativePath,
  MAX_EXPANDED_BACKUP_BYTES,
  sealBundle,
  parseEnvelope,
  openEnvelope,
  serializeBundle,
  deserializeBundle,
  ENVELOPE_FORMAT_V2,
  ENVELOPE_FORMAT_V3,
  CURRENT_ENVELOPE_VERSION,
  MAX_SUPPORTED_ENVELOPE_VERSION,
  DATABASE_CIPHERS,
  BACKUP_PLATFORMS,
  producerPlatformOf,
  canRestoreDatabaseOn,
  assertRestorableOn,
  observedDatabaseCipher,
  assertKdfCost,
  validateBackupPassphrase,
  MAX_ARCHIVE_VAULT_BYTES,
  assertVaultFitsArchive,
  readPassphraseHint
} from '../src/backup/index.js';

const PASSPHRASE = 'a-perfectly-adequate-backup-passphrase';

/** A complete vault: the auth record, the database, and two documents. */
function sampleFiles() {
  return [
    { relativePath: 'data/auth.json', bytes: Buffer.from('{"version":2}', 'utf8') },
    { relativePath: 'data/vault.db', bytes: Buffer.from('SQLite format 3\u0000...', 'utf8') },
    { relativePath: 'vault/doc-one.enc', bytes: crypto.randomBytes(2048) },
    { relativePath: 'vault/doc-two.enc', bytes: crypto.randomBytes(4096) }
  ];
}

function sampleBundle(overrides = {}) {
  return assembleBundle(
    {
      files: sampleFiles(),
      dbKeyHex: 'a'.repeat(64),
      databaseCipher: DATABASE_CIPHERS.SQLCIPHER,
      createdAt: '2026-08-22T12:00:00.000Z',
      ...overrides
    },
    adapter,
  );
}

describe('assembling a bundle', () => {
  it('carries every file, so a restore is a whole vault and not a metadata export', () => {
    const bundle = sampleBundle();

    expect(bundle.manifest.fileCount).toBe(4);
    expect(bundle.files.map((f) => f.relativePath).sort()).toEqual([
      'data/auth.json',
      'data/vault.db',
      'vault/doc-one.enc',
      'vault/doc-two.enc',
    ]);
    // The documents are the point. A backup without them restores an empty
    // vault that looks correct.
    expect(bundle.manifest.totalBytes).toBeGreaterThan(6000);
  });

  it('records a checksum for every file, in the manifest', () => {
    const bundle = sampleBundle();

    for (const entry of bundle.manifest.files) {
      expect(entry.sha256, entry.relativePath).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.sizeBytes).toBeGreaterThan(0);
    }
  });

  it('puts the digests in the manifest rather than beside the file contents', () => {
    // A digest stored next to the bytes it describes is checked against itself.
    // Both have to be altered together for that to pass, which is one edit.
    const bundle = sampleBundle();

    expect(bundle.files.every((file) => file.sha256 === undefined)).toBe(true);
    expect(bundle.manifest.files.every((entry) => typeof entry.sha256 === 'string')).toBe(true);
  });

  it('refuses two files at the same path', () => {
    expect(() => assembleBundle({
      files: [
        { relativePath: 'vault/a.enc', bytes: Buffer.from('one') },
        { relativePath: 'vault/a.enc', bytes: Buffer.from('two') },
      ],
    }, adapter)).toThrow(/twice/);
  });

  it('records which cipher the database uses', () => {
    expect(sampleBundle().database.cipher).toBe(DATABASE_CIPHERS.SQLCIPHER);
    expect(
      sampleBundle({ databaseCipher: DATABASE_CIPHERS.NONE }).database.cipher,
    ).toBe(DATABASE_CIPHERS.NONE);
  });
});

describe('path safety', () => {
  // A backup is an untrusted file that may have arrived from anywhere, and its
  // paths are used to write to disk.
  it('refuses paths that escape the backup', () => {
    for (const bad of [
      '../../.ssh/authorized_keys',
      'vault/../../etc/passwd',
      '/etc/passwd',
      'C:\\Windows\\System32\\drivers\\etc\\hosts',
      '..',
      'a/../../b',
      // A drive that only appears once the leading '.' segments are dropped.
      './C:/outside',
      './/C:/outside',
      '.\\C:\\outside',
      'C:outside',
      // NTFS alternate data stream, and a NUL that ends a path early.
      'vault/doc.enc:hidden',
      'vault/doc\u0000.enc',
    ]) {
      expect(() => normalizeRelativePath(bad), bad).toThrow();
    }
  });

  it('accepts ordinary paths and normalises separators', () => {
    expect(normalizeRelativePath('vault\\doc.enc')).toBe('vault/doc.enc');
    expect(normalizeRelativePath('./data/auth.json')).toBe('data/auth.json');
    expect(normalizeRelativePath('vault//doc.enc')).toBe('vault/doc.enc');
  });

  it('refuses an empty path rather than defaulting it', () => {
    for (const bad of ['', '   ', null, undefined, '.', './']) {
      expect(() => normalizeRelativePath(bad)).toThrow();
    }
  });
});

describe('verifying a bundle', () => {
  it('passes a bundle that has not been touched', () => {
    const result = verifyBundle(sampleBundle(), adapter);

    expect(result.ok).toBe(true);
    expect(result.problems).toEqual([]);
    expect(result.fileCount).toBe(4);
  });

  it('catches a file altered without changing its length', () => {
    // The case size alone cannot catch, and the reason a digest is recorded.
    const bundle = sampleBundle();
    const target = bundle.files.find((f) => f.relativePath === 'vault/doc-one.enc');
    const bytes = Buffer.from(target.contentBase64, 'base64');
    bytes[0] ^= 0xff;
    target.contentBase64 = bytes.toString('base64');

    const result = verifyBundle(bundle, adapter);

    expect(result.ok).toBe(false);
    expect(result.problems.join(' ')).toMatch(/doc-one\.enc.*checksum/);
  });

  it('catches a truncated file', () => {
    const bundle = sampleBundle();
    const target = bundle.files.find((f) => f.relativePath === 'vault/doc-two.enc');
    const bytes = Buffer.from(target.contentBase64, 'base64').subarray(0, 100);
    target.contentBase64 = bytes.toString('base64');

    expect(verifyBundle(bundle, adapter).ok).toBe(false);
  });

  it('catches a file listed in the manifest but missing from the archive', () => {
    const bundle = sampleBundle();
    bundle.files = bundle.files.filter((f) => f.relativePath !== 'data/auth.json');

    const result = verifyBundle(bundle, adapter);

    expect(result.ok).toBe(false);
    expect(result.problems.join(' ')).toMatch(/auth\.json.*missing/);
  });

  it('reports a file nothing vouches for, and never restores it', () => {
    const bundle = sampleBundle();
    bundle.files.push({
      relativePath: 'vault/smuggled.enc',
      contentBase64: Buffer.from('unlisted').toString('base64'),
    });

    const result = verifyBundle(bundle, adapter);

    // Not corrupt — the manifest still describes what it describes — but the
    // extra file is surfaced rather than quietly written to the vault.
    expect(result.unlisted).toContain('vault/smuggled.enc');
  });

  it('refuses a path that appears twice, so the bytes checked are the bytes used', () => {
    const twiceInFiles = sampleBundle();
    const first = twiceInFiles.files[0];
    // An unchecked copy first, the checked one last: a reader taking the first would use the wrong one.
    twiceInFiles.files.unshift({ relativePath: first.relativePath, contentBase64: Buffer.from('other').toString('base64') });
    expect(verifyBundle(twiceInFiles, adapter).problems.join(' ')).toMatch(/appears twice/);

    const twiceInManifest = sampleBundle();
    twiceInManifest.manifest.files.push({ ...twiceInManifest.manifest.files[0] });
    expect(() => assertBundleIntact(twiceInManifest, adapter)).toThrow(/listed twice/);
  });

  it('throws before anything is written, since restore is destructive', () => {
    const bundle = sampleBundle();
    bundle.manifest.files[0].sha256 = 'f'.repeat(64);

    expect(() => assertBundleIntact(bundle, adapter)).toThrow(/integrity check/);
  });

  it('refuses a bundle from a newer app rather than guessing at its shape', () => {
    const bundle = sampleBundle();
    bundle.version = 99;

    expect(() => verifyBundle(bundle, adapter)).toThrow(/Update PaperSafeAI/);
  });
});

describe('sealing and opening', () => {
  it('round-trips a complete vault', async () => {
    const bundle = sampleBundle();
    const envelope = await sealBundle(bundle, PASSPHRASE, adapter);

    const reopened = await openEnvelope(envelope, PASSPHRASE, adapter);

    expect(reopened).toEqual(bundle);
    expect(assertBundleIntact(reopened, adapter).ok).toBe(true);
  });

  it('survives the trip through JSON that a file on disk is', async () => {
    // The archive is written as text and read back by a different process, so a
    // round trip in memory is not the thing that has to work.
    const bundle = sampleBundle();
    const onDisk = JSON.stringify(await sealBundle(bundle, PASSPHRASE, adapter));

    const parsed = parseEnvelope(onDisk);
    const reopened = await openEnvelope(parsed, PASSPHRASE, adapter);

    expect(reopened).toEqual(bundle);
  });

  it('writes v3 with Argon2id', async () => {
    const envelope = await sealBundle(sampleBundle(), PASSPHRASE, adapter);

    expect(envelope.format).toBe(ENVELOPE_FORMAT_V3);
    expect(envelope.version).toBe(CURRENT_ENVELOPE_VERSION);
    expect(envelope.kdf.name).toBe('argon2id');
    expect(envelope.cipher.name).toBe('aes-256-gcm');
  });

  it('never writes the passphrase or the plaintext into the archive', async () => {
    const envelope = await sealBundle(sampleBundle(), PASSPHRASE, adapter);
    const text = JSON.stringify(envelope);

    expect(text).not.toContain(PASSPHRASE);
    // The database key lives inside the bundle, so it must NOT be visible in
    // the envelope's own JSON.
    expect(text).not.toContain('a'.repeat(64));
    expect(text).not.toContain('vault.db');
  });

  it('produces a different archive every time from identical input', async () => {
    // A fresh salt and IV per archive. Reusing either across two backups of the
    // same vault would leak that they are the same vault, and reusing an IV
    // under one key breaks GCM outright.
    const bundle = sampleBundle();
    const first = await sealBundle(bundle, PASSPHRASE, adapter);
    const second = await sealBundle(bundle, PASSPHRASE, adapter);

    expect(first.kdf.salt).not.toBe(second.kdf.salt);
    expect(first.cipher.iv).not.toBe(second.cipher.iv);
    expect(first.ciphertext).not.toBe(second.ciphertext);
  });

  it('caps decompression, so a small archive cannot expand without bound', async () => {
    const zeros = zlib.gzipSync(Buffer.alloc(1024 * 1024));
    let error = null;
    try { adapter.gunzip(zeros, { maxOutputLength: 1000 }); } catch (e) { error = e; }
    expect(error && error.code).toBe('ERR_BUFFER_TOO_LARGE');
    expect(adapter.gunzip(zeros, { maxOutputLength: 2 * 1024 * 1024 }).length).toBe(1024 * 1024);

    // openEnvelope asks for the cap and names the refusal.
    const envelope = await sealBundle(sampleBundle(), PASSPHRASE, adapter);
    let asked = null;
    const capped = {
      ...adapter,
      gunzip: (bytes, options) => {
        asked = options;
        const tooLarge = new RangeError('too large');
        tooLarge.code = 'ERR_BUFFER_TOO_LARGE';
        throw tooLarge;
      },
    };
    await expect(openEnvelope(envelope, PASSPHRASE, capped)).rejects.toThrow(/more than 8 GiB/);
    expect(asked).toEqual({ maxOutputLength: MAX_EXPANDED_BACKUP_BYTES });
  });

  it('rejects the wrong passphrase', async () => {
    const envelope = await sealBundle(sampleBundle(), PASSPHRASE, adapter);

    await expect(openEnvelope(envelope, 'not-the-right-passphrase', adapter))
      .rejects.toThrow(/incorrect or the archive is corrupted/);
  });

  it('says the same thing for a wrong passphrase and a corrupt archive', async () => {
    // Distinguishing them tells someone holding a stolen archive whether a
    // guess was close.
    const envelope = await sealBundle(sampleBundle(), PASSPHRASE, adapter);
    const corrupted = { ...envelope, ciphertext: envelope.ciphertext.replace(/^.{8}/, 'AAAAAAAA') };

    const wrongPassphrase = await openEnvelope(envelope, 'wrong-passphrase-here', adapter)
      .catch((error) => error.message);
    const corruptArchive = await openEnvelope(corrupted, PASSPHRASE, adapter)
      .catch((error) => error.message);

    expect(wrongPassphrase).toBe(corruptArchive);
  });

  it('refuses a passphrase too short to be worth anything', async () => {
    await expect(sealBundle(sampleBundle(), 'short', adapter)).rejects.toThrow(/at least 10/);
    expect(() => validateBackupPassphrase('nine char')).toThrow();
    expect(validateBackupPassphrase('ten chars!')).toBe('ten chars!');
  });
});

describe('the authenticated header (what v3 adds)', () => {
  // In v2 the header was unauthenticated: createdAt, fileCount, totalBytes and
  // the entire kdf block could be edited and the archive still opened. The KDF
  // parameters feed straight into key derivation, so that was the weakest part
  // of the format.
  const mutations = {
    createdAt: (e) => ({ ...e, createdAt: '1999-01-01T00:00:00.000Z' }),
    fileCount: (e) => ({ ...e, fileCount: 1 }),
    totalBytes: (e) => ({ ...e, totalBytes: 12 }),
    'kdf.salt': (e) => ({ ...e, kdf: { ...e.kdf, salt: Buffer.alloc(16, 7).toString('base64') } }),
    'kdf.timeCost': (e) => ({ ...e, kdf: { ...e.kdf, timeCost: 2 } }),
    'kdf.memoryCost': (e) => ({ ...e, kdf: { ...e.kdf, memoryCost: 32768 } }),
    'cipher.iv': (e) => ({
      ...e,
      cipher: { ...e.cipher, iv: Buffer.alloc(12, 3).toString('base64') },
    }),
  };

  for (const [field, mutate] of Object.entries(mutations)) {
    it(`refuses an archive whose ${field} was edited`, async () => {
      const envelope = await sealBundle(sampleBundle(), PASSPHRASE, adapter);

      await expect(openEnvelope(mutate(envelope), PASSPHRASE, adapter)).rejects.toThrow();
    });
  }

  it('refuses a v3 archive with its authentication marker stripped', async () => {
    // Otherwise stripping one field would downgrade a v3 archive to v2's
    // unauthenticated handling — the classic way an added protection is skipped.
    const envelope = await sealBundle(sampleBundle(), PASSPHRASE, adapter);
    const stripped = { ...envelope, cipher: { ...envelope.cipher, aad: undefined } };

    await expect(openEnvelope(stripped, PASSPHRASE, adapter))
      .rejects.toThrow(/not authenticated|tampered/);
  });
});

describe('key-derivation cost is never taken on trust', () => {
  it('refuses scrypt dialled below the floor', () => {
    // A crafted archive claiming N=2 makes an offline brute-force of the
    // passphrase seconds of work.
    expect(() => assertKdfCost({ name: 'scrypt', N: 2, r: 8, p: 1 })).toThrow(/weak key derivation/);
    expect(() => assertKdfCost({ name: 'scrypt', N: 8192, r: 8, p: 1 })).toThrow(/16384/);
  });

  it('refuses Argon2id dialled below the floor', () => {
    expect(() => assertKdfCost({ name: 'argon2id', timeCost: 1, memoryCost: 65536 }))
      .toThrow(/weak key derivation/);
    expect(() => assertKdfCost({ name: 'argon2id', timeCost: 3, memoryCost: 1024 }))
      .toThrow(/weak key derivation/);
  });

  it('refuses a scheme it does not know instead of picking one', () => {
    expect(() => assertKdfCost({ name: 'rot13' })).toThrow(/unknown key-derivation scheme/);
    expect(() => assertKdfCost({})).toThrow(/unknown key-derivation scheme/);
  });

  it('refuses Argon2id asking for more work than any build writes (a hang or out-of-memory, not a key)', () => {
    const ok = { name: 'argon2id', timeCost: 3, memoryCost: 65536, parallelism: 1, keyLength: 32 };
    expect(() => assertKdfCost({ ...ok, memoryCost: 4 * 1024 * 1024 })).toThrow(/more key-derivation work.*memoryCost=262144/);
    expect(() => assertKdfCost({ ...ok, timeCost: 1_000_000 })).toThrow(/timeCost=10/);
    expect(() => assertKdfCost({ ...ok, parallelism: 64 })).toThrow(/parallelism=4/);
    expect(() => assertKdfCost({ ...ok, keyLength: 1 << 30 })).toThrow(/keyLength=32/);
    expect(() => assertKdfCost({ ...ok, timeCost: 3.5 })).toThrow(/more key-derivation work/);
    expect(() => assertKdfCost({ ...ok, memoryCost: 262144, timeCost: 10, parallelism: 4 })).not.toThrow();
    expect(() => assertKdfCost({ name: 'argon2id', timeCost: 3, memoryCost: 65536 })).not.toThrow();
  });

  it('refuses scrypt asking for more memory than any build wrote', () => {
    expect(() => assertKdfCost({ name: 'scrypt', N: 1 << 24, r: 8, p: 1 })).toThrow(/N=262144/);
    expect(() => assertKdfCost({ name: 'scrypt', N: 65536, r: 1024, p: 1 })).toThrow(/r=8/);
    expect(() => assertKdfCost({ name: 'scrypt', N: 65536, r: 8, p: 1, keyLength: 32 })).not.toThrow();
  });

  it('checks the ceiling BEFORE spending anything', async () => {
    const envelope = await sealBundle(sampleBundle(), PASSPHRASE, adapter);
    const heavy = { ...envelope, kdf: { ...envelope.kdf, memoryCost: 8 * 1024 * 1024 } };
    let derived = false;
    const watching = { ...adapter, deriveKey: async (...args) => { derived = true; return adapter.deriveKey(...args); } };
    await expect(openEnvelope(heavy, PASSPHRASE, watching)).rejects.toThrow(/more key-derivation work/);
    expect(derived).toBe(false);
  });

  it('checks the cost BEFORE spending it', async () => {
    // The point of a floor is to refuse the work, not to do it and complain.
    const envelope = await sealBundle(sampleBundle(), PASSPHRASE, adapter);
    const weakened = { ...envelope, kdf: { ...envelope.kdf, memoryCost: 8 } };

    const started = Date.now();
    await expect(openEnvelope(weakened, PASSPHRASE, adapter)).rejects.toThrow(/weak key derivation/);
    expect(Date.now() - started).toBeLessThan(250);
  });

  it('accepts the parameters this build actually writes', async () => {
    const envelope = await sealBundle(sampleBundle(), PASSPHRASE, adapter);

    expect(() => assertKdfCost(envelope.kdf)).not.toThrow();
  });
});

describe('reading v2 archives, forever', () => {
  /** A v2 archive exactly as the previous desktop wrote it: scrypt, no AAD. */
  function writeLegacyV2(bundle, passphrase) {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const kdf = { name: 'scrypt', N: 65536, r: 8, p: 1, keyLength: 32 };
    const key = crypto.scryptSync(passphrase, salt, 32, {
      N: kdf.N, r: kdf.r, p: kdf.p, maxmem: 256 * 1024 * 1024,
    });
    const compressed = zlib.gzipSync(Buffer.from(JSON.stringify(bundle), 'utf8'));
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
    return {
      format: ENVELOPE_FORMAT_V2,
      version: 2,
      createdAt: bundle.createdAt,
      fileCount: bundle.manifest.fileCount,
      totalBytes: bundle.manifest.totalBytes,
      kdf: { ...kdf, salt: salt.toString('base64') },
      cipher: { name: 'aes-256-gcm', iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64') },
      ciphertext: ciphertext.toString('base64'),
    };
  }

  it('opens an archive written by the previous format', async () => {
    // The one thing a backup format must never do is strand the files people
    // already hold.
    const bundle = sampleBundle();
    const legacy = writeLegacyV2(bundle, PASSPHRASE);

    const reopened = await openEnvelope(legacy, PASSPHRASE, adapter);

    expect(reopened).toEqual(bundle);
    expect(assertBundleIntact(reopened, adapter).ok).toBe(true);
  });

  it('recognises a v2 archive as an archive', () => {
    const legacy = writeLegacyV2(sampleBundle(), PASSPHRASE);
    const parsed = parseEnvelope(JSON.stringify(legacy));

    expect(parsed?.format).toBe(ENVELOPE_FORMAT_V2);
  });

  it('does not demand the authentication v2 could never have had', async () => {
    const legacy = writeLegacyV2(sampleBundle(), PASSPHRASE);

    expect(legacy.cipher.aad).toBeUndefined();
    await expect(openEnvelope(legacy, PASSPHRASE, adapter)).resolves.toBeTruthy();
  });

  it('still rejects a wrong passphrase on a v2 archive', async () => {
    const legacy = writeLegacyV2(sampleBundle(), PASSPHRASE);

    await expect(openEnvelope(legacy, 'wrong-passphrase-x', adapter)).rejects.toThrow();
  });
});

describe('recognising what a file is', () => {
  it('returns null for something that is not an archive at all', () => {
    // The caller then tries the legacy raw-gzip path, so this must not throw.
    for (const text of ['', 'not json', '\u001f\u008b binary gzip', '[]', '{"format":"other"}']) {
      expect(parseEnvelope(text), text).toBeNull();
    }
  });

  it('THROWS for an archive from a newer app, rather than returning null', async () => {
    // "I do not recognise this" and "I recognise it and cannot read it" need
    // different answers — the second one has a fix, and it is "update the app".
    const envelope = await sealBundle(sampleBundle(), PASSPHRASE, adapter);
    const future = JSON.stringify({ ...envelope, version: MAX_SUPPORTED_ENVELOPE_VERSION + 1 });

    expect(() => parseEnvelope(future)).toThrow(/Update PaperSafeAI/);
  });
});

describe('the database-cipher question', () => {
  it('carries the writer\'s intent so a reader can normalise', async () => {
    // Mobile's expo-sqlite has no encryption; the desktop's is SQLCipher. A
    // phone-authored bundle restored on a desktop would otherwise put a
    // plaintext database where an encrypted one is expected.
    const fromPhone = sampleBundle({ databaseCipher: DATABASE_CIPHERS.NONE, dbKeyHex: null });
    const envelope = await sealBundle(fromPhone, PASSPHRASE, adapter);
    const reopened = await openEnvelope(envelope, PASSPHRASE, adapter);

    expect(reopened.database.cipher).toBe(DATABASE_CIPHERS.NONE);
    expect(reopened.dbKeyHex).toBeNull();
  });

  it('is a declaration, not a proof — and now it is at least authenticated', async () => {
    // In v2 this field would have been editable. It still must not be the only
    // thing a restore relies on: the reader detects what it actually received.
    const bundle = sampleBundle();
    const envelope = await sealBundle(bundle, PASSPHRASE, adapter);
    const lying = { ...envelope, fileCount: 0 };

    await expect(openEnvelope(lying, PASSPHRASE, adapter)).rejects.toThrow();
  });
});

/**
 * Which app can open which backup.
 *
 * Not "same platform only". The asymmetry is the point: a phone-authored
 * bundle carries a PLAINTEXT database that a desktop encrypts on first open,
 * and that path is the whole reason mobile export exists — the phone is
 * sometimes the only copy. A desktop-authored bundle carries SQLCipher, and
 * expo-sqlite has no cipher at all, so the phone would write a file it could
 * never read. Before this check that restore ran to completion and left the
 * vault in exactly that state.
 */
describe('which platform can restore a bundle', () => {
  const desktopBundle = () => sampleBundle({ platform: BACKUP_PLATFORMS.DESKTOP });
  const mobileBundle = () => sampleBundle({
    platform: BACKUP_PLATFORMS.MOBILE,
    dbKeyHex: null,
    databaseCipher: DATABASE_CIPHERS.NONE,
  });

  it('stamps the producing platform, and reads it back', () => {
    expect(producerPlatformOf(desktopBundle())).toBe(BACKUP_PLATFORMS.DESKTOP);
    expect(producerPlatformOf(mobileBundle())).toBe(BACKUP_PLATFORMS.MOBILE);
  });

  it('reads a bundle written before the field as unknown, not as suspect', () => {
    const legacy = mobileBundle();
    delete legacy.producer;
    expect(producerPlatformOf(legacy)).toBe(BACKUP_PLATFORMS.UNKNOWN);
    // Still restorable on the phone: the decision is the cipher, not the stamp.
    expect(canRestoreDatabaseOn(legacy, BACKUP_PLATFORMS.MOBILE).ok).toBe(true);
  });

  it('lets a phone backup restore on a phone AND on a desktop', () => {
    expect(canRestoreDatabaseOn(mobileBundle(), BACKUP_PLATFORMS.MOBILE).ok).toBe(true);
    expect(canRestoreDatabaseOn(mobileBundle(), BACKUP_PLATFORMS.DESKTOP).ok).toBe(true);
  });

  it('lets a desktop backup restore on a desktop', () => {
    expect(canRestoreDatabaseOn(desktopBundle(), BACKUP_PLATFORMS.DESKTOP).ok).toBe(true);
  });

  it('refuses a desktop backup on a phone, and says why in words a user can act on', () => {
    const verdict = canRestoreDatabaseOn(desktopBundle(), BACKUP_PLATFORMS.MOBILE);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toBe('encrypted-database-unsupported');
    expect(verdict.message).toMatch(/computer/i);
    // It must tell them what WILL work, not only what will not.
    expect(verdict.message).toMatch(/phone can be restored here|Restore it on a computer/i);
  });

  it('decides on the cipher, not on the platform stamp', () => {
    // A bundle claiming to be from a phone while carrying an encrypted
    // database is still refused: the stamp is attacker-supplied text in a file
    // the user may have received from anywhere, the cipher is a property of
    // the bytes.
    const lying = sampleBundle({
      platform: BACKUP_PLATFORMS.MOBILE,
      dbKeyHex: 'b'.repeat(64),
      databaseCipher: DATABASE_CIPHERS.SQLCIPHER,
    });
    expect(canRestoreDatabaseOn(lying, BACKUP_PLATFORMS.MOBILE).ok).toBe(false);
  });

  it('infers the cipher from dbKeyHex when no database field was written', () => {
    const old = desktopBundle();
    delete old.database;
    expect(canRestoreDatabaseOn(old, BACKUP_PLATFORMS.MOBILE).ok).toBe(false);
  });

  it('assertRestorableOn throws with a code, and stays silent when it is fine', () => {
    expect(() => assertRestorableOn(desktopBundle(), BACKUP_PLATFORMS.MOBILE))
      .toThrow(/computer/i);
    try {
      assertRestorableOn(desktopBundle(), BACKUP_PLATFORMS.MOBILE);
    } catch (error) {
      expect(error.code).toBe('encrypted-database-unsupported');
    }
    expect(() => assertRestorableOn(mobileBundle(), BACKUP_PLATFORMS.MOBILE)).not.toThrow();
  });
});

/**
 * What the database bytes ARE, versus what the bundle says they are.
 *
 * The declaration is written by whoever produced the file, and a `.psbak` is a
 * file a user may have been handed by anyone. It is also wrong on one honest
 * path: a desktop exporting while it does not hold the database key raw-copies
 * the SQLCipher file and stamps `cipher: none`, because there is no dbKeyHex to
 * infer from. Trusting it would drop an unopenable database onto a phone that
 * had just deleted its own.
 */
describe('the database cipher is read from the bytes', () => {
  const SQLITE_HEADER = 'SQLite format 3\u0000the rest of a plain database';
  const CIPHERTEXT = '\u00a7\u00e3\u0011\u00ff not a sqlite header at all, just bytes';

  function bundleWithDatabase(contents, overrides = {}) {
    return assembleBundle({
      files: [
        { relativePath: 'data/auth.json', bytes: Buffer.from('{}', 'utf8') },
        { relativePath: 'data/vault.db', bytes: Buffer.from(contents, 'binary') },
      ],
      createdAt: '2026-09-04T12:00:00.000Z',
      ...overrides,
    }, adapter);
  }

  it('sees a plaintext database for what it is', () => {
    expect(observedDatabaseCipher(bundleWithDatabase(SQLITE_HEADER), adapter))
      .toBe(DATABASE_CIPHERS.NONE);
  });

  it('sees an encrypted database for what it is', () => {
    expect(observedDatabaseCipher(bundleWithDatabase(CIPHERTEXT), adapter))
      .toBe(DATABASE_CIPHERS.SQLCIPHER);
  });

  it('returns null when there is no database entry, rather than guessing plaintext', () => {
    const noDatabase = assembleBundle({
      files: [{ relativePath: 'data/auth.json', bytes: Buffer.from('{}', 'utf8') }],
      createdAt: '2026-09-04T12:00:00.000Z',
    }, adapter);
    expect(observedDatabaseCipher(noDatabase, adapter)).toBeNull();
  });

  it('refuses an encrypted database on mobile even when the bundle claims otherwise', () => {
    // The honest mislabel: raw-copied SQLCipher bytes stamped `cipher: none`.
    // Before this the phone accepted it, deleted its own database, and wrote a
    // file it could never open.
    const lying = bundleWithDatabase(CIPHERTEXT, {
      platform: BACKUP_PLATFORMS.MOBILE,
      databaseCipher: DATABASE_CIPHERS.NONE,
      dbKeyHex: null,
    });
    expect(canRestoreDatabaseOn(lying, BACKUP_PLATFORMS.MOBILE).ok).toBe(true);
    expect(canRestoreDatabaseOn(lying, BACKUP_PLATFORMS.MOBILE, adapter).ok).toBe(false);
  });

  it('allows a genuinely plaintext database on mobile even when it claims to be encrypted', () => {
    // The other direction. A declaration must not be able to lock a user out of
    // a backup that would restore perfectly well.
    const mislabelled = bundleWithDatabase(SQLITE_HEADER, {
      platform: BACKUP_PLATFORMS.DESKTOP,
      databaseCipher: DATABASE_CIPHERS.SQLCIPHER,
    });
    expect(canRestoreDatabaseOn(mislabelled, BACKUP_PLATFORMS.MOBILE, adapter).ok).toBe(true);
  });

  it('falls back to the declaration when the bytes cannot be judged', () => {
    const noDatabase = assembleBundle({
      files: [{ relativePath: 'data/auth.json', bytes: Buffer.from('{}', 'utf8') }],
      platform: BACKUP_PLATFORMS.DESKTOP,
      databaseCipher: DATABASE_CIPHERS.SQLCIPHER,
      createdAt: '2026-09-04T12:00:00.000Z',
    }, adapter);
    expect(canRestoreDatabaseOn(noDatabase, BACKUP_PLATFORMS.MOBILE, adapter).ok).toBe(false);
  });
});

/**
 * Bundle v2: the file bytes live OUTSIDE the JSON.
 *
 * v1 base64'd every file into one `JSON.stringify` call. V8 caps a string at
 * 536,870,888 bytes and base64 costs 4/3, so a vault over roughly 400 MB could
 * not be backed up — and, worse, could not be restored either.
 */
describe('bundle v2 container', () => {
  /* The writer emits v1 today (format.js explains why), so these exercise the
     v2 reader against explicitly-produced v2 bytes. That is the half that has
     to be correct BEFORE anything writes v2 in the field. */
  const sampleFiles = () => ([
    { relativePath: 'data/vault.db', bytes: new Uint8Array([1, 2, 3, 4, 5]) },
    { relativePath: 'vault/a.enc', bytes: new Uint8Array([9, 8, 7]) },
    // An empty file is a real case and an easy off-by-one in a length-prefixed
    // container.
    { relativePath: 'vault/empty.enc', bytes: new Uint8Array([]) }
  ]);

  it('round-trips a bundle byte for byte', () => {
    const bundle = assembleBundle({ files: sampleFiles(), platform: 'desktop' }, adapter);
    const restored = deserializeBundle(serializeBundle(bundle, adapter, { version: 2 }), adapter);

    expect(restored.version).toBe(2);
    expect(restored.manifest).toEqual(bundle.manifest);
    for (const file of bundle.files) {
      const match = restored.files.find((f) => f.relativePath === file.relativePath);
      expect(match?.contentBase64).toBe(file.contentBase64);
    }
  });

  it('keeps the bytes out of the JSON, so no single string holds the vault', () => {
    const bundle = assembleBundle({ files: sampleFiles(), platform: 'desktop' }, adapter);
    const bytes = serializeBundle(bundle, adapter, { version: 2 });
    // The header is JSON; the payload is not. If contents leaked into the
    // header we would be back to the ceiling this format exists to remove.
    const headerLength = (bytes[6] << 24 >>> 0) + (bytes[7] << 16) + (bytes[8] << 8) + bytes[9];
    const header = JSON.parse(adapter.bytesToUtf8(bytes.subarray(10, 10 + headerLength)));
    expect(header.files).toBeUndefined();
    expect(header.manifest.files).toHaveLength(3);
  });

  it('still reads a v1 bundle, which is plain JSON', () => {
    const bundle = assembleBundle({ files: sampleFiles(), platform: 'desktop' }, adapter);
    const legacy = adapter.utf8ToBytes(JSON.stringify({ ...bundle, version: 1 }));

    const restored = deserializeBundle(legacy, adapter);
    expect(restored.version).toBe(1);
    expect(restored.files).toHaveLength(3);
    expect(() => assertBundleIntact(restored, adapter)).not.toThrow();
  });

  it('refuses a truncated container rather than returning half a vault', () => {
    const bundle = assembleBundle({ files: sampleFiles(), platform: 'desktop' }, adapter);
    const bytes = serializeBundle(bundle, adapter, { version: 2 });

    expect(() => deserializeBundle(bytes.subarray(0, bytes.length - 3), adapter))
      .toThrow(/truncated/i);
  });
});

describe('what this build actually writes', () => {
  it('writes v1, so a phone that predates v2 can still open it', () => {
    // Forward compatibility is the reason. A shipped phone caps at bundle v1
    // AND parses JSON before it checks the version, so a v2 archive fails as
    // "this backup decrypted but its contents could not be read" — the
    // corruption message, on the file the user most needs to trust.
    const bundle = assembleBundle({
      files: [{ relativePath: 'vault/a.enc', bytes: new Uint8Array([1, 2, 3]) }],
      platform: 'desktop'
    }, adapter);
    const bytes = serializeBundle(bundle, adapter);

    expect(bundle.version).toBe(1);
    expect(adapter.bytesToUtf8(bytes.subarray(0, 1))).toBe('{');
    expect(deserializeBundle(bytes, adapter).files).toHaveLength(1);
  });

  it('refuses a vault too large to survive being turned into one string', async () => {
    // Two base64 passes and two string builds against V8's 512 MB cap. The
    // user gets this instead of `RangeError: Invalid string length`.
    await expect(sealBundle(
      { manifest: { totalBytes: 1_000_000_000, fileCount: 1 }, files: [] },
      PASSPHRASE,
      adapter
    )).rejects.toThrow(/too large for a single encrypted backup archive/);
  });

  it('refuses up front from a stat size, with advice for a feature that exists', () => {
    expect(() => assertVaultFitsArchive(MAX_ARCHIVE_VAULT_BYTES - 1)).not.toThrow();
    // Only what is true at any size: a paired phone's documents reach the
    // computer by everyday sync (no size limit). "Pair this phone" was not:
    // copying a phone vault to a computer stops at about 300 MB.
    expect(() => assertVaultFitsArchive(MAX_ARCHIVE_VAULT_BYTES, { platform: 'mobile' }))
      .toThrow(/If this phone is paired with PaperSafeAI on a computer, your documents are kept there too/);
    expect(() => assertVaultFitsArchive(MAX_ARCHIVE_VAULT_BYTES, { platform: 'mobile' }))
      .not.toThrow(/Pair this phone/);
    expect(() => assertVaultFitsArchive(MAX_ARCHIVE_VAULT_BYTES)).toThrow(/automatic backups/);
    expect(() => assertVaultFitsArchive(MAX_ARCHIVE_VAULT_BYTES)).not.toThrow(/smaller parts/);
  });
});

describe('passphrase hint', () => {
  const bundle = () => assembleBundle({
    files: [{ relativePath: 'vault/a.enc', bytes: new Uint8Array([1, 2, 3]) }],
    platform: 'desktop'
  }, adapter);

  it('is stored readable before decryption and does not change what opens', async () => {
    const envelope = await sealBundle(bundle(), PASSPHRASE, adapter, { passphraseHint: '  the usual one  ' });
    const reparsed = parseEnvelope(JSON.stringify(envelope));
    expect(readPassphraseHint(reparsed)).toBe('the usual one');
    expect((await openEnvelope(reparsed, PASSPHRASE, adapter)).files).toHaveLength(1);
  });

  it('is absent when not given, so older archives read as having none', async () => {
    const envelope = await sealBundle(bundle(), PASSPHRASE, adapter);
    expect('passphraseHint' in envelope).toBe(false);
    expect(readPassphraseHint(envelope)).toBeNull();
  });

  it('refuses a hint that contains the passphrase', async () => {
    await expect(sealBundle(bundle(), PASSPHRASE, adapter, { passphraseHint: `it is ${PASSPHRASE}` }))
      .rejects.toThrow(/must not contain the passphrase/);
  });
});
