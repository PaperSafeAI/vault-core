'use strict';

/**
 * The payload inside a backup: every file, plus what proves each one intact.
 *
 * A complete backup is the whole vault — the auth record, the database, and
 * every encrypted document under the vault directory. Not a metadata export:
 * restoring one onto a clean machine must give the user their documents back,
 * because for many of them this file is the only other copy that exists.
 *
 * Deliberately NOT included, on any platform: the database key as wrapped for
 * THIS machine, and every biometric enrolment (Keychain or Secure Enclave
 * bound). The app leaves those files out when it lists what to back up.
 *
 * Those are machine-bound by design and meaningless elsewhere; including them
 * would carry a device's credentials into a file the user emails to themselves.
 * The consequence is deliberate and must stay true in the UI: a restore needs
 * the master password, and biometric unlock has to be set up again.
 */

const {
  BUNDLE_FORMAT,
  BUNDLE_VERSION_V2,
  CURRENT_BUNDLE_VERSION,
  CURRENT_MANIFEST_VERSION,
  MAX_SUPPORTED_BUNDLE_VERSION,
  MAX_SUPPORTED_MANIFEST_VERSION,
  DATABASE_CIPHERS,
  BACKUP_PLATFORMS,
  assertSupportedFormatVersion
} = require('./format');
const { assertAdapter, timestamp } = require('./adapter');

/**
 * Build the bundle for a set of files.
 *
 * @param {object} args
 * @param {Array<{relativePath: string, bytes: Uint8Array}>} args.files
 *   Every file, already read. `relativePath` is the position inside the
 *   backup, chosen by the app.
 * @param {string|null} [args.dbKeyHex] SQLCipher key, when the database is
 *   encrypted with one. Inside the envelope, so protected by the passphrase.
 * @param {string} [args.databaseCipher] Which cipher the database uses — see
 *   the note on `database` below.
 * @param {string} [args.platform] A BACKUP_PLATFORMS value: which app is
 *   writing this. Recorded for the restoring side's message, never for its
 *   decision — see canRestoreDatabaseOn.
 * @param {string} [args.createdAt] ISO timestamp; defaults to now.
 * @param {number} [args.schemaVersion] Desktop SQLite schema (PRAGMA
 *   user_version) of the bundled database. Additive and optional: only a writer
 *   whose database is on the desktop's ladder sets it, and readers must treat
 *   its absence as "unknown", never as a refusal.
 * @param {object} adapter
 */
function assembleBundle(args, adapter) {
  assertAdapter(adapter);
  const files = Array.isArray(args?.files) ? args.files : [];
  const createdAt = args?.createdAt || timestamp(adapter);

  const seen = new Set();
  const manifestFiles = [];
  const bundleFiles = [];
  let totalBytes = 0;

  for (const file of files) {
    const relativePath = normalizeRelativePath(file?.relativePath);
    const bytes = file?.bytes;
    if (!(bytes instanceof Uint8Array)) {
      throw new Error(`Backup file "${relativePath}" was not read as bytes.`);
    }
    // Two entries at one path would restore in whichever order the writer
    // happened to emit them, and the manifest would describe only one.
    if (seen.has(relativePath)) {
      throw new Error(`Backup contains "${relativePath}" twice.`);
    }
    seen.add(relativePath);

    manifestFiles.push({
      relativePath,
      sizeBytes: bytes.length,
      // MANDATORY, and recorded here rather than beside the file contents.
      // Restore re-hashes every entry against this list and aborts on a
      // mismatch, so a per-file digest stored next to the file it describes
      // would be checked against itself and prove nothing.
      sha256: adapter.sha256Hex(bytes)
    });
    bundleFiles.push({ relativePath, contentBase64: adapter.toBase64(bytes) });
    totalBytes += bytes.length;
  }

  return {
    version: CURRENT_BUNDLE_VERSION,
    format: BUNDLE_FORMAT,
    createdAt,
    manifest: {
      version: CURRENT_MANIFEST_VERSION,
      createdAt,
      fileCount: manifestFiles.length,
      totalBytes,
      ...(args?.schemaVersion != null ? { schemaVersion: Number(args.schemaVersion) } : {}),
      files: manifestFiles
    },
    files: bundleFiles,
    /**
     * Which app wrote this, for the restoring side to quote back when it has
     * to refuse. Additive: a bundle written before this existed simply has no
     * `producer`, and producerPlatformOf reads that as 'unknown' rather than
     * treating an older backup as suspect.
     */
    producer: {
      platform: args?.platform || BACKUP_PLATFORMS.UNKNOWN
    },
    dbKeyHex: args?.dbKeyHex || null,
    /**
     * How the database inside this bundle is encrypted.
     *
     * Desktop writes SQLCipher; mobile's expo-sqlite has no encryption at all.
     * Without this, a phone-authored bundle restored on a desktop would put a
     * plaintext database where an encrypted one is expected — a corruption
     * error at best, and at worst a vault that opens and quietly is not
     * protected at rest.
     *
     * A restoring platform must still DETECT what it received rather than
     * trusting this field, and normalise to its own storage. The field says
     * what the writer intended; detection establishes what actually arrived.
     * They are different questions, and only one of them is attacker-supplied.
     */
    database: {
      cipher: args?.databaseCipher || DATABASE_CIPHERS.NONE
    }
  };
}

/**
 * Check a bundle before anything is written to disk.
 *
 * Restore is destructive — it replaces a vault — so every reason to refuse has
 * to be found BEFORE the existing one is touched, not partway through.
 */
function verifyBundle(bundle, adapter) {
  assertAdapter(adapter);
  if (!bundle || typeof bundle !== 'object') {
    throw new Error('This backup could not be read.');
  }
  assertSupportedFormatVersion('bundle', bundle.version, MAX_SUPPORTED_BUNDLE_VERSION);
  assertSupportedFormatVersion('manifest', bundle.manifest?.version, MAX_SUPPORTED_MANIFEST_VERSION);

  const manifestFiles = Array.isArray(bundle.manifest?.files) ? bundle.manifest.files : [];
  const problems = [];
  // One entry per path, in the files and in the manifest. With two, a reader
  // that takes the first and a check that took the last would disagree about
  // which bytes were verified; no writer emits a path twice (assembleBundle).
  const contents = new Map();
  for (const file of Array.isArray(bundle.files) ? bundle.files : []) {
    const relativePath = normalizeRelativePath(file?.relativePath);
    if (contents.has(relativePath)) problems.push(`${relativePath} appears twice in the backup`);
    contents.set(relativePath, file?.contentBase64);
  }
  const manifestPaths = new Set();
  for (const entry of manifestFiles) {
    const relativePath = normalizeRelativePath(entry?.relativePath);
    if (manifestPaths.has(relativePath)) problems.push(`${relativePath} is listed twice in the manifest`);
    manifestPaths.add(relativePath);
  }

  for (const entry of manifestFiles) {
    const relativePath = normalizeRelativePath(entry?.relativePath);
    const contentBase64 = contents.get(relativePath);
    if (contentBase64 === undefined) {
      problems.push(`${relativePath} is listed in the manifest but missing from the backup`);
      continue;
    }
    let bytes;
    try {
      bytes = adapter.fromBase64(contentBase64);
    } catch {
      problems.push(`${relativePath} could not be decoded`);
      continue;
    }
    if (Number.isFinite(Number(entry?.sizeBytes)) && bytes.length !== Number(entry.sizeBytes)) {
      problems.push(
        `${relativePath} is ${bytes.length} bytes but the manifest says ${entry.sizeBytes}`
      );
      continue;
    }
    // The check that actually matters. Size catches truncation; only the digest
    // catches a file that was altered while keeping its length.
    const digest = adapter.sha256Hex(bytes);
    if (String(entry?.sha256 || '').toLowerCase() !== digest) {
      problems.push(`${relativePath} does not match its recorded checksum`);
    }
  }

  // A file present but unlisted is not a corrupt archive, but it IS a file
  // nothing vouches for — so it is reported and never restored.
  const listed = new Set(manifestFiles.map((entry) => normalizeRelativePath(entry?.relativePath)));
  const unlisted = [...contents.keys()].filter((relativePath) => !listed.has(relativePath));

  return {
    ok: problems.length === 0,
    problems,
    unlisted,
    fileCount: manifestFiles.length,
    totalBytes: Number(bundle.manifest?.totalBytes || 0),
    createdAt: bundle.manifest?.createdAt || bundle.createdAt || null,
    databaseCipher: databaseCipherOf(bundle)
  };
}

/** Throwing form, for callers about to overwrite something. */
function assertBundleIntact(bundle, adapter) {
  const result = verifyBundle(bundle, adapter);
  if (!result.ok) {
    throw new Error(
      `This backup failed its integrity check and was not restored:\n- ${result.problems.join('\n- ')}`
    );
  }
  return result;
}

/**
 * Which cipher the database in this bundle uses.
 *
 * Bundles written before the `database` field existed do not carry it, and
 * defaulting those to "none" would tell a desktop that its own SQLCipher
 * database is plaintext — and invite a restore to "fix" it by encrypting an
 * already-encrypted file. Every such bundle came from a desktop, and a desktop
 * records `dbKeyHex` exactly when its database is encrypted, so the key's
 * presence is the answer for anything older than the field.
 */
function databaseCipherOf(bundle) {
  const declared = bundle?.database?.cipher;
  if (declared) return declared;
  return bundle?.dbKeyHex ? DATABASE_CIPHERS.SQLCIPHER : DATABASE_CIPHERS.NONE;
}

/** Every SQLite file begins with this. A SQLCipher one begins with ciphertext. */
const SQLITE_MAGIC = 'SQLite format 3\u0000';
/**
 * Where the app keeps its database inside a bundle. The app names it with
 * configureBundle; until it does, observedDatabaseCipher has nothing to look at
 * and returns null, and callers fall back to the declared cipher.
 */
// Kept on a global symbol for the same reason as the AAD registry (aad.js): a
// setting made through one loaded copy of this file holds for every copy.
const SETTINGS_KEY = Symbol.for('@papersafeailabs/vault-core/bundle-settings');
const settings = globalThis[SETTINGS_KEY] || (globalThis[SETTINGS_KEY] = { databaseEntry: null });

/**
 * App-specific bundle settings: `databaseEntry`, the bundle-relative path of
 * the database file.
 *
 * @param {{ databaseEntry?: string | null }} [options]
 */
function configureBundle({ databaseEntry: entry = null } = {}) {
  settings.databaseEntry = entry == null ? null : normalizeRelativePath(entry);
}

/**
 * What the database bytes in this bundle ACTUALLY are, ignoring what the bundle
 * says about itself.
 *
 * `databaseCipherOf` reads a declared JSON field, which is fine as a hint and
 * useless as a check — it is written by whoever produced the file, and this is a
 * file a user may have been handed by anyone. Worse, one honest producer path
 * gets it wrong: when the desktop exports while it does not hold the database
 * key, the snapshot falls back to a raw byte copy of the SQLCipher file while
 * the manifest stamps `cipher: none`, because no dbKeyHex was available to
 * infer from.
 *
 * Returns null when there is no database entry to look at, which is not the same
 * as "plaintext" and must not be treated as such by the caller.
 *
 * @param {object} bundle
 * @param {object} adapter
 * @returns {string|null}
 */
function observedDatabaseCipher(bundle, adapter) {
  const databaseEntry = settings.databaseEntry;
  if (!databaseEntry) return null;
  const entry = (Array.isArray(bundle?.files) ? bundle.files : [])
    .find((file) => normalizeRelativePath(file?.relativePath) === databaseEntry);
  if (!entry || typeof entry.contentBase64 !== 'string') return null;

  let head;
  try {
    head = adapter.fromBase64(entry.contentBase64).slice(0, SQLITE_MAGIC.length);
  } catch {
    return null;
  }
  if (head.length < SQLITE_MAGIC.length) return null;

  const asText = Array.from(head, (byte) => String.fromCharCode(byte)).join('');
  return asText === SQLITE_MAGIC ? DATABASE_CIPHERS.NONE : DATABASE_CIPHERS.SQLCIPHER;
}

/**
 * Reject any path that could escape the restore directory.
 *
 * A backup is an untrusted file that a user may have received from anywhere,
 * and its paths are used to write to disk. `../../.ssh/authorized_keys` inside
 * an archive is the whole attack, and it costs one line to make impossible.
 */
function normalizeRelativePath(value) {
  const raw = String(value || '').trim().replace(/\\/g, '/');
  if (!raw) {
    throw new Error('Backup contains a file with no path.');
  }
  if (raw.startsWith('/') || /^[A-Za-z]:/.test(raw)) {
    throw new Error(`Backup contains an absolute path: ${raw}`);
  }
  const segments = raw.split('/').filter((segment) => segment !== '' && segment !== '.');
  if (segments.some((segment) => segment === '..')) {
    throw new Error(`Backup contains a path that escapes the backup: ${raw}`);
  }
  // Checked on the segments that are returned, not only on the raw string:
  // `./C:/x` must not become `C:/x` once the `.` is dropped. A ':' anywhere is
  // a Windows drive (`C:`, `C:x`) or an NTFS alternate stream (`a.txt:s`), and
  // no file a PaperSafeAI app writes has one; a NUL ends a path early.
  if (segments.some((segment) => segment.includes(':') || segment.includes('\0'))) {
    throw new Error(`Backup contains an absolute or unsafe path: ${raw}`);
  }
  if (segments.length === 0) {
    throw new Error('Backup contains a file with no path.');
  }
  return segments.join('/');
}

/** Which app wrote this bundle. 'unknown' for one written before the field. */
function producerPlatformOf(bundle) {
  const declared = bundle?.producer?.platform;
  return declared || BACKUP_PLATFORMS.UNKNOWN;
}

/**
 * Can the app restoring this bundle actually OPEN the database inside it?
 *
 * Keyed on the DATABASE BYTES when they are there to look at, and on the
 * declared field only when they are not.
 *
 * An earlier version of this comment claimed the cipher was "a property of the
 * bytes" while the code read `bundle.database.cipher` — a second self-declared
 * field, in a file a user may have been handed by anyone, sitting right beside
 * the platform stamp it was supposedly safer than. It also mislabels on an
 * honest path: a desktop exporting while it does not hold the database key
 * raw-copies the SQLCipher file and stamps `cipher: none`, because there was no
 * dbKeyHex to infer from.
 *
 * So the bytes decide, the declaration is a fallback for a bundle with no
 * database entry, and the platform stamp only ever words the message.
 *
 * The asymmetry is real and worth stating, because it is not "same platform
 * only":
 *
 *   mobile -> desktop   fine. The database arrives as plaintext SQLite and
 *                       the desktop encrypts it into SQLCipher on first open
 *                       (openDatabase's migrateToSQLCipher). This is the
 *                       "my phone is the only copy, put it on a computer"
 *                       path, and it must keep working.
 *
 *                       The phone's own database IS SQLCipher now, but it
 *                       decrypts it on the way into the archive so that this
 *                       stays true. That costs no protection: the archive
 *                       itself is encrypted under the backup passphrase.
 *   desktop -> mobile   still refused, for a NARROWER reason than before.
 *
 *                       The phone has a cipher now, so "no cipher at all" is no
 *                       longer why. What it lacks is the KEY: a desktop
 *                       database may be encrypted under the vault-key-derived
 *                       key (../crypto/db-key.js, which the phone can
 *                       reproduce from the auth.json in the same bundle) OR
 *                       under the legacy safeStorage key, which only
 *                       `bundle.dbKeyHex` carries and which the phone could not
 *                       re-derive afterwards. Telling those apart, and
 *                       `PRAGMA rekey`-ing the second onto the phone's own
 *                       derived key at restore time, is the work this gate is
 *                       still standing in for. Until then a refusal that leaves
 *                       the existing vault intact beats a restore that
 *                       completes and leaves an unopenable one.
 *
 * @param {object} bundle
 * @param {string} targetPlatform  a BACKUP_PLATFORMS value — the app restoring
 * @param {object} [adapter]  the platform's backup adapter. Supply it whenever
 *   you have one: without it the decision falls back to the bundle's own claim
 *   about itself, which is exactly what this is meant to stop trusting.
 * @returns {{ok: true} | {ok: false, reason: string, message: string}}
 */
function canRestoreDatabaseOn(bundle, targetPlatform, adapter = null) {
  // Observed beats declared. Null means there was nothing to observe — no
  // database entry, or bytes too short to judge — and only then does the
  // bundle's own claim about itself get to decide.
  const observed = adapter ? observedDatabaseCipher(bundle, adapter) : null;
  const cipher = observed || databaseCipherOf(bundle);
  if (targetPlatform === BACKUP_PLATFORMS.MOBILE && cipher === DATABASE_CIPHERS.SQLCIPHER) {
    const from = producerPlatformOf(bundle);
    return {
      ok: false,
      reason: 'encrypted-database-unsupported',
      message: from === BACKUP_PLATFORMS.DESKTOP
        ? 'This backup was made on a computer, and its vault database is encrypted in a '
          + 'way this phone cannot open. Restore it on a computer instead. A backup made '
          + 'on a phone can be restored here, and on a computer too.'
        : 'This backup holds an encrypted vault database that this phone cannot open. '
          + 'Restore it on a computer instead.'
    };
  }
  return { ok: true };
}

/**
 * The same decision, as a throw. Call it BEFORE anything destructive — the
 * whole point is that the existing vault is still intact when it refuses.
 *
 * @param {object} bundle
 * @param {string} targetPlatform
 * @param {object} [adapter]
 */
function assertRestorableOn(bundle, targetPlatform, adapter = null) {
  const verdict = canRestoreDatabaseOn(bundle, targetPlatform, adapter);
  if (!verdict.ok) {
    const error = new Error(verdict.message);
    error.code = verdict.reason;
    throw error;
  }
}


/* ─── Serialisation: keeping a whole vault out of one JavaScript string ─────

   A bundle used to travel as `JSON.stringify(bundle)`, with every file's bytes
   base64-encoded INSIDE that JSON. V8 caps a single string at 536,870,888
   bytes and base64 costs 4/3 of what it encodes, so a vault holding more than
   about 400 MB of files could not be backed up at all: "Create Backup" threw
   `RangeError: Invalid string length`. Restore hit the same wall independently,
   which is the worse half — a backup you can write and cannot read is not a
   backup.

   Bundle v2 keeps the metadata as JSON and moves the file bytes OUT of it:

     "PSBK2\n"                        6-byte magic
     uint32 big-endian                header length
     header JSON (utf8)               the bundle, minus files[].contentBase64
     raw bytes                        each manifest file in order, concatenated

   No single string holds more than the header, and base64 disappears from the
   container, so a v2 archive is about 25% smaller.

   It does NOT remove the ceiling on its own, and an earlier version of this
   comment wrongly said it did. The envelope still base64-encodes the
   ciphertext and JSON.stringify's itself, so the archive passes through one
   string regardless: v2 raises the limit from roughly 290 MB of vault content
   to roughly 390 MB. Removing it means making the .psbak container binary
   too. Until then the writer stays on v1 and a size guard refuses honestly.

   v1 is still read, forever. The magic is what tells them apart: a v1 bundle is
   JSON and begins with `{`. */

const BUNDLE_V2_MAGIC = 'PSBK2\n';
const BUNDLE_V2_HEADER_LENGTH_BYTES = 4;

/** The bundle object with file contents stripped — what the v2 header holds. */
function bundleHeaderOf(bundle) {
  const header = { ...bundle };
  delete header.files;
  return header;
}

/**
 * A bundle as the bytes that go into the envelope.
 *
 * Emits v2. Files are written in MANIFEST order, not in `bundle.files` order,
 * so the reader can walk the manifest and slice — the manifest is the list the
 * integrity check already trusts, and making it authoritative here means the
 * two cannot disagree about what is in the archive.
 */
function serializeBundle(bundle, adapter, options = {}) {
  assertAdapter(adapter);
  // Defaults to CURRENT_BUNDLE_VERSION, which is v1 today — see the long note
  // in format.js for why the v2 reader ships ahead of the v2 writer. `version`
  // is the seam the eventual switch flips, and what lets the v2 reader be
  // tested against real v2 bytes in the meantime.
  const version = Number(options.version || CURRENT_BUNDLE_VERSION);
  if (version !== BUNDLE_VERSION_V2) {
    return adapter.utf8ToBytes(JSON.stringify(bundle));
  }
  const manifestFiles = Array.isArray(bundle?.manifest?.files) ? bundle.manifest.files : [];
  const contents = new Map();
  for (const file of Array.isArray(bundle?.files) ? bundle.files : []) {
    contents.set(normalizeRelativePath(file?.relativePath), file?.contentBase64);
  }

  const parts = [];
  let payloadBytes = 0;
  for (const entry of manifestFiles) {
    const relativePath = normalizeRelativePath(entry?.relativePath);
    const contentBase64 = contents.get(relativePath);
    if (contentBase64 === undefined) {
      throw new Error(`Backup is missing the contents of "${relativePath}".`);
    }
    const bytes = adapter.fromBase64(contentBase64);
    parts.push(bytes);
    payloadBytes += bytes.length;
  }

  const headerBytes = adapter.utf8ToBytes(JSON.stringify({
    ...bundleHeaderOf(bundle),
    version: BUNDLE_VERSION_V2
  }));
  const magicBytes = adapter.utf8ToBytes(BUNDLE_V2_MAGIC);

  const out = new Uint8Array(
    magicBytes.length + BUNDLE_V2_HEADER_LENGTH_BYTES + headerBytes.length + payloadBytes
  );
  let offset = 0;
  out.set(magicBytes, offset); offset += magicBytes.length;
  // Big-endian, written by hand so this needs nothing from the adapter.
  out[offset] = (headerBytes.length >>> 24) & 0xff;
  out[offset + 1] = (headerBytes.length >>> 16) & 0xff;
  out[offset + 2] = (headerBytes.length >>> 8) & 0xff;
  out[offset + 3] = headerBytes.length & 0xff;
  offset += BUNDLE_V2_HEADER_LENGTH_BYTES;
  out.set(headerBytes, offset); offset += headerBytes.length;
  for (const bytes of parts) {
    out.set(bytes, offset); offset += bytes.length;
  }
  return out;
}

function looksLikeBundleV2(bytes, adapter) {
  if (!bytes || bytes.length < BUNDLE_V2_MAGIC.length) return false;
  return adapter.bytesToUtf8(bytes.subarray(0, BUNDLE_V2_MAGIC.length)) === BUNDLE_V2_MAGIC;
}

/**
 * Bytes back into a bundle object, in either format.
 *
 * The returned shape is identical for v1 and v2 — including
 * `files[].contentBase64` — so nothing downstream has to know which it read.
 */
function deserializeBundle(bytes, adapter) {
  assertAdapter(adapter);
  if (!looksLikeBundleV2(bytes, adapter)) {
    // v1: the whole thing is JSON. Still read forever; only the ceiling is new.
    return JSON.parse(adapter.bytesToUtf8(bytes));
  }

  let offset = BUNDLE_V2_MAGIC.length;
  if (bytes.length < offset + BUNDLE_V2_HEADER_LENGTH_BYTES) {
    throw new Error('This backup is truncated and could not be read.');
  }
  const headerLength = (bytes[offset] << 24 >>> 0)
    + (bytes[offset + 1] << 16)
    + (bytes[offset + 2] << 8)
    + bytes[offset + 3];
  offset += BUNDLE_V2_HEADER_LENGTH_BYTES;
  if (headerLength <= 0 || bytes.length < offset + headerLength) {
    throw new Error('This backup is truncated and could not be read.');
  }

  let header;
  try {
    header = JSON.parse(adapter.bytesToUtf8(bytes.subarray(offset, offset + headerLength)));
  } catch {
    throw new Error('This backup could not be read.');
  }
  offset += headerLength;

  const manifestFiles = Array.isArray(header?.manifest?.files) ? header.manifest.files : [];
  const files = [];
  for (const entry of manifestFiles) {
    const sizeBytes = Number(entry?.sizeBytes);
    if (!Number.isFinite(sizeBytes) || sizeBytes < 0 || offset + sizeBytes > bytes.length) {
      throw new Error('This backup is truncated and could not be read.');
    }
    files.push({
      relativePath: entry?.relativePath,
      contentBase64: adapter.toBase64(bytes.subarray(offset, offset + sizeBytes))
    });
    offset += sizeBytes;
  }
  return { ...header, files };
}

module.exports = {
  assembleBundle,
  serializeBundle,
  deserializeBundle,
  looksLikeBundleV2,
  verifyBundle,
  assertBundleIntact,
  databaseCipherOf,
  observedDatabaseCipher,
  configureBundle,
  producerPlatformOf,
  canRestoreDatabaseOn,
  assertRestorableOn,
  normalizeRelativePath
};
