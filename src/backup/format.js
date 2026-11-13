'use strict';

/**
 * The backup format contract, shared by every platform.
 *
 * A `.psbak` is a single UTF-8 JSON object. There is no binary header, so a
 * human can open one and see what it claims to be — which matters for a file
 * users are told to keep for years and may find again on a drive long after
 * this app is gone.
 *
 * Three version numbers move independently, because they describe different
 * things and change for different reasons:
 *
 *   envelope  how the payload is encrypted (KDF, cipher, AAD)
 *   bundle    the shape of the decrypted payload
 *   manifest  what is recorded about the files inside it
 *
 * RULES, the same as for every stored format in the apps:
 *  - Additive only. Never renumber an existing constant.
 *  - Readers REFUSE anything newer than their MAX, and PRESERVE unknown fields
 *    on anything at or below it.
 *  - To change KDF cost, add a new scheme id. Never mutate an existing one — a
 *    backup in the field records the scheme it was written with, and
 *    reinterpreting that record silently derives the wrong key.
 */

const ENVELOPE_FORMAT_V2 = 'papersafe-encrypted-backup-v2';

/**
 * The most a backup may expand to when it is decompressed (8 GiB). Enforced
 * while decompressing, so a small crafted archive cannot make the reader
 * allocate without bound before anything else is checked; the archive cannot
 * raise it. Above the largest real vault: the whole bundle is held in memory
 * either way.
 */
const MAX_EXPANDED_BACKUP_BYTES = 8 * 1024 * 1024 * 1024;
const ENVELOPE_FORMAT_V3 = 'papersafe-encrypted-backup-v3';
const BUNDLE_FORMAT = 'papersafe-archive-v1';

/** Envelope v3 is what this build WRITES; v2 is still read, and always will be. */
const CURRENT_ENVELOPE_VERSION = 3;
const MAX_SUPPORTED_ENVELOPE_VERSION = 3;
/* v2 moves the file bytes out of the JSON and into a raw payload after it.
   READ support ships now; WRITING it does not, and both halves of that are
   deliberate.

   Why the reader ships: a v2 archive must be openable by the time anything
   produces one, and a build that can already read it is what makes the
   eventual switch a one-line change instead of a migration.

   Why the writer does not, yet:

     1. It would not have achieved what it was for. The envelope still
        base64-encodes the ciphertext and `JSON.stringify`s the whole
        envelope (envelope.js, backup-service.js), so the archive STILL
        passes through one JavaScript string. v2 raises the ceiling from
        roughly 290 MB of vault content to roughly 390 MB; it does not
        remove it. Removing it means making the .psbak itself binary, which
        is a second, larger format change.

     2. Forward compatibility bites the user, not us. A shipped phone build
        caps at bundle v1 — and its reader calls JSON.parse BEFORE the
        version gate, so a v2 archive fails as "this backup decrypted but its
        contents could not be read". Desktop and the App Store ship on
        independent cadences, so between a desktop release writing v2 and the
        matching phone build going live, every desktop backup would tell the
        user their file is corrupt at the moment they most need it to work.

   So: read v2, write v1, and switch the writer once the .psbak container is
   binary AND a v2-capable phone build is live. */
const BUNDLE_VERSION_V1 = 1;
const BUNDLE_VERSION_V2 = 2;
const MAX_SUPPORTED_BUNDLE_VERSION = BUNDLE_VERSION_V2;
const MAX_SUPPORTED_MANIFEST_VERSION = 3;
const CURRENT_BUNDLE_VERSION = BUNDLE_VERSION_V1;
const CURRENT_MANIFEST_VERSION = 3;

/**
 * Key-derivation schemes a backup may record.
 *
 * v2 archives use scrypt. React Native has no scrypt, and the cost cannot be
 * dialled down to a pure-JS implementation without dropping below the tamper
 * floor below — so v3 moves to Argon2id, which BOTH platforms already ship
 * (`argon2` on desktop, `react-native-argon2` on mobile) and which the vault's
 * own auth record already uses.
 *
 * `minimum` is the tamper floor. A crafted archive claiming N=2 or
 * memoryCost=8 would make the derivation trivial and turn an offline
 * brute-force of the passphrase into seconds of work. The header is attacker-
 * controlled data, so its cost parameters are checked, never trusted.
 *
 * `maximum` is the ceiling, for the opposite attack: an archive claiming
 * memoryCost of several gigabytes, or a million passes, makes the reader hang
 * or run out of memory before the passphrase is ever tried — on a phone, the
 * app is killed. The ceilings sit well above anything a PaperSafeAI build has
 * written (4x the current memory, over 3x the passes) and within what a phone
 * can afford, so raising the default later still opens on every device.
 * `keyLength` is fixed at 32: the key is an AES-256 key and nothing else.
 */
const KDF_SCHEMES = {
  scrypt: {
    name: 'scrypt',
    write: false, // read-only: kept forever for v2 archives, never written again
    defaults: { N: 65536, r: 8, p: 1, keyLength: 32 },
    minimum: { N: 16384 },
    // 128 * N * r bytes: at most 256 MiB.
    maximum: { N: 262144, r: 8, p: 4, keyLength: 32 }
  },
  argon2id: {
    name: 'argon2id',
    write: true,
    // Matches ARGON2_PARAMS / KDF_SCHEMES['argon2id-v1'] in the vault's auth
    // record, so a device that can unlock a vault can afford to open a backup.
    defaults: { timeCost: 3, memoryCost: 65536, parallelism: 1, keyLength: 32 },
    minimum: { timeCost: 2, memoryCost: 32768 },
    // memoryCost is KiB: at most 256 MiB.
    maximum: { timeCost: 10, memoryCost: 262144, parallelism: 4, keyLength: 32 }
  }
};

const CURRENT_KDF = 'argon2id';

/** What the database inside a bundle is encrypted with, if anything. */
const DATABASE_CIPHERS = {
  /** Desktop: SQLCipher, keyed by `dbKeyHex` in the bundle. */
  SQLCIPHER: 'sqlcipher',
  /** Mobile: expo-sqlite, which has no encryption of its own. */
  NONE: 'none'
};

/**
 * Which app wrote a bundle. Recorded for the restoring side's MESSAGE, not for
 * its decision — see canRestoreDatabaseOn in bundle.js, which keys off the
 * database cipher because that is the thing that actually has to be opened.
 * A platform name in an attacker-supplied file cannot be trusted to gate
 * anything; it can only make a refusal explicable to the person reading it.
 */
const BACKUP_PLATFORMS = {
  DESKTOP: 'desktop',
  MOBILE: 'mobile',
  /** A bundle written before this field existed. */
  UNKNOWN: 'unknown'
};

const MINIMUM_PASSPHRASE_LENGTH = 10;

function assertSupportedFormatVersion(kind, version, maxSupported) {
  const safeVersion = Number(version || 0);
  if (safeVersion > maxSupported) {
    throw new Error(
      `This backup's ${kind} format (v${safeVersion}) is newer than this version `
      + `of PaperSafeAI supports (up to v${maxSupported}). Update PaperSafeAI, `
      + 'then try restoring again.'
    );
  }
}

/**
 * Check a recorded KDF descriptor against its scheme's floor.
 *
 * Every parameter comes from the file, so every parameter is attacker-supplied.
 * The failure this prevents is not a crash — it is a backup that opens fine and
 * whose passphrase can be brute-forced offline in minutes.
 */
function assertKdfCost(kdf) {
  const name = String(kdf?.name || '');
  const scheme = KDF_SCHEMES[name];
  if (!scheme) {
    throw new Error(
      `This backup uses an unknown key-derivation scheme ("${name || 'missing'}"). `
      + 'It may have been written by a newer version of PaperSafeAI, or it may be corrupt.'
    );
  }
  for (const [parameter, floor] of Object.entries(scheme.minimum)) {
    const value = Number(kdf[parameter]);
    if (!Number.isFinite(value) || value < floor) {
      throw new Error(
        `Backup archive uses weak key derivation (${name} ${parameter}=${kdf[parameter]}). `
        + `The archive may have been tampered with. Minimum acceptable: ${parameter}=${floor}.`
      );
    }
  }
  // Checked on the value the reader will actually use: an absent parameter
  // falls back to the scheme's default (see the platform adapters' deriveKey).
  for (const [parameter, ceiling] of Object.entries(scheme.maximum)) {
    const raw = kdf[parameter];
    const value = raw === undefined || raw === null || raw === '' ? scheme.defaults[parameter] : Number(raw);
    if (!Number.isInteger(value) || value < 1 || value > ceiling) {
      throw new Error(
        `Backup archive asks for more key-derivation work than any PaperSafeAI build writes `
        + `(${name} ${parameter}=${raw}). The archive may have been tampered with. `
        + `Maximum acceptable: ${parameter}=${ceiling}.`
      );
    }
  }
  return scheme;
}

/**
 * The passphrase rule.
 *
 * Ten characters is weak for something protecting an entire document vault, and
 * raising it is tempting. It is deliberately unchanged: this same function
 * gates RESTORE, so a higher floor would lock users out of backups they already
 * hold. Strength belongs in the UI at the moment of choosing, where it can
 * advise without stranding anyone.
 */
function validateBackupPassphrase(value) {
  const passphrase = String(value || '');
  if (passphrase.length < MINIMUM_PASSPHRASE_LENGTH) {
    throw new Error(`Backup passphrase must be at least ${MINIMUM_PASSPHRASE_LENGTH} characters.`);
  }
  return passphrase;
}

module.exports = {
  MAX_EXPANDED_BACKUP_BYTES,
  ENVELOPE_FORMAT_V2,
  ENVELOPE_FORMAT_V3,
  BUNDLE_FORMAT,
  CURRENT_ENVELOPE_VERSION,
  MAX_SUPPORTED_ENVELOPE_VERSION,
  BUNDLE_VERSION_V1,
  BUNDLE_VERSION_V2,
  MAX_SUPPORTED_BUNDLE_VERSION,
  MAX_SUPPORTED_MANIFEST_VERSION,
  CURRENT_BUNDLE_VERSION,
  CURRENT_MANIFEST_VERSION,
  KDF_SCHEMES,
  CURRENT_KDF,
  DATABASE_CIPHERS,
  BACKUP_PLATFORMS,
  MINIMUM_PASSPHRASE_LENGTH,
  assertSupportedFormatVersion,
  assertKdfCost,
  validateBackupPassphrase
};
