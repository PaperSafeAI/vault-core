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
export function assembleBundle(args: {
    files: Array<{
        relativePath: string;
        bytes: Uint8Array;
    }>;
    dbKeyHex?: string | null;
    databaseCipher?: string;
    platform?: string;
    createdAt?: string;
    schemaVersion?: number;
}, adapter: object): {
    version: number;
    format: string;
    createdAt: any;
    manifest: {
        files: {
            relativePath: string;
            sizeBytes: number;
            sha256: any;
        }[];
        schemaVersion?: number;
        version: number;
        createdAt: any;
        fileCount: number;
        totalBytes: number;
    };
    files: {
        relativePath: string;
        contentBase64: any;
    }[];
    /**
     * Which app wrote this, for the restoring side to quote back when it has
     * to refuse. Additive: a bundle written before this existed simply has no
     * `producer`, and producerPlatformOf reads that as 'unknown' rather than
     * treating an older backup as suspect.
     */
    producer: {
        platform: string;
    };
    dbKeyHex: string;
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
        cipher: string;
    };
};
/**
 * A bundle as the bytes that go into the envelope.
 *
 * Emits v2. Files are written in MANIFEST order, not in `bundle.files` order,
 * so the reader can walk the manifest and slice — the manifest is the list the
 * integrity check already trusts, and making it authoritative here means the
 * two cannot disagree about what is in the archive.
 */
export function serializeBundle(bundle: any, adapter: any, options?: {}): any;
/**
 * Bytes back into a bundle object, in either format.
 *
 * The returned shape is identical for v1 and v2 — including
 * `files[].contentBase64` — so nothing downstream has to know which it read.
 */
export function deserializeBundle(bytes: any, adapter: any): any;
export function looksLikeBundleV2(bytes: any, adapter: any): boolean;
/**
 * Check a bundle before anything is written to disk.
 *
 * Restore is destructive — it replaces a vault — so every reason to refuse has
 * to be found BEFORE the existing one is touched, not partway through.
 */
export function verifyBundle(bundle: any, adapter: any): {
    ok: boolean;
    problems: string[];
    unlisted: any[];
    fileCount: any;
    totalBytes: number;
    createdAt: any;
    databaseCipher: any;
};
/** Throwing form, for callers about to overwrite something. */
export function assertBundleIntact(bundle: any, adapter: any): {
    ok: boolean;
    problems: string[];
    unlisted: any[];
    fileCount: any;
    totalBytes: number;
    createdAt: any;
    databaseCipher: any;
};
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
export function databaseCipherOf(bundle: any): any;
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
export function observedDatabaseCipher(bundle: object, adapter: object): string | null;
/**
 * App-specific bundle settings: `databaseEntry`, the bundle-relative path of
 * the database file.
 *
 * @param {{ databaseEntry?: string | null }} [options]
 */
export function configureBundle({ databaseEntry: entry }?: {
    databaseEntry?: string | null;
}): void;
/** Which app wrote this bundle. 'unknown' for one written before the field. */
export function producerPlatformOf(bundle: any): any;
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
export function canRestoreDatabaseOn(bundle: object, targetPlatform: string, adapter?: object): {
    ok: true;
} | {
    ok: false;
    reason: string;
    message: string;
};
/**
 * The same decision, as a throw. Call it BEFORE anything destructive — the
 * whole point is that the existing vault is still intact when it refuses.
 *
 * @param {object} bundle
 * @param {string} targetPlatform
 * @param {object} [adapter]
 */
export function assertRestorableOn(bundle: object, targetPlatform: string, adapter?: object): void;
/**
 * Reject any path that could escape the restore directory.
 *
 * A backup is an untrusted file that a user may have received from anywhere,
 * and its paths are used to write to disk. `../../.ssh/authorized_keys` inside
 * an archive is the whole attack, and it costs one line to make impossible.
 */
export function normalizeRelativePath(value: any): string;
