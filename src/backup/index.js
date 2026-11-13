'use strict';

/**
 * The backup format, in one place, for every platform.
 *
 * Desktop, iOS and Android all produce and consume `.psbak` files. Before this
 * module there was one implementation on the desktop and an import-only reader
 * on the phone, which is the shape that eventually ships two formats calling
 * themselves one — and finds out years later, when a user restores.
 *
 * Everything that decides what a backup IS lives here: the versions, the
 * envelope, the manifest, the integrity rules, and every reason to refuse a
 * file. What each platform supplies is only the primitives underneath — see
 * ./adapter.js.
 *
 * Typical use:
 *
 *   const bundle   = assembleBundle({ files, dbKeyHex, databaseCipher }, adapter);
 *   const envelope = await sealBundle(bundle, passphrase, adapter);
 *   write(JSON.stringify(envelope));
 *
 *   const envelope = parseEnvelope(read());
 *   const bundle   = await openEnvelope(envelope, passphrase, adapter);
 *   assertBundleIntact(bundle, adapter);   // BEFORE touching the live vault
 */

const format = require('./format');
const adapter = require('./adapter');
const bundle = require('./bundle');
const envelope = require('./envelope');

module.exports = {
  ...format,
  ...adapter,
  ...bundle,
  ...envelope
};
