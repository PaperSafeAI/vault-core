'use strict';

/**
 * @papersafeailabs/vault-core — every format PaperSafeAI uses to keep your data
 * encrypted on your own devices. Platform-free: each function is handed its
 * crypto primitives (see src/node/ for the Node ones). SPEC.md describes the
 * formats; test-vectors/ lets anyone check an independent implementation.
 */
module.exports = {
  VERSION: require('./version').VERSION,
  vaultCipher: require('./crypto/vault-cipher'),
  documentKey: require('./crypto/document-key'),
  dbKey: require('./crypto/db-key'),
  kdf: require('./kdf/vault-kdf'),
  vaultUnlock: require('./kdf/auth-record'),
  backup: require('./backup'),
  catalogKeys: require('./sync/catalog/keys'),
  catalogSeal: require('./sync/catalog/seal'),
  canonicalJson: require('./sync/catalog/canonical-json'),
  aad: require('./crypto/aad'),
  pairingTransport: require('./pairing/transport'),
  responseBinding: require('./pairing/response-binding')
};
