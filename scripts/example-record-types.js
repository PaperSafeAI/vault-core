'use strict';

/**
 * Example record types and bundle settings for the package's own tests and
 * test vectors. An app registers its own (registerRecordTypes, configureBundle);
 * these stand in for them with neutral names.
 *
 *   catalogue-v1  record, other_record (live); log_entry, other_log_entry
 *                 (bound to a generation)
 *   vault-v3      example_column, other_column (encrypted columns)
 *   bundle        the database at data/vault.db
 *
 * `registerExamples(aad, bundle)` is called by the test setup (test/setup.mjs)
 * and the vector generator with the modules they load.
 */
function registerExamples(aad, bundle) {
  aad.registerRecordTypes(aad.COMPONENT_CATALOGUE, {
    record: {},
    other_record: {},
    log_entry: { generation: true },
    other_log_entry: { generation: true },
  });
  aad.registerRecordTypes(aad.COMPONENT_VAULT, {
    example_column: {},
    other_column: {},
  });
  bundle.configureBundle({ databaseEntry: 'data/vault.db' });
}

module.exports = { registerExamples };
