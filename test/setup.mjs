// Neutral record types and bundle settings standing in for an app's
// (scripts/example-record-types.js).
import * as aad from '../src/crypto/aad.js';
import * as bundle from '../src/backup/bundle.js';
import examples from '../scripts/example-record-types.js';

examples.registerExamples(aad, bundle);
