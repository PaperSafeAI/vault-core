// Lint for @papersafeailabs/vault-core. Correctness rules only; formatting is left
// to the code as written.
import js from '@eslint/js';
import globals from 'globals';

// What every platform the core runs on provides (Node, React Native, the
// browser extension): no Node built-ins, no DOM.
const portable = {
  TextEncoder: 'readonly', TextDecoder: 'readonly', btoa: 'readonly', atob: 'readonly',
  console: 'readonly', globalThis: 'readonly',
};

const strict = {
  'no-unused-vars': ['error', { args: 'after-used', argsIgnorePattern: '^_', caughtErrors: 'none' }],
  // `x != null` (null or undefined) is the one loose comparison allowed.
  eqeqeq: ['error', 'always', { null: 'ignore' }],
  'no-var': 'error',
  'prefer-const': 'error',
  'no-implicit-globals': 'error',
  'no-new-func': 'error',
  'no-eval': 'error',
};

export default [
  { ignores: ['node_modules/', 'types/', 'test-vectors/'] },
  js.configs.recommended,
  {
    files: ['src/**/*.js'],
    languageOptions: { sourceType: 'commonjs', ecmaVersion: 2022, globals: { ...portable, require: 'readonly', module: 'writable' } },
    rules: strict,
  },
  {
    // The browser bridge runs in the extension's service worker too: WebCrypto only.
    files: ['src/**/*.mjs'],
    languageOptions: { sourceType: 'module', ecmaVersion: 2022, globals: { ...portable, crypto: 'readonly' } },
    rules: strict,
  },
  {
    // Node-only: the Node adapter, the CLI, the build scripts.
    files: ['src/node/**/*.js', 'bin/**/*.js', 'scripts/**/*.js'],
    languageOptions: { sourceType: 'commonjs', ecmaVersion: 2022, globals: globals.node },
    rules: strict,
  },
  {
    files: ['scripts/**/*.mjs'],
    languageOptions: { sourceType: 'module', ecmaVersion: 2022, globals: globals.node },
    rules: strict,
  },
  {
    files: ['test/**/*.js', '*.mjs', '*.config.mjs'],
    languageOptions: { sourceType: 'module', ecmaVersion: 2022, globals: globals.node },
    rules: { ...strict, 'no-unused-vars': ['error', { args: 'none', caughtErrors: 'none', varsIgnorePattern: '^_' }] },
  },
];
