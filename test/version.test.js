import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { VERSION } = require('../src/version');
const core = require('../src');
const pkg = require('../package.json');

describe('VERSION', () => {
  it('equals package.json version, so the apps report the release they bundle', () => {
    expect(VERSION).toBe(pkg.version);
    expect(core.VERSION).toBe(pkg.version);
  });
});
