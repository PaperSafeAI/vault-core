/** The published TypeScript declarations are generated from src/'s JSDoc and must match it. */
import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

describe('types/', () => {
  it('is what src/ generates today', () => {
    const script = path.join(here, '..', 'scripts', 'build-types.js');
    expect(() => execFileSync(process.execPath, [script, '--check'], { stdio: 'pipe' })).not.toThrow();
  }, 60_000);
});
