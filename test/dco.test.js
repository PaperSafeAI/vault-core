import { describe, it, expect } from 'vitest';
import { checkCommit } from '../scripts/check-dco.mjs';

const identity = { login: 'dependabot[bot]', id: 49699333, type: 'Bot' };
const sha = 'a'.repeat(40);
const bot = { sha, author: 'dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>', signoffs: ['dependabot[bot] <support@github.com>'] };
const context = { pullRequestAuthor: identity };
const verified = { sha, author: identity, commit: { verification: { verified: true, reason: 'valid' } } };

describe('DCO policy', () => {
  it('preserves exact human signoffs without calling GitHub', async () => {
    expect(await checkCommit({ sha, author: 'Contributor <dev@example.org>', signoffs: ['Contributor <dev@example.org>'] }, {}, () => { throw Error('unexpected lookup'); })).toBe(true);
    expect(await checkCommit({ sha, author: 'Contributor <dev@example.org>', signoffs: [] }, context, async () => verified)).toBe(false);
  });
  it('accepts the signed GitHub Dependabot identity mismatch', async () => {
    expect(await checkCommit(bot, context, async () => verified)).toBe(true);
  });
  it.each([
    ['human PR', { pullRequestAuthor: { ...identity, login: 'someone', id: 1, type: 'User' } }, verified],
    ['lookalike bot', { pullRequestAuthor: { ...identity, id: 1 } }, verified],
    ['unsigned commit', context, { ...verified, commit: { verification: { verified: false, reason: 'unsigned' } } }],
    ['wrong commit', context, { ...verified, sha: 'b'.repeat(40) }],
    ['wrong API author', context, { ...verified, author: { ...identity, id: 1 } }],
    ['missing verification', context, { ...verified, commit: {} }],
  ])('rejects %s', async (_name, ctx, evidence) => {
    expect(await checkCommit(bot, ctx, async () => evidence)).toBe(false);
  });
  it('rejects forged local author and unexpected bot signoffs', async () => {
    expect(await checkCommit({ ...bot, author: 'Attacker <evil@example.org>' }, context, async () => verified)).toBe(false);
    expect(await checkCommit({ ...bot, signoffs: ['dependabot[bot] <evil@example.org>'] }, context, async () => verified)).toBe(false);
  });
  it('fails closed on unavailable GitHub evidence', async () => {
    expect(await checkCommit(bot, context, async () => { throw Error('offline'); })).toBe(false);
  });
});

// Exercise real Git history, not only the policy's in-memory representation.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { checkRange, githubCommitReader } from '../scripts/check-dco.mjs';

it('checks every non-merge commit and rejects an unsigned human within a bot PR', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'vault-dco-'));
  const git = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' } });
  try {
    git('init', '-q');
    git('config', 'user.name', 'Test Contributor');
    git('config', 'user.email', 'test@example.org');
    git('config', 'commit.gpgsign', 'false');
    git('commit', '--allow-empty', '-qm', 'base');
    const base = git('rev-parse', 'HEAD').trim();
    git('commit', '--allow-empty', '-qm', 'signed human\n\nSigned-off-by: Test Contributor <test@example.org>');
    git('commit', '--allow-empty', '--author', bot.author, '-qm', `bot update\n\nSigned-off-by: ${bot.signoffs[0]}`);
    const botSha = git('rev-parse', 'HEAD').trim();
    git('commit', '--allow-empty', '-qm', 'unsigned human');
    const head = git('rev-parse', 'HEAD').trim();
    const requested = [];
    const result = await checkRange({ base, head, context, git, getVerifiedCommit: async s => { requested.push(s); return { ...verified, sha: s }; } });
    expect(result).toEqual({ checked: 3, failures: [head] });
    expect(requested).toEqual([botSha]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

it('rejects malformed Git refs before invoking Git', async () => {
  await expect(checkRange({ base: '--all', head: sha, git: () => { throw Error('must not execute'); } })).rejects.toThrow('full base and head');
});

it('uses the repository commit API and rejects API failures', async () => {
  const calls = [];
  const read = githubCommitReader({ repository: 'PaperSafeAI/vault-core', token: 'test-token', fetchImpl: async (...args) => { calls.push(args); return { ok: true, json: async () => verified }; } });
  expect(await read(sha)).toEqual(verified);
  expect(calls[0][0]).toBe(`https://api.github.com/repos/PaperSafeAI/vault-core/commits/${sha}`);
  expect(calls[0][1].redirect).toBe('error');
  const failing = githubCommitReader({ repository: 'PaperSafeAI/vault-core', token: 'test-token', fetchImpl: async () => ({ ok: false, status: 403 }) });
  expect(await checkCommit(bot, context, failing)).toBe(false);
});
