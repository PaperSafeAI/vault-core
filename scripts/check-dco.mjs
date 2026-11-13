import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';

const isDependabot = user => user?.login === 'dependabot[bot]' && user?.id === 49699333 && user?.type === 'Bot';
const BOT_AUTHOR = 'dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>';
const BOT_SIGNOFF = 'dependabot[bot] <support@github.com>';

export async function checkCommit(commit, context, getVerifiedCommit) {
  if (commit.signoffs.includes(commit.author)) return true;
  if (!isDependabot(context?.pullRequestAuthor) || commit.author !== BOT_AUTHOR || !commit.signoffs.includes(BOT_SIGNOFF)) return false;
  try {
    const evidence = await getVerifiedCommit(commit.sha);
    return evidence?.sha === commit.sha && isDependabot(evidence.author)
      && evidence.commit?.verification?.verified === true && evidence.commit.verification.reason === 'valid';
  } catch {
    // Missing authentication, API failures and unverifiable commits never grant an exemption.
    return false;
  }
}

export async function checkRange({ base, head, context, getVerifiedCommit, git = (...args) => execFileSync('git', args, { encoding: 'utf8' }) }) {
  if (![base, head].every(sha => /^[a-f0-9]{40}$/.test(sha))) throw Error('Expected full base and head commit SHAs');
  const commits = git('rev-list', '--no-merges', `${base}..${head}`).trim().split('\n').filter(Boolean);
  const failures = [];
  for (const sha of commits) {
    const author = git('show', '-s', '--format=%an <%ae>', sha).trim();
    const signoffs = git('show', '-s', '--format=%(trailers:key=Signed-off-by,valueonly)', sha).trim().split('\n').map(s => s.trim());
    if (!await checkCommit({ sha, author, signoffs }, context, getVerifiedCommit)) failures.push(sha);
  }
  return { checked: commits.length, failures };
}

export function githubCommitReader({ repository, token, fetchImpl = fetch }) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository || '') || !token) throw Error('GitHub repository and read-only token required');
  return async sha => {
    if (!/^[a-f0-9]{40}$/.test(sha)) throw Error('Invalid commit SHA');
    const response = await fetchImpl(`https://api.github.com/repos/${repository}/commits/${sha}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
      signal: AbortSignal.timeout(15000), redirect: 'error',
    });
    if (!response.ok) throw Error(`GitHub commit verification unavailable (${response.status})`);
    return response.json();
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
    if (!event.pull_request) throw Error('DCO check requires a pull request event');
    const result = await checkRange({
      base: event.pull_request.base.sha, head: event.pull_request.head.sha,
      context: { pullRequestAuthor: event.pull_request.user },
      getVerifiedCommit: githubCommitReader({ repository: process.env.GITHUB_REPOSITORY, token: process.env.GITHUB_TOKEN }),
    });
    console.log(`DCO: checked ${result.checked} commits; ${result.failures.length} failed`);
    for (const sha of result.failures) console.error(`DCO failed for ${sha}: author signoff missing or Dependabot verification unavailable`);
    process.exitCode = result.failures.length ? 1 : 0;
  } catch {
    console.error('DCO check failed: invalid context, unavailable Git history or verification configuration');
    process.exitCode = 1;
  }
}
