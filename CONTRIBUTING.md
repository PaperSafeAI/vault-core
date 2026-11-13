# Contributing

Thank you for looking. This package is the encryption and key handling of the
PaperSafeAI apps, so changes are reviewed slowly and carefully.

## Before you start

- **Security problems:** do not open an issue or pull request. Follow
  [SECURITY.md](SECURITY.md).
- **Format changes** (anything that changes bytes on disk or on the wire, a key
  label, a parameter) need an issue first. They must stay readable by apps
  already in use, and they change [SPEC.md](SPEC.md) and the test vectors in the
  same pull request.
- Small fixes, tests, documentation and clearer errors are welcome directly.

## Working on it

Node 22 or later.

```sh
npm ci
npm run lint
npm test               # unit, fuzz, independent vector reader
npm run vectors:check  # fails if any format changed
npm run types          # regenerate types/ after changing JSDoc in src/
npm run types:check
```

Rules the reviewers will check:

- Only the platform's primitives: no new cryptographic algorithm written here,
  and no new runtime dependency.
- Modules get their crypto from the adapter they are handed; Node built-ins
  only in `src/node/`, `bin/` and `scripts/` (ESLint enforces this).
- Every new input that crosses a boundary is rejected with an error when it is
  malformed, and has a test (a fuzz case if it is parsed).
- Secrets compare in constant time, and keys are overwritten when done.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a contributor licence agreement. By adding a `Signed-off-by` line to
each commit you certify that you wrote the change, or otherwise have the right
to submit it under this project's licence (Apache 2.0):

```sh
git commit -s -m "Explain what and why"
```

This adds `Signed-off-by: Your Name <you@example.com>`, which must match the
commit's author. CI fails a pull request with an unsigned commit; fix it with
`git rebase --signoff main` and force-push your branch.

GitHub's authenticated Dependabot account is the only exception to exact address
matching: its expected noreply commit author may use the bot's
`support@github.com` signoff. The PR author and GitHub's commit-author identity
must both be the official bot (account ID 49699333), and GitHub must report a
valid verified signature for that exact commit. Missing evidence or API failures
reject the exception. This does not exempt unsigned human commits in bot PRs.
CI runs the checker from the base branch, not the contributor's proposed code.

## How changes reach a release

Pull requests are reviewed and merged here, on `main`. A maintainer releases
with `npm run release -- <version>` (after writing the CHANGELOG section), which
tags `v<version>`; the Release workflow then checks, scans and publishes to npm
with provenance.

## Name and logo

The licence covers the code. It does not grant use of the PaperSafeAI name or
logo; see [NOTICE](NOTICE).

Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [GOVERNANCE.md](GOVERNANCE.md).
