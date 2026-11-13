# Security policy

## Reporting a vulnerability

Email **security@papersafeai.com** with a description, the affected version and,
if you can, steps to reproduce. Please don't open a public issue or pull
request for a security problem until it is fixed.

What to expect:

- an acknowledgement within 3 working days;
- an assessment, and a planned fix date for confirmed issues, within 10 working days;
- credit in the release notes if you'd like it.

Please give us a reasonable time to ship a fix before you disclose, and don't
access data that isn't yours while you test.

## In scope

Everything in this repository: key derivation, the encryption formats, backup
sealing and opening, sync record sealing, and the `papersafe-open-backup` tool.
Weaknesses in the formats themselves (described in `SPEC.md`) are in scope even
if the code implements them faithfully.

## Supported versions

The latest minor release of the current major version receives security fixes.

## Secret-scanner fixture policy

`npm run security:scan` runs pinned gitleaks over all reachable Git refs and
then proves that new secret-like values in source, tests and vectors still
fail scanning. Set `GITLEAKS_BIN` to a local scanner path if needed.

`.gitleaks.toml` suppresses only exact reviewed synthetic secret values AND
only their three fixture paths: generated vault vectors, bridge test vectors
and the auth-record test's synthetic recovery key. These keys protect no real
data; generators document their test-only origin. No entire directory or rule
is excluded. Newly generated canaries at those exact paths must still fail.
Changes to allowed values or paths require review.

The release and normal CI workflows use the same checksum-verified scanner
installation and the same scan/canary command. Scan reports are temporary and
redacted; never paste production secret values into a report or issue.

## Standalone CLI platform boundary

Native Windows extraction is refused before the backup or passphrase is read.
Until Windows ACL creation/verification is implemented and tested, the CLI
cannot promise owner-only output there. macOS/Linux output uses a new POSIX
0700 directory and exclusive 0600 files. Use a private POSIX filesystem, not
a filesystem that ignores Unix permissions. Core encryption adapters and the
PaperSafeAI app have their own platform lifecycles; this limit is CLI-specific.
