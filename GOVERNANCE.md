# Maintainers and decisions

PaperSafeAI maintains vault-core. Contact security@papersafeai.com; use private
reporting for vulnerabilities or conduct concerns, and public issues for
ordinary bugs and proposals. No private vault, password or live key is needed
in a public report. See CONTRIBUTING.md and SECURITY.md.

At least two trusted maintainers should retain administrative access. Require
2FA for privileged accounts. Changes need a maintainer review, passing CI and
DCO sign-off; changes to formats also update SPEC, declarations and vectors.
An author should not approve their own substantive change. Security fixes may
be coordinated privately before a reviewed public patch/advisory is released.

Maintainers own triage, response promises in SECURITY.md, dependency updates,
releases and succession. Each security report needs a primary and backup
maintainer assigned privately; do not publish reporter identities without consent.

Release tags must identify reviewed main commits. npm publishing credentials
are least privilege and separate from contribution workflows. Release notes
state compatibility changes, limitations and security fixes. No claim of an
independent audit is made until a real audit report is published.

Maintainer clones must deliberately configure the intended public identity.
The project's company commits use security@papersafeai.com as author name and
email. This does not hide GitHub account handles. Contributors may use a
verified GitHub noreply address; preserve their legitimate attribution and DCO
certification rather than replacing another person's sign-off.
