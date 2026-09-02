# Security policy

The security design (least-privilege remote-to-remote transfers, hardening
against hostile filesystems, and release integrity) is described in
[docs/security.md](docs/security.md); the factual threat inventory compared
with rsync 3.5.0 is [docs/threat-inventory.md](docs/threat-inventory.md).
This file covers supported versions and how to report a vulnerability.

## Supported versions

Security fixes are made on `master` and included in the next release. The
current release is supported; older releases may not receive fixes.

## Reporting a vulnerability

Please report suspected vulnerabilities through
[GitHub's private vulnerability reporting form](https://github.com/greaber/syq/security/advisories/new),
not through a public issue.

Include the affected version or commit, the expected impact, and enough detail
to reproduce the problem with disposable test data. Do not include credentials,
private keys, or other people's data.

We will acknowledge the report as soon as practical and coordinate a fix and
disclosure with you. Please allow time for that process before publishing the
details.
