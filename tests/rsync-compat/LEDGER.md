# Upstream rsync test ledger

This file is generated from `manifest.toml` and `inventory.tsv`. Update it with:

```sh
python3 scripts/rsync-compat.py --ledger-only --update-ledger
```

Pinned rsync commit: `7c20b077c980036a19587701cec320cc88e42a4a`.
Configured command prefix: `syq`.

| Classification | Tests |
|---|---:|
| conformance | 15 |
| adapted | 21 |
| unsupported | 133 |
| out-of-scope | 182 |
| unassessed | 0 |

## Runnable behavioral tests

The baseline is the last reviewed observation, not a claim that rsync's behavior is always the desired product policy.

| Area | Test | Baseline | Product position | Provenance | Circumstances | Note |
|---|---|---|---|---|---|---|
| deletion | `delete-deep` | pass | Compatible | subset adaptation (delete-supported-subset) | platform=linux | Deep deletion, --delete-delay/--delete-after, --existing, and --ignore-existing agree; unsupported delete timing and backup cases and SYQ's intentional --max-delete policy difference are omitted. |
| end-to-end | `hands` | pass | Compatible | subset adaptation (hands-supported-subset) | platform=linux; symlinks; POSIX modes | The canonical rich-tree test covers initial copy, one-file repair, a longer destination, deletion, and explicit multiple-source mapping; only destination-root metadata is normalized because no source root was transferred. Hard-link preservation and delta debugging are omitted. |
| failure-isolation | `source-read-failure-continues` | pass | Compatible | fixture adaptation (source-read-failure-preload) of upstream source-change-size-continues | platform=linux; C compiler; LD_PRELOAD; /proc/self/fd | An external shim deterministically shrinks a source at its first positioned read. The failure remains visible, preserves the existing destination, and allows a later file to transfer; rsync's exact exit code and diagnostic wording are not required. |
| file-selection | `files-from-comments-from0` | pass | Compatible | subset adaptation (files-from-split) of upstream files-from-depth | platform=linux | Entries beginning with # or ; are ignored as rsync comments in a NUL-delimited --files-from list. |
| file-selection | `files-from-comments-line` | pass | Compatible | subset adaptation (files-from-split) of upstream files-from-depth | platform=linux | Entries beginning with # or ; are ignored as rsync comments in a line-delimited --files-from list. |
| file-selection | `files-from-depth` | pass | Compatible | subset adaptation (files-from-split) | platform=linux | Deep line- and NUL-delimited --files-from selection agree; comment handling and unsupported filter-list cases are reported separately or omitted. |
| file-selection | `files-from-path-clamp` | fail | Policy open | unmodified upstream | platform=linux | SYQ rejects parent components instead of clamping them at the source root. |
| file-selection | `size-filter` | pass | Compatible | unmodified upstream | platform=linux | Apply --min-size and --max-size throughout a deep tree. |
| hardlinks | `hardlinks-deep` | pass | Compatible | subset adaptation (hardlink-default) | platform=linux; hard links | Without -H, two cross-directory source names for one inode become independent destination files; unsupported hard-link preservation is omitted. |
| metadata | `chgrp` | pass | Compatible | unmodified upstream | platform=linux; POSIX groups; chgrp | Preserve a supplementary group with -g. |
| metadata | `chown` | pass | Compatible | subset adaptation (chown-syq-cli) | platform=linux; run-as=root; root; chown | Archive mode preserves varied numeric owners and groups on files and directories at depth; rsync-only --super and -H are removed. |
| metadata | `dir-sgid` | pass | Compatible | unmodified upstream | platform=linux; POSIX modes | Honor setgid inheritance when creating destination directories. |
| metadata | `executability` | pass | Compatible | subset adaptation (executability-default) | platform=linux; POSIX modes | Without -p, rerunning a copy leaves existing destination modes and executable bits unchanged; unsupported -E behavior is omitted. |
| metadata | `metadata-depth` | pass | Compatible | subset adaptation (metadata-supported-subset) | platform=linux; POSIX modes and mtimes | Preserve modes and mtimes throughout a deep tree; upstream's unsupported --chmod case is omitted. |
| paths | `deep-path` | pass | Compatible | subset adaptation (deep-path-local) | platform=linux; paths deeper than 64 components | Copy a 70-level local tree; the rsync-daemon half is outside SYQ's scope. |
| paths | `dest-symlinked-dir` | pass | Compatible | unmodified upstream | platform=linux; symlinks | Follow an operator-named destination symlink to a directory. |
| paths | `longdir` | pass | Compatible | subset adaptation (longdir-no-hardlinks) | platform=linux; long path components | Copy and delete within a tree containing three 175-character path components. |
| permissions | `protected-regular` | pass | Compatible | unmodified upstream | platform=linux; run-as=root; root; Linux fs.protected_regular | --inplace can update a foreign-owned file in a sticky directory when the caller has authority. |
| permissions | `search-only-destination` | pass | Compatible | unmodified upstream | platform=linux; Linux search-only directory semantics; setpriv when run as root | Traverse a searchable but unreadable destination parent. |
| publication | `inplace` | pass | Compatible | invocation adaptation (inplace-syq-cli) | platform=linux; stable inode numbers | --inplace retains the destination inode while the default atomic path replaces it. |
| quick-check | `compare` | pass | Compatible | subset adaptation (compare-supported-subset) | platform=linux; POSIX mtimes | At depth, the default size-and-mtime check skips a stealth change, -c repairs it, and an mtime change triggers the default transfer; unsupported -I, --size-only, and --modify-window cases are omitted. |
| remote | `ssh-basic` | pass | Compatible | invocation adaptation (ssh-syq-path) | platform=linux; rsync lsh test helper | Remote-shell copy and follow-up deletion using SYQ's remote executable option. |
| resume | `partial` | pass | Intentional divergence | fixture adaptation (syq-partial-layout) | platform=linux; signals; bandwidth limiting | An interrupted transfer leaves SYQ's job-scoped deterministic sidecar and a rerun completes it. |
| robustness | `change-shrink` | pass | Compatible | invocation adaptation (source-mutation-cli) | platform=linux; threads; bandwidth limiting | Continue a transfer when a source file shrinks after the source scan. |
| robustness | `change-vanish` | pass | Compatible | invocation adaptation (source-mutation-cli) | platform=linux; threads; bandwidth limiting | Continue a transfer when a source file vanishes after the source scan. |
| robustness | `growing-file` | pass | Compatible | invocation adaptation (source-mutation-cli) | platform=linux; threads; bandwidth limiting | Copy the final contents of a file that grows after the source scan. |
| robustness | `highfd-hang` | pass | Compatible | unmodified upstream | platform=linux; C compiler; soft fd limit above FD_SETSIZE | An ordinary transfer completes when the child inherits high-numbered descriptors. |
| security | `remote-shell-newline-escaping` | pass | Compatible | invocation adaptation (remote-shell-syq-cli) | platform=linux; rsync lsh test helper | A newline-bearing remote destination cannot split SYQ's quoted remote command and execute an injected shell command. |
| security | `sender-scan-dir-escape` | pass | Compatible | unmodified upstream | platform=linux; symlinks; C compiler; renameat2 | A raced source parent cannot make the copy enumerate outside the source tree. |
| security | `symlink-race-dest` | pass | Compatible | unmodified upstream | platform=linux; run-as=root; root; a second uid; symlinks | The receiver refuses an attacker-owned symlink in an operator-named absolute destination path, retains the selected directory, and continues to follow a root-owned administrative link. |
| security | `symlink-race-relative-dest` | pass | Compatible | unmodified upstream | platform=linux; run-as=root; root; a second uid; symlinks | The receiver refuses an attacker-owned symlink in an operator-named relative destination path, retains the selected directory, and continues to follow a root-owned administrative link. |
| security | `symlink-race-source` | pass | Compatible | unmodified upstream | platform=linux; symlinks; C compiler; renameat2 | A raced source parent cannot make SYQ read file contents from outside the source tree. |
| source-mapping | `duplicates` | pass | Compatible | unmodified upstream | platform=linux; symlinks | Exactly repeated source operands are scanned and copied once while retaining multi-source destination placement. |
| special-files | `nested-socket-specials` | pass | Compatible | unmodified upstream | platform=linux; Unix-domain sockets | Archive mode handles a nested socket without losing ordinary files. |
| symlinks | `links` | pass | Compatible | subset adaptation (links-preserve-subset) | platform=linux; symlinks | -l preserves both file and directory symlinks several levels deep; unsupported -L and -k cases are omitted. |
| symlinks | `symlink-ignore` | pass | Compatible | unmodified upstream | platform=linux; symlinks | Without -l/-L/-a, omit symlinks while copying referent files. |
| symlinks | `unsafe-links` | pass | Compatible | subset adaptation (unsafe-links-default) | platform=linux; symlinks | Default -a preserves both in-tree and lexically escaping symlinks without following them; unsupported copy-links variants are omitted. |
| update | `update` | pass | Compatible | subset adaptation (update-supported-subset) | platform=linux; symlinks | -u skips a newer deep destination, updates an older one, and still replaces a type mismatch. |

## Exclusion reasons

| Reason | Meaning |
|---|---|
| `rrsync` | Exercises rrsync, rsync's restricted-command wrapper, rather than the copy command's filesystem semantics. |
| `rsync-daemon` | Exercises rsync daemon configuration, modules, authentication, or daemon transport; SYQ has no rsync daemon mode. |
| `rsync-internal` | Exercises rsync's implementation, build, helper programs, or test harness rather than command-line filesystem semantics. |
| `rsync-wire` | Exercises rsync's sender/receiver protocol or a malicious/legacy rsync peer; SYQ intentionally speaks a different protocol. |
| `unsupported-acls` | Requires rsync ACL behavior, which SYQ does not implement. |
| `unsupported-alt-dest` | Requires rsync backup, link-dest, compare-dest, copy-dest, or alternate-basis behavior, which SYQ does not implement. |
| `unsupported-batch` | Requires rsync batch-file behavior, which SYQ does not implement. |
| `unsupported-filters` | Requires rsync's filter language; SYQ currently exposes gitignore-style filters instead. |
| `unsupported-hardlinks` | Requires hard-link preservation, which SYQ does not implement. |
| `unsupported-metadata` | Requires an rsync metadata option that SYQ does not implement yet. |
| `unsupported-relative` | Requires rsync --relative/-R behavior, which SYQ does not implement. |
| `unsupported-transfer-mode` | Requires an rsync transfer mode or output option that SYQ does not implement. |
| `unsupported-xattrs` | Requires extended-attribute behavior, which SYQ does not implement. |

## Unsupported user-facing features

| Test | Reason |
|---|---|
| `acl-symlink-race` | `unsupported-acls` |
| `acls` | `unsupported-acls` |
| `acls-default` | `unsupported-acls` |
| `acls-depth` | `unsupported-acls` |
| `acls-unpinnable` | `unsupported-acls` |
| `alt-dest` | `unsupported-alt-dest` |
| `alt-dest-deep` | `unsupported-alt-dest` |
| `alt-dest-symlink-race` | `unsupported-alt-dest` |
| `append` | `unsupported-transfer-mode` |
| `append-shortsum` | `unsupported-transfer-mode` |
| `atimes` | `unsupported-metadata` |
| `backup` | `unsupported-alt-dest` |
| `backup-acl-xattr-cache` | `unsupported-xattrs` |
| `backup-crossdev-copy` | `unsupported-alt-dest` |
| `backup-deep` | `unsupported-alt-dest` |
| `backup-dir-relative` | `unsupported-alt-dest` |
| `backup-dir-repeated-separator-delete` | `unsupported-alt-dest` |
| `backup-dir-symlink-race` | `unsupported-alt-dest` |
| `backup-incremental` | `unsupported-alt-dest` |
| `basis-xname-traversal` | `unsupported-alt-dest` |
| `batch-file-symlink` | `unsupported-batch` |
| `batch-mode` | `unsupported-batch` |
| `batch-only-remove-source-regression` | `unsupported-batch` |
| `chmod` | `unsupported-metadata` |
| `chmod-option` | `unsupported-metadata` |
| `chmod-setid` | `unsupported-metadata` |
| `chmod-symlink-race` | `unsupported-metadata` |
| `chmod-temp-dir` | `unsupported-metadata` |
| `chown-fake` | `unsupported-xattrs` |
| `compress-options` | `unsupported-transfer-mode` |
| `copy-dest-source-symlink` | `unsupported-alt-dest` |
| `copy-dest-symlink-readleak` | `unsupported-alt-dest` |
| `copy-xattrs-symlink-race` | `unsupported-xattrs` |
| `crtimes` | `unsupported-metadata` |
| `cvs-exclude` | `unsupported-filters` |
| `delay-updates` | `unsupported-transfer-mode` |
| `delay-updates-deep` | `unsupported-transfer-mode` |
| `delete` | `unsupported-filters` |
| `delete-missing-args-files-from` | `unsupported-transfer-mode` |
| `devices` | `unsupported-hardlinks` |
| `devices-fake` | `unsupported-xattrs` |
| `dirs` | `unsupported-transfer-mode` |
| `early-input-symlink` | `unsupported-transfer-mode` |
| `exclude` | `unsupported-filters` |
| `exclude-implied-trailing-backslash` | `unsupported-filters` |
| `exclude-lsh` | `unsupported-filters` |
| `excludefrom-symlink` | `unsupported-filters` |
| `fake-super-acl-xattr` | `unsupported-xattrs` |
| `fake-super-backup-fifo-regression` | `unsupported-xattrs` |
| `file-to-file-mkpath-dry-run` | `unsupported-transfer-mode` |
| `files-from` | `unsupported-transfer-mode` |
| `filter-depth` | `unsupported-filters` |
| `filter-leak` | `unsupported-filters` |
| `filter-merge-content-echo` | `unsupported-filters` |
| `filter-merge-recursion` | `unsupported-filters` |
| `filter-merge-symlink` | `unsupported-filters` |
| `fuzzy` | `unsupported-transfer-mode` |
| `fuzzy-basis` | `unsupported-transfer-mode` |
| `hardlinks` | `unsupported-hardlinks` |
| `itemize` | `unsupported-transfer-mode` |
| `keep-dirlinks-rule` | `unsupported-transfer-mode` |
| `keep-dirlinks-symlinked-dest` | `unsupported-transfer-mode` |
| `ki58-log-format-percent` | `unsupported-transfer-mode` |
| `ki72-safe-links-backup` | `unsupported-alt-dest` |
| `ki73-cvs-clear-list` | `unsupported-filters` |
| `link-dest-module-escape` | `unsupported-alt-dest` |
| `link-dest-pathroot` | `unsupported-alt-dest` |
| `link-dest-relative-basis` | `unsupported-alt-dest` |
| `link-dest-symlink-enotsup` | `unsupported-alt-dest` |
| `log-control-chars` | `unsupported-transfer-mode` |
| `log-file-symlink` | `unsupported-transfer-mode` |
| `macos-setgid-ordinary-mode-regression` | `unsupported-metadata` |
| `max-alloc-zero-rejected` | `unsupported-transfer-mode` |
| `merge` | `unsupported-filters` |
| `misc-coverage` | `unsupported-transfer-mode` |
| `missing` | `unsupported-relative` |
| `mkpath` | `unsupported-transfer-mode` |
| `no-implied-dirs-symlink` | `unsupported-relative` |
| `nondaemon-symlink-race` | `unsupported-alt-dest` |
| `omit-times` | `unsupported-metadata` |
| `open-noatime` | `unsupported-metadata` |
| `operator-path-backup-dir` | `unsupported-alt-dest` |
| `operator-path-backup-rmdir` | `unsupported-alt-dest` |
| `operator-path-backup-symlink` | `unsupported-alt-dest` |
| `operator-path-compare-dest` | `unsupported-alt-dest` |
| `operator-path-copy-dest` | `unsupported-alt-dest` |
| `operator-path-files-from` | `unsupported-transfer-mode` |
| `operator-path-inplace-backup-dir` | `unsupported-alt-dest` |
| `operator-path-link-dest` | `unsupported-alt-dest` |
| `operator-path-log-file` | `unsupported-transfer-mode` |
| `operator-path-partial-dir` | `unsupported-transfer-mode` |
| `operator-path-temp-dir` | `unsupported-transfer-mode` |
| `operator-path-write-batch` | `unsupported-batch` |
| `output-options` | `unsupported-transfer-mode` |
| `ownership-depth` | `unsupported-metadata` |
| `partial-dir-abs-delta` | `unsupported-transfer-mode` |
| `partial_nowrite` | `unsupported-transfer-mode` |
| `password-file-symlink` | `unsupported-transfer-mode` |
| `preallocate` | `unsupported-transfer-mode` |
| `prune-empty-dirs` | `unsupported-transfer-mode` |
| `relative` | `unsupported-relative` |
| `relative-content` | `unsupported-relative` |
| `relative-implied` | `unsupported-relative` |
| `relative-implied-symlink` | `unsupported-relative` |
| `relative-mkpath-dir-symlink` | `unsupported-relative` |
| `relative-mkpath-symlink` | `unsupported-relative` |
| `relative-symlinked-parent` | `unsupported-relative` |
| `relative-symlinked-parent-dotdot` | `unsupported-relative` |
| `rename-fullpath-symlink-race` | `unsupported-transfer-mode` |
| `safe-links` | `unsupported-transfer-mode` |
| `safe-links-absolute-intree` | `unsupported-transfer-mode` |
| `safe-links-unsafe-def` | `unsupported-transfer-mode` |
| `sender-remove-source-relative-anchor` | `unsupported-relative` |
| `sender-remove-source-root-anchor` | `unsupported-relative` |
| `sparse` | `unsupported-transfer-mode` |
| `stop-time` | `unsupported-transfer-mode` |
| `symlink-dest-backupdir` | `unsupported-alt-dest` |
| `symlink-dirlink-basis` | `unsupported-transfer-mode` |
| `symlink-exclude-chdir-alias` | `unsupported-filters` |
| `symlink-exclude-component` | `unsupported-filters` |
| `symlink-exclude-deep` | `unsupported-filters` |
| `symlink-exclude-leaf` | `unsupported-filters` |
| `symlink-exclude-meta` | `unsupported-filters` |
| `symlink-exclude-xattr` | `unsupported-xattrs` |
| `symlink-mknod-fakesuper-symlink-race` | `unsupported-xattrs` |
| `temp-dir` | `unsupported-transfer-mode` |
| `temp-dir-symlink-injection` | `unsupported-transfer-mode` |
| `write-batch-filter-injection` | `unsupported-batch` |
| `write-batch-quoting` | `unsupported-batch` |
| `xattr-wire-cap` | `unsupported-xattrs` |
| `xattrs` | `unsupported-xattrs` |
| `xattrs-depth` | `unsupported-xattrs` |
| `xattrs-hlink` | `unsupported-xattrs` |

## Rsync-specific internals, protocol, and services

| Test | Reason |
|---|---|
| `00-hello` | `rsync-internal` |
| `authenticate-no-ocloexec-build-regression` | `rsync-internal` |
| `bare-do-open-symlink-race` | `rsync-internal` |
| `chdir-symlink-race` | `rsync-internal` |
| `checksum-zero-blocklen` | `rsync-internal` |
| `chroot-alt-dest-inner-module` | `rsync-daemon` |
| `chroot-basis-forge-inner-module` | `rsync-daemon` |
| `chroot-copy-dest-inner-module` | `rsync-daemon` |
| `chroot-link-dest-inner-module` | `rsync-daemon` |
| `chroot-receiver-write-inner-module` | `rsync-daemon` |
| `chroot-special-inner-module` | `rsync-daemon` |
| `clean-fname-collapse` | `rsync-internal` |
| `clean-fname-underflow` | `rsync-internal` |
| `compress-zlib-insert` | `rsync-internal` |
| `connect-prog-host-quoting` | `rsync-daemon` |
| `connect-prog-nested-singlequote-host-injection` | `rsync-daemon` |
| `daemon` | `rsync-daemon` |
| `daemon-access` | `rsync-daemon` |
| `daemon-access-idn` | `rsync-daemon` |
| `daemon-access-ip` | `rsync-daemon` |
| `daemon-argv-limit` | `rsync-daemon` |
| `daemon-auth` | `rsync-daemon` |
| `daemon-auth-digest-floor` | `rsync-daemon` |
| `daemon-auth-group` | `rsync-daemon` |
| `daemon-auth-users-comma-only` | `rsync-daemon` |
| `daemon-chroot` | `rsync-daemon` |
| `daemon-chroot-acl` | `rsync-daemon` |
| `daemon-chroot-munge-default` | `rsync-daemon` |
| `daemon-config` | `rsync-daemon` |
| `daemon-config-symlink` | `rsync-daemon` |
| `daemon-copy-links-symlink` | `rsync-daemon` |
| `daemon-copylinks-intree` | `rsync-daemon` |
| `daemon-copylinks-parent-escape` | `rsync-daemon` |
| `daemon-copylinks-parent-target-regression` | `rsync-daemon` |
| `daemon-delete-stats` | `rsync-daemon` |
| `daemon-deny-dns-failopen` | `rsync-daemon` |
| `daemon-dot-file-force-wipe` | `rsync-daemon` |
| `daemon-early-exec-nameconv` | `rsync-daemon` |
| `daemon-exclude-from-outside-module` | `rsync-daemon` |
| `daemon-exclude-namebased` | `rsync-daemon` |
| `daemon-exec` | `rsync-daemon` |
| `daemon-exec-metachar-documented-limit` | `rsync-daemon` |
| `daemon-exec-metachar-refused` | `rsync-daemon` |
| `daemon-exec-rsync-env-shell-escape` | `rsync-daemon` |
| `daemon-exec-second-shell-argument-injection` | `rsync-daemon` |
| `daemon-exec-singlequote-injection` | `rsync-daemon` |
| `daemon-filter` | `rsync-daemon` |
| `daemon-filter-merge-bypass` | `rsync-daemon` |
| `daemon-groupmap-wild` | `rsync-daemon` |
| `daemon-gzip-download` | `rsync-daemon` |
| `daemon-gzip-upload` | `rsync-daemon` |
| `daemon-handshake-timeout` | `rsync-daemon` |
| `daemon-http-proxy` | `rsync-daemon` |
| `daemon-include-maxconn` | `rsync-daemon` |
| `daemon-leaf-type-race-fchmod` | `rsync-daemon` |
| `daemon-link-dest-escape` | `rsync-daemon` |
| `daemon-max-alloc-zero` | `rsync-daemon` |
| `daemon-module-chdir-symlink` | `rsync-daemon` |
| `daemon-module-options` | `rsync-daemon` |
| `daemon-module-private-parent` | `rsync-daemon` |
| `daemon-munge` | `rsync-daemon` |
| `daemon-namecvt-empty-response` | `rsync-daemon` |
| `daemon-namecvt-newline-token` | `rsync-daemon` |
| `daemon-path-root-read` | `rsync-daemon` |
| `daemon-path-rsync-var` | `rsync-daemon` |
| `daemon-proxy-protocol` | `rsync-daemon` |
| `daemon-refuse` | `rsync-daemon` |
| `daemon-refuse-compress` | `rsync-daemon` |
| `daemon-refuse-compress-threads-alias` | `rsync-daemon` |
| `daemon-refuse-delete-alias` | `rsync-daemon` |
| `daemon-scan-cwd-desync` | `rsync-daemon` |
| `daemon-scan-dir-escape` | `rsync-daemon` |
| `daemon-secrets-file-symlink` | `rsync-daemon` |
| `daemon-size-arg-overflow` | `rsync-daemon` |
| `daemon-standalone-detach` | `rsync-daemon` |
| `daemon-strict-modes-matrix` | `rsync-daemon` |
| `daemon-subdir-climb-symlink` | `rsync-daemon` |
| `daemon-symlink-escape-matrix` | `rsync-daemon` |
| `daemon-unix-socket-atfd` | `rsync-daemon` |
| `daemon-zstd-thread-exhaustion` | `rsync-daemon` |
| `files-from-leak` | `rsync-daemon` |
| `git-set-file-times-python-compat-regression` | `rsync-internal` |
| `hashsearch-chain` | `rsync-internal` |
| `hashtable-overflow` | `rsync-internal` |
| `idn` | `rsync-daemon` |
| `inband-modname-leak` | `rsync-wire` |
| `insecure-links-admin-optout` | `rsync-daemon` |
| `install-strip` | `rsync-internal` |
| `io-noop-flood-recursion` | `rsync-wire` |
| `io-nosend-flood-recursion` | `rsync-wire` |
| `io-readargs-argv-nullwrite` | `rsync-wire` |
| `iwildmatch-fold` | `rsync-internal` |
| `ki62-io-error-mask` | `rsync-wire` |
| `malicious-dot-dir-delete-scope` | `rsync-wire` |
| `malicious-dot-file-delete-scope` | `rsync-wire` |
| `malicious-sender-delete-scope` | `rsync-wire` |
| `malicious-server-partial-basis-symlink-overwrite` | `rsync-wire` |
| `match-append-empty-nullmap` | `rsync-internal` |
| `match-want-i-nolen` | `rsync-internal` |
| `msg-io-timeout-overflow` | `rsync-wire` |
| `msg-io-timeout-zero` | `rsync-wire` |
| `nonroot-restrictive-perms` | `rsync-daemon` |
| `operator-path-backup-dir-daemon` | `rsync-daemon` |
| `operator-path-backup-dir-exclude-daemon` | `rsync-daemon` |
| `operator-path-dir-daemon-inmodule` | `rsync-daemon` |
| `operator-path-dir-daemon-leaf` | `rsync-daemon` |
| `operator-path-dir-daemon-mkdir` | `rsync-daemon` |
| `operator-path-dir-daemon-outside` | `rsync-daemon` |
| `operator-path-insecure-links-daemon` | `rsync-daemon` |
| `operator-path-insecure-links-refused` | `rsync-daemon` |
| `operator-path-partial-dir-daemon` | `rsync-daemon` |
| `operator-path-partial-dir-exclude-daemon` | `rsync-daemon` |
| `operator-path-traversal-backup-dir-daemon` | `rsync-daemon` |
| `operator-path-traversal-dest-dir-daemon` | `rsync-daemon` |
| `operator-path-traversal-partial-dir-daemon` | `rsync-daemon` |
| `partial-protected-regular-retry-linux` | `rsync-internal` |
| `partial-protected-regular-retry-policy` | `rsync-internal` |
| `peer-legacy-implied-delete-scope` | `rsync-wire` |
| `proto-cleared-dirflist` | `rsync-wire` |
| `proto-cleared-ndx` | `rsync-wire` |
| `proto-hlink-flag-oob` | `rsync-wire` |
| `proto-hlink-gnum` | `rsync-wire` |
| `proto-msg-info-assert` | `rsync-wire` |
| `proto-parent-ndx-empty-dirflist` | `rsync-wire` |
| `proto-sender-selftest` | `rsync-wire` |
| `proto-subflist-freed` | `rsync-wire` |
| `proxy-connect-request-too-long` | `rsync-wire` |
| `proxy-host-crlf` | `rsync-wire` |
| `proxy-protocol-trusted-peer` | `rsync-wire` |
| `proxy-response-header-too-long` | `rsync-wire` |
| `proxy-response-line-too-long` | `rsync-wire` |
| `readonly-partial-abort-mode-regression` | `rsync-wire` |
| `recv-discard-nullderef` | `rsync-wire` |
| `recv-generator-acl-leak` | `rsync-wire` |
| `rename-mixed-parent-escape-poc` | `rsync-internal` |
| `rename-mixed-parent-symlink-race` | `rsync-internal` |
| `rename-mixed-parent-transfer` | `rsync-daemon` |
| `reverse-daemon-delta` | `rsync-wire` |
| `rrsync-alt-dest-inband-pivot` | `rrsync` |
| `rrsync-archive-mode` | `rrsync` |
| `rrsync-backup-dir-inband-pivot` | `rrsync` |
| `rrsync-copy-unsafe-links-denied` | `rrsync` |
| `rrsync-debug-denied` | `rrsync` |
| `rrsync-files-from-stdin` | `rrsync` |
| `rrsync-logfile-symlink` | `rrsync` |
| `rrsync-merge-file-confine` | `rrsync` |
| `rrsync-no-overwrite-backup-collision` | `rrsync` |
| `rrsync-no-overwrite-delay-updates` | `rrsync` |
| `rrsync-no-overwrite-logfile` | `rrsync` |
| `rrsync-no-overwrite-partial-dir` | `rrsync` |
| `rrsync-pull-arg-shapes` | `rrsync` |
| `rrsync-pull-delivers-content` | `rrsync` |
| `rrsync-sender-leaf-flip` | `rrsync` |
| `rrsync-sender-parent-pin` | `rrsync` |
| `rrsync-specials-denied` | `rrsync` |
| `rrsync-symlink` | `rrsync` |
| `rrsync-userns-procfs` | `rrsync` |
| `rrsync-write-only-files-from` | `rrsync` |
| `rsync-ssl-hostname-validation` | `rsync-daemon` |
| `rsync-ssl-openssl-hostname-check` | `rsync-daemon` |
| `rsync-ssl-stunnel-ca-required` | `rsync-daemon` |
| `rsync-ssl-stunnel-hostname-check` | `rsync-daemon` |
| `rsync-ssl-type-option` | `rsync-daemon` |
| `safe-arg-leak` | `rsync-wire` |
| `scanner-argv-bounds` | `rsync-wire` |
| `scanner-batch-flag-mismatch` | `rsync-wire` |
| `scanner-daemon-log-checksum` | `rsync-wire` |
| `scanner-delete-delay-overread` | `rsync-wire` |
| `secure-relpath-validation` | `rsync-internal` |
| `sender-flist-symlink-leak` | `rsync-wire` |
| `sender-readlink-atfd` | `rsync-daemon` |
| `sender-remove-source-secure` | `rsync-daemon` |
| `simd-checksum` | `rsync-internal` |
| `skiplist-spec` | `rsync-internal` |
| `symlink-exclude` | `rsync-daemon` |
| `trimslash` | `rsync-internal` |
| `uidlist-id0-name-leak` | `rsync-internal` |
| `unsafe-byname` | `rsync-internal` |
| `variety` | `rsync-wire` |
| `variety-symlink-traversal` | `rsync-wire` |
| `wildmatch` | `rsync-internal` |
| `xrsync` | `rsync-wire` |
