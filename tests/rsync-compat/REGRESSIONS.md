# Historical rsync regression corpus

This generated ledger turns selected upstream bug reports, security policy,
advisories, and regression tests into reviewable behavioral claims for SYQ.
It prioritizes security, data loss, and data integrity; it is deliberately
curated rather than a claim that every rsync issue applies to SYQ.

Update it with:

```sh
python3 scripts/rsync-compat.py --ledger-only --update-ledger
```

| Status | Cases |
|---|---:|
| covered | 2 |
| partial | 4 |
| candidate | 2 |
| not-applicable | 2 |

`covered` means the recorded behavioral claim has executable coverage,
not that SYQ implements every option or internal mechanism in the report.
`partial` identifies the untested remainder explicitly; `candidate` is
triaged future work; `not-applicable` records a deliberate exclusion.

| Priority | Impact | Case | Status | Behavioral claim | Executable coverage | Note |
|---|---|---|---|---|---|---|
| critical | data-loss | [rsync-359](https://github.com/RsyncProject/rsync/issues/359) — Self-copy with source removal destroyed the source | partial | A copy whose effective source and destination are the same inode or tree must never truncate or overwrite its only good copy. | local:`inplace_self_copy_preserves_source`; local:`file_onto_itself_is_allowed_noop`; local:`copy_onto_itself_among_sources_is_order_independent` | SYQ's supported ordinary and --inplace self-copy paths are guarded. Rsync's destructive --remove-source-files mode is not implemented, so the exact historical command is not applicable yet. |
| critical | security | [rsync-ghsa-phxh-hjqv-39c9](https://github.com/RsyncProject/rsync/security/advisories/GHSA-phxh-hjqv-39c9) — Raced ACL/xattr application could modify an inode outside the destination | not-applicable | Metadata application must remain bound to the intended destination inode. | none | SYQ does not implement ACL or xattr preservation, the vulnerable metadata classes. This entry prevents that exclusion from being mistaken for an unreviewed gap if those features are added later. |
| critical | security | [rsync-security-parent-symlink-races](https://github.com/RsyncProject/rsync/blob/7c20b077c980036a19587701cec320cc88e42a4a/SECURITY.md) — Parent-component symlink races can escape transfer roots | partial | Peer-selected source and destination paths must not be redirected outside their transfer roots by raced parent symlinks. | compat:`sender-scan-dir-escape`; compat:`symlink-race-source`; compat:`symlink-race-dest`; compat:`symlink-race-relative-dest`; local:`destination_root_replacement_after_selection_cannot_redirect_worker`; local:`self_copy_guard_sees_through_symlinks`; local:`files_from_self_copy_through_symlinked_root_is_rejected` | Source-side confinement and retained operator-named destination roots pass. Destination operations still resolve in-tree descendant components from relative pathnames, so descendant parent-component race confinement remains partial and highly visible. |
| high | availability | [rsync-350](https://github.com/RsyncProject/rsync/issues/350) — Valid --files-from entries were randomly rejected after a security fix | partial | Large --files-from inputs must retain every valid selected path across internal batching boundaries. | compat:`files-from-depth`; local:`files_from_repeats_and_late_listed_dirs_across_chunks` | SYQ's 1,200-entry chunk-boundary test covers its analogous planner risk. The rsync protocol-validation mechanism that caused the original remote failure is intentionally different. |
| high | availability | [rsync-376](https://github.com/RsyncProject/rsync/issues/376) — Hash-shaped --files-from entries were rejected as unrequested | partial | A large set of valid nested --files-from names must transfer completely without ordering-dependent rejection. | compat:`files-from-depth`; local:`files_from_repeats_and_late_listed_dirs_across_chunks` | Current coverage stresses chunking and late directory claims but not the original rsync wire protocol or its exact hash corpus; a remote SYQ variant would complete this case. |
| high | data-integrity | [rsync-715](https://github.com/RsyncProject/rsync/issues/715) — Security hardening broke updates through a symlinked relative path | candidate | A supported relative-path copy through a legitimate destination directory symlink must update reliably without discarding verified data. | none | The reproducer depends on --relative/-R behavior that SYQ does not implement. Keep it queued for the rsync subcommand's relative-path work. |
| high | resource-exhaustion | [rsync-959](https://github.com/RsyncProject/rsync/issues/959) — Security hardening amplified memory use for large directory trees | candidate | Scanning many empty directories should use memory proportional to useful planner state, without catastrophic amplification. | none | The reported 80,000-directory corpus is too large for the normal compatibility job. Add a separately budgeted scale test with an explicit memory envelope. |
| high | security | [rsync-remote-shell-newline](https://github.com/RsyncProject/rsync/blob/7c20b077c980036a19587701cec320cc88e42a4a/testsuite/remote-shell-newline-escaping_test.py) — A newline in a remote argument could split a shell command | covered | A newline-bearing remote destination must remain one quoted argument and must not execute an injected command. | compat:`remote-shell-newline-escaping` | The adaptation substitutes SYQ's remote option spelling without weakening the command-injection oracle. |
| high | data-integrity | [rsync-source-change-size-continues](https://github.com/RsyncProject/rsync/blob/7c20b077c980036a19587701cec320cc88e42a4a/testsuite/source-change-size-continues_test.py) — A changed source aborted unrelated later transfers | covered | A source that shrinks at read time must fail visibly, preserve an existing destination, and not abort unrelated later files. | compat:`source-read-failure-continues` | The adapted fixture uses an external positioned-read shim and checks all three consequences against ordinary debug or release binaries. |
| medium | availability | [rsync-897](https://github.com/RsyncProject/rsync/issues/897) — Native rsync protocol reads failed after path hardening | not-applicable | A remote protocol implementation must open module-root source files through its intended confinement model. | none | The failure is specific to rsync daemon/native-protocol module roots. SYQ uses its own authenticated helper protocol, so this exact regression is outside the compatibility surface. |
