# rsync compatibility

`syq rsync` is syq's rsync-shaped command surface. This file is the
tracked record of how far that goes: what behaves the same, what differs and
why, what rsync has that syq doesn't, and the open issues. `README.md` and the documents under `docs/`
are the user-facing contract; when they and this record disagree, fix one of them.

Each entry says whether it was **measured** (run against upstream rsync —
3.5.0 at `7c20b077`, cross-checked with 3.2.7 where version-sensitive) or is
**believed** (from documentation or memory, not yet exercised). A raw run of
the upstream rsync test suite is not a compatibility score: most of its
failures come from unsupported options, protocol internals, daemon mode, or
its harness. The automated matrix therefore reports raw observations alongside
our product position on each behavior instead of reducing them to a percentage.

Categories:

- **Compatible** — same observable behavior.
- **Compatible subset or approximation** — the ordinary result agrees, but a
  documented edge, output detail, or implementation constraint differs. Exact
  emulation may be disproportionate to the compatibility value, but the
  approximation must not hide failure or introduce unexpected data loss.
- **Intentional divergence** — syq knowingly chooses different semantics for
  safety, product architecture, or another documented reason.
- **SYQ extension** — functionality outside rsync's model. Every retained
  long option uses a `--syq-` name so scripts can identify it as non-portable.
- **Not implemented** — rsync has it, syq doesn't yet, or the behavior belongs
  only on syq's native interface.
- **Open issues** — known gaps we intend to close, or decisions still to make.

## Automated upstream test ledger

`tests/rsync-compat/` turns the upstream audit into a repeatable CI check:

```sh
python3 scripts/rsync-compat.py
```

The manifest pins rsync commit `7c20b077` and defines one target representing
SYQ's `syq rsync` compatibility surface. Its configured `rsync`
argument routes every upstream invocation through that subcommand without
changing upstream test calls. `inventory.tsv` names all 351 tests at that
commit; changing the pin without classifying every added or removed test is an
error. The classifications deliberately distinguish:

- relevant unmodified and adapted conformance tests;
- user-visible features syq does not implement;
- rsync daemon, wire-protocol, restricted-wrapper, build, and internal tests
  that syq does not need to pass; and
- an explicit unassessed category for future pin updates (currently empty).

Each runnable entry records a raw observation baseline separately from its
product position: compatible, unimplemented, intentional divergence, undecided
policy, or unresolved test claim. CI fails when the observation changes in
either direction until it is reviewed, but an expected test failure is not
misreported as a harness crash. Runner completeness and output parsing are
checked independently. All 351 pinned tests are classified: 36 are runnable,
133 require unsupported user-facing features, and 182 exercise rsync's own
internals, protocol, daemon, or restricted wrapper. There are no unassessed
tests. The runnable sources produce 38 independently reported scenarios. CI
runs 34 scenarios as a non-root user, then those scenarios plus four
root-only circumstances as root, and publishes JSON, Markdown, static HTML,
and raw-log matrices rather than a headline score.

The generated `tests/rsync-compat/LEDGER.md` is the readable per-test record;
CI rejects it if it drifts from the manifest and inventory. An adapted test
names a patch under `tests/rsync-compat/adaptations/`. Patches may translate an
incidental implementation detail, such as SYQ's partial-file layout, or isolate
a supported scenario from an aggregate upstream test, but must preserve the
claimed behavioral oracle. Their provenance is visible in the matrix, including
whether they alter an invocation, fixture, or tested subset. Git validates both
the forward and reverse path sets before the exact patch bytes are applied, so
adaptations cannot modify rsync sources or the runner outside `testsuite/`.

## Compatible

The **Test** column names the function in `tests/local.rs` that pins the
behavior; an entry without one is only believed, not held.

| Behavior | Status | Test |
|---|---|---|
| Path rules: `src` copies the directory, `src/` its contents; a single file lands as `dest/file` when `dest` is a directory; several sources need a directory destination | measured | `trailing_slash_copies_contents`, `dir_into_existing_dir`, `dir_into_missing_dest_creates_basename`, `single_file_into_existing_dir`, `single_file_to_new_name`, `multiple_sources_require_dir_dest` |
| Quick check: size + mtime; without `-t` every file is re-sent | measured | `updates_changed_file_and_skips_symlink_only_when_same`, `skip_reconciles_mode` |
| `--delete` scope: only inside the directories being synced; a single-file source deletes nothing | measured | `delete_only_inside_directories_the_sources_map_onto`, `delete_with_nested_roots_deletes_once` |
| Ignored/excluded paths are protected from deletion by default; `--delete-excluded` lifts that | measured | `delete_removes_extras_and_protects_ignored`, `delete_nested_roots_keep_their_own_anchored_ignores`, `delete_excluded_removes_ignored_destination_paths` |
| A directory that can't be emptied because of protected content is reported and left (rsync: `cannot delete non-empty directory`; syq: `not deleting keep/: it holds ignored paths`) | measured | `delete_removes_extras_and_protects_ignored` |
| Deletion is skipped when listing the source hit errors (rsync: `IO error encountered -- skipping file deletion`) | measured; see "Compatible subsets or approximations" 1 for the transfer-time case | `delete_is_skipped_when_the_source_scan_has_errors`, `unreadable_source_root_disables_delete` |
| Files the source has but a rule skips — `-u`, `--existing`, `--ignore-existing`, `--max-size`/`--min-size`, symlinks without `-l`, specials without `-D` — are not deleted, even when the destination entry is a non-empty directory | measured on 3.2.7 and 3.5.0 (an earlier README claim that rsync deletes a `--max-size` casualty was wrong) | `delete_never_removes_paths_the_source_has_but_skips`, `delete_leaves_directory_contents_under_a_skipped_source_path`, `size_limits_filter_files_and_protect_them_from_delete`, `delete_keeps_partials_of_filtered_files` |
| `-u`/`--update`: a destination regular file with a newer mtime is left alone | measured for regular files; see "Compatible subsets or approximations" for symlinks/devices | `update_skips_files_newer_on_the_destination` |
| `--existing` / `--ignore-existing`, including `--existing` covering directories | measured | `ignore_existing_and_existing`, `existing_never_creates_the_destination_root`, `existing_leaves_a_file_where_a_source_directory_would_go`, `existing_dry_run_lists_no_missing_directories`, `existing_opens_up_readonly_dirs_even_after_a_symlinked_dir` |
| `--max-size` / `--min-size` on regular files only; `K`/`M`/`G` suffixes | measured | `size_limits_filter_files_and_protect_them_from_delete`, `bad_size_limits_fail_before_anything_connects` |
| `--files-from` baseline: paths relative to one source; implied parents created; a plain listed directory is copied without its contents unless `-r` is given explicitly (`-a` doesn't count); `--from0`; `-` reads stdin; blank entries and entries starting with `#` or `;` dropped in both separator modes (literal names remain reachable as `./#name` and `./;name`) | measured; entry *parsing* has gaps, open issue 1 | `files_from_copies_listed_paths_with_their_parents`, `files_from_treats_hash_and_semicolon_entries_as_comments`, `files_from_creates_listed_and_implied_dirs_without_r`, `files_from_repeats_and_late_listed_dirs_across_chunks`, `files_from_root_may_be_a_symlink_and_root_lines_are_rejected` |
| `--delete-after` / `--delete-delay` accepted as synonyms of `--delete` (they describe what syq does) | by construction | `delete_after_and_delay_are_synonyms` |
| `--max-delete N` exists and exits 25 when it trips | believed (exit code matches rsync); see "Intentional divergences" for positive-limit semantics | `max_delete_refuses_everything_past_the_limit` |
| `--max-delete=0` reports destination-only entries without deleting them; `--max-delete=-1` is accepted as the historical synonym; without `--delete` the option has no effect | measured for syq; rsync behavior documented upstream | `max_delete_refuses_everything_past_the_limit` |
| An operator-named destination symlink is followed when owned by root or by the receiving process's effective uid; a foreign-owned component is refused | measured, including absolute and relative root/cross-uid cases | `symlink_destination_is_followed`, `destination_root_symlink_preserves_target_metadata_for_both_spellings`, `existing_updates_through_a_destination_root_symlink_to_a_dir`, `foreign_owned_destination_root_symlink_is_refused` |
| A symlink to a directory found *inside* the destination tree is replaced with a real directory; only the argument itself is followed (rsync without `-K`) | measured | `in_tree_destination_symlink_is_replaced_not_followed`, `existing_does_not_write_through_a_destination_symlink_dir` |
| `-P`, `-h`, `--partial`, `--numeric-ids`, `-V` accepted as no-ops/aliases; common unsupported flags are rejected with an explanation | by construction | `rsync_compat_noops_are_accepted`, `unsupported_rsync_flags_explain_themselves` |
| `-B` and `--block-size` select syq's transfer/hash block size | by construction | `checksum_repairs_silent_corruption` |
| A remote source and remote destination are refused before connecting, as by rsync | by construction | `rsync_rejects_remote_to_remote` |
| Source entries whose names look like SYQ sidecars (`.name.syq-part.<id>`) are copied as ordinary payload (with one warning); only the exact case where a payload path equals a sidecar this job would use for another file is refused, before anything is written | by construction (PR #7's namespace preflight) | `sidecar_named_source_directory_is_payload`, `delete_treats_sidecar_patterned_files_as_ordinary_extras`, `partial_named_symlink_is_a_symlink_not_a_leftover` |

## Intentional divergences

Each item records the current reason syq does otherwise. Safety is one reason;
architecture and disproportionate implementation cost can also justify a
narrow divergence. If the reasoning stops holding, move the item.

1. **`--delete` runs after the transfer, always; no `--delete-before` /
   `--delete-during`.** rsync defaults to delete-during. syq's rule means a run
   interrupted or failed during scanning or transfer never starts deletion,
   and deletion is computed against a quiescent destination (no races with
   partial renames or in-place replaces). Interruption after deletion starts
   can still leave some planned extras removed. The cost is that space is never
   freed before writing. We consider "the transfer failed after it already
   deleted destination-only files" a worse outcome than "ran out of space."
   *Tests: `delete_with_inplace_replacing_many_symlinks`,
   `delete_removes_only_this_jobs_orphaned_sidecars`.*
2. **A positive `--max-delete N` deletes *nothing* past the limit.** rsync
   deletes the first N and then stops. A safety cap that leaves the destination
   in a partially-deleted state is not much of a safety cap; syq refuses
   outright, says so, and exits 25 like rsync. Zero already means delete
   nothing in both programs. *Test:
   `max_delete_refuses_everything_past_the_limit`.*
3. **`--files-from` follows symlinked implied parents and creates them as real
   directories on the destination**, and refuses a listed symlink together with
   a path through it. rsync's behavior here is version-sensitive (measured:
   3.2.7 followed the parent and copied through it; 3.5 created the implied
   directory, then refused the open with `ELOOP`). Either way, sending the
   parent as a symlink would make a later write go *through* a destination
   symlink to wherever it points, which is how a file list could redirect
   writes outside the destination. Listing `data/foo` means "I want `foo`
   under `data`"; syq does that and nothing else. *Tests:
   `files_from_rejects_symlinked_ancestors_and_recurses_only_listed_dirs`,
   `files_from_leaves_no_ancestors_behind_on_a_bad_chain`,
   `files_from_symlink_conflict_is_order_independent`.*
4. **Two distinct sources mapping onto one destination file is an error.**
   Measured rsync silently keeps the first. Silent last-writer-wins (or
   first-writer-wins) on a collision is data loss with no message; syq refuses
   and names both. Exactly repeated source operands are deduplicated before
   scanning while retaining the original source count for placement. Naming
   the destination file itself as one of the sources is a conflict too, not a
   licence for the other source to overwrite it.
   *Tests: `duplicate_destination_rejected`,
   `exactly_repeated_sources_are_deduplicated_without_changing_placement`,
   `dir_vs_file_destination_collision_rejected`,
   `cross_source_collision_is_detected_before_any_change`,
   `copy_onto_itself_among_sources_is_order_independent`,
   `three_claimants_are_validated_as_a_group`.*

5. **`--ignore-existing` keeps an existing non-directory even where the
   source maps a directory.** rsync exempts directories from the flag ("this
   does not ignore existing directories"), and consequently — believed from
   the manpage, not yet measured — unlinks an existing destination file to
   make room for a source directory. Under a flag whose whole meaning is
   "what exists is authoritative", that is unrecoverable data loss; syq keeps
   the file and skips the mapped directory with its subtree, with a notice.
   *Test: `ignore_existing_keeps_a_file_where_a_source_directory_maps`.*

## SYQ extensions

These options intentionally do not pretend to be rsync options:

| Option | Purpose |
|---|---|
| `--syq-connections N` | Fix syq's parallel connection/worker count |
| `--syq-ignore`, `--syq-ignore-from` | Use syq's ordered gitignore-style filter language |
| `--syq-progress-json` | Emit JSON progress events |
| `--syq-verify-only` | Compare the selected source and destination scope without mutation |
| `--syq-no-bootstrap` | Require a compatible syq in the remote `PATH` |
| `--syq-no-tcp`, `--syq-tcp-plain`, `--syq-tcp-ports`, `--syq-tcp-congestion` | Tune syq's separate TCP data path |
| `--syq-pscope PATH` | Use an isolated SSH persistence scope created by `syq persist on --ephemeral` |

The gitignore rules have a broadly similar purpose to rsync filters but are not
syntax-compatible: syq is last-match-wins with `!` re-inclusion, while rsync
uses first-match include/exclude/filter rules with side modifiers and
per-directory merge files. Rsync's `-i` remains `--itemize-changes` and is
rejected because itemized output is not implemented.

`--syq-verify-only` applies `-u`, size limits, `--existing`, and
`--ignore-existing` to the scope it compares; it checks exactly what the
corresponding copy would select. *Test: `verify_only_checks_the_filtered_scope`.*

## Compatible subsets or approximations

1. **Any error while listing the source disables deletion** — the same idea
   as rsync's file-list I/O check. A directory we couldn't read would
   otherwise look like one whose contents vanished. A read failure *during
   transfer* does not disable deletion: the failed file is still claimed, so
   it is never an extra, and the extras set is unaffected. *Tests:
   `unreadable_source_root_disables_delete`,
   `delete_is_skipped_when_the_source_scan_has_errors`.*
2. **`-u` applies to regular files only.** rsync also compares mtimes for
   symlinks and devices (believed, not measured). Low impact; could be
   aligned. Deliberately, a *type change* replaces regardless of mtimes —
   a source directory still replaces a newer destination file (as in
   rsync): `-u` is about not regressing newer file content, not about
   protecting whatever exists; that stronger promise is
   `--ignore-existing`'s (see "Intentional divergences" 5).
3. **`--files-from` cannot combine with `--syq-ignore`/
   `--syq-ignore-from` or `--delete`.** Rsync allows filters and deletion with
   a file list. These are explicit restrictions rather than silent semantic
   choices. Filters over a file list are a plausible later addition; deletion
   scope under a file list is genuinely ambiguous and rsync's semantics for it
   are murky. *Test:
   `files_from_rejections_and_stdin`.*
4. **Deletions are executed over the control connection** in batches of 1000
   (the receiving side unlinks a batch in parallel), not spread over syq's
   data connections. rsync has one connection anyway; this is a note about
   syq's own model.
5. **`--rsync-path PATH` must name syq, not rsync.** The standard spelling and
   placement in the remote-shell command agree, but syq speaks its own protocol
   and cannot launch an rsync peer. Unlike rsync's option, the current value is
   an exact executable path rather than a shell fragment with extra arguments.
6. **`-B`/`--block-size` controls syq's fixed transfer, hashing, and resume
   granularity.** Rsync uses the option within its rolling-checksum algorithm,
   which syq does not implement.

## Not implemented

rsync features syq doesn't have. The common ones are rejected with a one-line
explanation (`src/cli.rs`, `reject_unsupported_rsync_flags`) so a pasted rsync
command says what to change.

- `--delete-before`, `--delete-during`, `--force` — see "Intentional
  divergences" 1; these are refused rather than pending.
- `-H`/`--hard-links` — needs cross-file ordering in a scheduler that has
  none today.
- `-L`/`--copy-links`, `-k`/`--copy-dirlinks`, `-K`/`--keep-dirlinks`.
- `--backup`/`--backup-dir`/`--suffix`.
- `--link-dest`/`--compare-dest`/`--copy-dest`.
- `--relative` (`-R`), `--partial-dir`.
- `-A`/`--acls`, `-X`/`--xattrs`, `-S`/`--sparse`, `-x`/`--one-file-system`.
- `-i`/`--itemize-changes` — rejected with a specific explanation;
  `--syq-verify-only` compares contents but does not provide itemized output.
- `--size-only`, `--ignore-times`/`-I`, `--modify-window`, `--chmod`,
  `--log-file`.
- rsync filter rules (`--exclude`/`--include`/`--filter`); use
  `--syq-ignore` if gitignore semantics are suitable.
- rsync daemon mode / `rsync://`; syq speaks its own protocol.
- Rolling-checksum delta transfer; syq resumes at block granularity.
- Remote-to-remote transfer is deliberately absent from `syq rsync`, matching
  rsync itself; use native `syq cp` or `syq cp --prune`.

## Open issues

1. **The remaining `--files-from` entry parsing doesn't match rsync's**
   (measured on 3.2.7 and 3.5.0). Finish the related path rules as one change:
   normalize `..` and clamp it at the source root instead of rejecting;
   preserve a trailing slash (`dir/` selects the directory's immediate
   children without `-r`, `dir` only the directory); accept `.`/`/` as the root
   entry (children without `-r`); add `-0` as an alias of `--from0`.
2. **`-h` alone should print help**, as rsync does, while staying
   `--human-readable` inside a cluster (`-avh`). Essentially free.
3. **`-u` for symlinks/devices** — measure rsync, then align or record.
