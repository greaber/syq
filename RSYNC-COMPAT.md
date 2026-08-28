# rsync compatibility

pcp has an rsync-shaped command line. This file is the tracked record of how
far that goes: what behaves the same, what differs and why, what rsync has
that pcp doesn't, and the open issues. `README.md` is the user-facing
contract; when the two disagree, fix one of them.

Each entry says whether it was **measured** (run against upstream rsync —
3.5.0 at `7c20b077`, cross-checked with 3.2.7 where version-sensitive) or is
**believed** (from documentation or memory, not yet exercised). A raw run of
the upstream rsync test suite is not a compatibility score: most of its
failures come from unsupported options, protocol internals, daemon mode, or
its harness. The classified non-root Linux subset currently passes 20 of 22
tests; the two known failures are open issues 2 and 3 below.

Categories:

- **Compatible** — same observable behavior.
- **Incompatible on purpose** — pcp does something different because we
  think rsync's behavior is wrong or unsafe. Each one carries its reasoning.
- **Different, no claim of better** — a design choice that isn't rsync's;
  reasonable either way.
- **Not implemented** — rsync has it, pcp doesn't yet.
- **Open issues** — known gaps we intend to close, or decisions still to make.
- **Resolved** — a log of items that moved between categories, with the
  commit or PR.

## Automated upstream test ledger

`tests/rsync-compat/` turns the upstream audit into a repeatable CI check:

```sh
python3 scripts/rsync-compat.py
```

The manifest pins rsync commit `7c20b077`, records normal and future strict
profiles, and gives every runnable test an expected result plus platform and
environment requirements. `inventory.tsv` names all 351 tests at that commit;
changing the pin without classifying every added or removed test is an error.
The classifications deliberately distinguish:

- relevant unmodified and adapted conformance tests;
- user-visible features pcp does not implement;
- rsync daemon, wire-protocol, restricted-wrapper, build, and internal tests
  that pcp does not need to pass; and
- an explicit unassessed category for future pin updates (currently empty).

The upstream runner's expected-result mode is the oracle. A known failure is
green, while both a regression and an unexpected pass fail CI until the ledger
is updated. All 351 pinned tests are classified: 26 are runnable conformance
tests, 141 require unsupported user-facing features, and 184 exercise rsync's
own internals, protocol, daemon, or restricted wrapper. There are no unassessed
tests. The normal non-root Linux run selects 22 of the 26 and currently records
20 passes and 2 known failures; CI also runs the four root-only circumstances.
That pass rate covers the selected conformance subset, not an overall
percentage of rsync compatibility.

The generated `tests/rsync-compat/LEDGER.md` is the readable per-test record;
CI rejects it if it drifts from the manifest and inventory. An adapted test
names a patch under `tests/rsync-compat/adaptations/`. Patches may translate an
incidental implementation detail, such as PCP's partial-file layout, or isolate
a supported scenario from an aggregate upstream test, but must preserve the
claimed behavioral oracle. The future `strict` profile is recorded but disabled
until its CLI flag exists; the harness will inject that flag without changing
upstream test invocations.

## Compatible

The **Test** column names the function in `tests/local.rs` that pins the
behavior; an entry without one is only believed, not held.

| Behavior | Status | Test |
|---|---|---|
| Path rules: `src` copies the directory, `src/` its contents; a single file lands as `dest/file` when `dest` is a directory; several sources need a directory destination | measured | `trailing_slash_copies_contents`, `dir_into_existing_dir`, `dir_into_missing_dest_creates_basename`, `single_file_into_existing_dir`, `single_file_to_new_name`, `multiple_sources_require_dir_dest` |
| Quick check: size + mtime; without `-t` every file is re-sent | measured | `updates_changed_file_and_skips_symlink_only_when_same`, `skip_reconciles_mode` |
| `--delete` scope: only inside the directories being synced; a single-file source deletes nothing | measured | `delete_only_inside_directories_the_sources_map_onto`, `delete_with_nested_roots_deletes_once` |
| Ignored/excluded paths are protected from deletion by default; `--delete-excluded` lifts that | measured | `delete_removes_extras_and_protects_ignored`, `delete_nested_roots_keep_their_own_anchored_ignores`, `delete_excluded_removes_ignored_destination_paths` |
| A directory that can't be emptied because of protected content is reported and left (rsync: `cannot delete non-empty directory`; pcp: `not deleting keep/: it holds ignored paths`) | measured | `delete_removes_extras_and_protects_ignored` |
| Deletion is skipped when the source scan hit errors (rsync: `IO error encountered -- skipping file deletion`) | measured; pcp is stricter, see "Different" | `delete_is_skipped_when_the_source_scan_has_errors`, `unreadable_source_root_disables_delete` |
| Files the source has but a rule skips — `-u`, `--existing`, `--ignore-existing`, `--max-size`/`--min-size`, symlinks without `-l`, specials without `-D` — are not deleted, even when the destination entry is a non-empty directory | measured on 3.2.7 and 3.5.0 (an earlier README claim that rsync deletes a `--max-size` casualty was wrong) | `delete_never_removes_paths_the_source_has_but_skips`, `delete_leaves_directory_contents_under_a_skipped_source_path`, `size_limits_filter_files_and_protect_them_from_delete`, `delete_keeps_partials_of_filtered_files` |
| `-u`/`--update`: a destination regular file with a newer mtime is left alone | measured for regular files; see "Different" for symlinks/devices | `update_skips_files_newer_on_the_destination` |
| `--existing` / `--ignore-existing`, including `--existing` covering directories | measured | `ignore_existing_and_existing`, `existing_never_creates_the_destination_root`, `existing_leaves_a_file_where_a_source_directory_would_go`, `existing_dry_run_lists_no_missing_directories`, `existing_opens_up_readonly_dirs_even_after_a_symlinked_dir` |
| `--max-size` / `--min-size` on regular files only; `K`/`M`/`G` suffixes | measured | `size_limits_filter_files_and_protect_them_from_delete`, `bad_size_limits_fail_before_anything_connects` |
| `--files-from` baseline: paths relative to one source; implied parents created; a plain listed directory is copied without its contents unless `-r` is given explicitly (`-a` doesn't count); `--from0`; `-` reads stdin; blank entries dropped | measured; entry *parsing* has gaps, open issue 2 | `files_from_copies_listed_paths_with_their_parents`, `files_from_creates_listed_and_implied_dirs_without_r`, `files_from_repeats_and_late_listed_dirs_across_chunks`, `files_from_root_may_be_a_symlink_and_root_lines_are_rejected` |
| `--delete-after` / `--delete-delay` accepted as synonyms of `--delete` (they describe what pcp does) | by construction | `delete_after_and_delay_are_synonyms` |
| `--max-delete N` exists and exits 25 when it trips | believed (exit code matches rsync); see "Different" for the cap semantics | `max_delete_refuses_everything_past_the_limit` |
| A normal operator-owned destination *argument* that is a symlink to a directory is that directory | measured; see open issue 7 for a root/cross-uid case | `symlink_destination_is_followed`, `destination_root_symlink_preserves_target_metadata_for_both_spellings`, `existing_updates_through_a_destination_root_symlink_to_a_dir` |
| A symlink to a directory found *inside* the destination tree is replaced with a real directory; only the argument itself is followed (rsync without `-K`) | measured | `in_tree_destination_symlink_is_replaced_not_followed`, `existing_does_not_write_through_a_destination_symlink_dir` |
| `-P`, `-h`, `--partial`, `--numeric-ids`, `-V` accepted as no-ops/aliases; common unsupported flags are rejected with an explanation | by construction | `rsync_compat_noops_are_accepted`, `unsupported_rsync_flags_explain_themselves` |

## Incompatible on purpose

Each of these is a case where we think rsync's behavior is wrong or unsafe,
and pcp deliberately does otherwise. If the reasoning stops holding, move the
item.

1. **`--delete` runs after the transfer, always; no `--delete-before` /
   `--delete-during`.** rsync defaults to delete-during. pcp's rule means an
   interrupted run never deletes anything, and deletion is computed against a
   quiescent destination (no races with partial renames or in-place replaces).
   The cost is that space is never freed before writing. We consider "an
   aborted `--delete` run deleted half the tree" a worse outcome than "ran out
   of space."
2. **`--max-delete N` deletes *nothing* past the limit.** rsync deletes the
   first N and then stops. A safety cap that leaves the destination in a
   partially-deleted state is not much of a safety cap; pcp refuses outright,
   says so, and exits 25 like rsync.
3. **`--files-from` follows symlinked implied parents and creates them as real
   directories on the destination**, and refuses a listed symlink together with
   a path through it. rsync's behavior here is version-sensitive (measured:
   3.2.7 followed the parent and copied through it; 3.5 created the implied
   directory, then refused the open with `ELOOP`). Either way, sending the
   parent as a symlink would make a later write go *through* a destination
   symlink to wherever it points, which is how a file list could redirect
   writes outside the destination. Listing `data/foo` means "I want `foo`
   under `data`"; pcp does that and nothing else.
4. **Two distinct sources mapping onto one destination file is an error.**
   Measured rsync silently keeps the first. Silent last-writer-wins (or
   first-writer-wins) on a collision is data loss with no message; pcp refuses
   and names both. *Identical* repeated sources should be deduplicated instead
   — open issue 3. *Test: `delete_with_inplace_replacing_many_symlinks`, `delete_cleans_stale_partials_but_keeps_resume_state_of_failed_files`.* *Test: `max_delete_refuses_everything_past_the_limit`.* *Test: `files_from_rejects_symlinked_ancestors_and_recurses_only_listed_dirs`, `files_from_leaves_no_ancestors_behind_on_a_bad_chain`.* *Test: `duplicate_destination_rejected`, `dir_vs_file_destination_collision_rejected`, `copy_onto_itself_among_sources_is_order_independent`.*

## Different, no claim of better

1. **Ignore rules use gitignore syntax (`--ignore`/`--ignore-from`), not
   rsync's filter language.** Same model — `/` anchors, `dir/` matches only
   directories, `**`, negation — but gitignore is last-match-wins with `!`
   re-includes, while rsync applies the first matching include/exclude/filter
   rule and has sender/receiver-side modifiers, `protect`/`risk` rules, and
   per-directory merge files. gitignore is what most users already know; the
   trade is that rsync filter files can't be reused. (The short `-i` alias is a
   separate CLI problem — open issue 1.)
2. **Any source-scan warning disables deletion**, not just I/O errors on the
   file list. Stricter than rsync; a directory we couldn't read would
   otherwise look like one whose contents vanished.
3. **`-u` applies to regular files only.** rsync also compares mtimes for
   symlinks and devices (believed, not measured). Low impact; could be
   aligned.
4. **`--files-from` cannot combine with `--ignore`/`--ignore-from` or
   `--delete`, and direct remote→remote needs `--relay`** (the list is read
   on the invoking machine). rsync allows all three. Restrictions rather than
   differences: you get a clear usage error. Filters over a file list is a
   plausible later addition; deletion scope under a file list is genuinely
   ambiguous and rsync's semantics for it are murky.
5. **`--verify-only` checks the run's scope.** `-u`, size limits,
   `--existing`, `--ignore-existing` narrow what a run would transfer, and
   `--verify-only` verifies exactly that set. rsync has no `--verify-only`.
6. **Source files named `.name.pcp-partial` are never copied.** rsync copies
   them. The name is pcp's in-flight file for `name` in the same directory;
   copying both would collide. The destination copy of such a file is still
   protected from `--delete`. Open issue 4 is about changing this.
7. **Deletions are executed over the control connection** in batches of 1000
   (the receiving side unlinks a batch in parallel), not spread over the `-j`
   data connections. rsync has one connection anyway; this is a note about
   pcp's own model. *Test: `unreadable_source_root_disables_delete`.* *Test: `verify_only_checks_the_filtered_scope`.* *Test: `delete_keeps_user_files_named_like_partials_and_survives_bare_suffix`, `partial_named_symlink_is_a_symlink_not_a_leftover`, `delete_treats_partial_named_directory_as_ordinary_extra`.*

## Not implemented

rsync features pcp doesn't have. The common ones are rejected with a one-line
explanation (`src/cli.rs`, `reject_unsupported_rsync_flags`) so a pasted rsync
command says what to change.

- `--delete-before`, `--delete-during`, `--force` — see "Incompatible on
  purpose" 1; these are refused rather than pending.
- `-H`/`--hard-links` — needs cross-file ordering in a scheduler that has
  none today.
- `-L`/`--copy-links`, `-k`/`--copy-dirlinks`, `-K`/`--keep-dirlinks`.
- `--backup`/`--backup-dir`/`--suffix` — cheap given partial+rename; not yet.
- `--link-dest`/`--compare-dest`/`--copy-dest`.
- `--relative` (`-R`), `--partial-dir`.
- `-A`/`--acls`, `-X`/`--xattrs`, `-S`/`--sparse`, `-x`/`--one-file-system`.
- `-i`/`--itemize-changes` — and the short flag is currently taken, open
  issue 1.
- `--size-only`, `--ignore-times`/`-I`, `--modify-window`, `--chmod`,
  `--log-file`.
- rsync filter rules (`--exclude`/`--include`/`--filter`); use `--ignore`.
- rsync daemon mode / `rsync://`; pcp speaks its own protocol.
- Rolling-checksum delta transfer; pcp resumes at block granularity.

## Open issues

1. **`-i` means `--ignore` in pcp and `--itemize-changes` in rsync.** Worse
   than cosmetic: rsync's `-i` takes no value, so a pasted multi-source
   command can consume a source argument as an ignore pattern. Plan: make
   `--ignore`/`--ignore-from` long-only; reject a bare `-i` with a specific
   explanation until itemized output exists. Don't pick another rsync short
   letter for ignore (`-I` is `--ignore-times`).
2. **`--files-from` entry parsing doesn't match rsync's** (measured on 3.2.7
   and 3.5.0). Adopt the full rule set as one change: skip entries starting
   with `#` or `;` (line mode and `--from0`); normalize `..` and clamp it at
   the source root instead of rejecting; preserve a trailing slash (`dir/`
   selects the directory's immediate children without `-r`, `dir` only the
   directory); accept `.`/`/` as the root entry (children without `-r`); add
   `-0` as an alias of `--from0`. Comment-looking names remain reachable as
   `./#name`.
3. **Repeated identical sources should be deduplicated**, not reported as a
   collision (rsync scans a source given ten times once). Only for
   byte-identical source arguments including trailing-slash mode; distinct
   sources on one destination stay an error ("Incompatible on purpose" 4).
4. **Reserved partial-name namespace in the source** ("Different" 6). Options:
   move pcp's in-flight files to a private location so user files named
   `.x.pcp-partial` are ordinary payload, or decide explicitly that they're
   pcp's. Real trade-off: the deterministic partial *is* the resume state.
5. **`-h` alone should print help**, as rsync does, while staying
   `--human-readable` inside a cluster (`-avh`). Essentially free.
6. **`-u` for symlinks/devices** — measure rsync, then align or record.
7. **Cross-uid symlinks in an operator-named destination path.** Current rsync
   refuses an absolute or relative destination component owned by another uid
   when root runs the copy, preventing an unprivileged user from redirecting a
   privileged copy outside the intended tree. pcp currently follows it just as
   it follows an ordinary destination-argument symlink. The root-only upstream
   `symlink-race-dest` and `symlink-race-relative-dest` tests record this as a
   known failure. This is a strong default-alignment candidate because it closes
   a privilege-boundary write redirection without changing the normal
   same-owner symlink behavior.

## Resolved

- `--delete-excluded`, `--max-delete`, `--delete-after`/`--delete-delay` —
  added (sync-options `118c8ee`).
- Nested destination symlinks were briefly followed at any depth (`rsync -K`
  behavior); PR #7 restored rsync's replace-in-tree, follow-argument-only
  rule, and `--existing` follows it.
- README claimed rsync deletes a `--max-size` casualty under `--delete`;
  measured false, README corrected (this file's commit).
- The automatic journal/marker (whose completion records `--delete` had to
  invalidate) was replaced by the explicit `--checkpoint`; `--delete` records
  deletions in an active checkpoint.
