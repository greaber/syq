# Local compatibility test references

The [user guide](../../docs/rsync-compat.md) describes behavior. This file maps
those claims to tests in [`tests/local.rs`](../local.rs), alongside the
upstream suite's [generated ledger](LEDGER.md). A test reference is evidence
for its named behavior, not a score for compatibility as a whole.

## Compatible behaviors

| Behavior | Status | Test |
|---|---|---|
| Path rules: `src` copies the directory, `src/` its contents; a single file lands as `dest/file` when `dest` is a directory; several sources need a directory destination | measured | `trailing_slash_copies_contents`, `dir_into_existing_dir`, `dir_into_missing_dest_creates_basename`, `single_file_into_existing_dir`, `single_file_to_new_name`, `multiple_sources_require_dir_dest` |
| Quick check: size + mtime; without `-t` every file is re-sent | measured | `updates_changed_file_and_skips_symlink_only_when_same`, `skip_reconciles_mode` |
| `--delete` scope: only inside the directories being synced; a single-file source deletes nothing | measured | `delete_only_inside_directories_the_sources_map_onto`, `delete_with_nested_roots_deletes_once` |
| Ignored/excluded paths are protected from deletion by default; `--delete-excluded` lifts that | measured | `delete_removes_extras_and_protects_ignored`, `delete_nested_roots_keep_their_own_anchored_ignores`, `delete_excluded_removes_ignored_destination_paths` |
| A directory that can't be emptied because of protected content is reported and left (rsync: `cannot delete non-empty directory`; syq: `not deleting keep/: it holds ignored paths`) | measured | `delete_removes_extras_and_protects_ignored` |
| Deletion is skipped when listing the source hit errors (rsync: `IO error encountered -- skipping file deletion`) | measured; see "Compatible subsets or approximations" 1 for the transfer-time case | `delete_is_skipped_when_the_source_scan_has_errors`, `unreadable_source_root_disables_delete` |
| Files the source has but a rule skips (`-u`, `--existing`, `--ignore-existing`, `--max-size`/`--min-size`, symlinks without `-l`, specials without `-D`) are not deleted, even when the destination entry is a non-empty directory | measured on 3.2.7 and 3.5.0 | `delete_never_removes_paths_the_source_has_but_skips`, `delete_leaves_directory_contents_under_a_skipped_source_path`, `size_limits_filter_files_and_protect_them_from_delete`, `delete_keeps_partials_of_filtered_files` |
| `-u`/`--update`: a destination regular file with a newer mtime is left alone | measured for regular files; see "Compatible subsets or approximations" for symlinks/devices | `update_skips_files_newer_on_the_destination` |
| `--existing` / `--ignore-existing`, including `--existing` covering directories | measured | `ignore_existing_and_existing`, `existing_never_creates_the_destination_root`, `existing_leaves_a_file_where_a_source_directory_would_go`, `existing_dry_run_reports_no_missing_directory_changes`, `existing_opens_up_readonly_dirs_even_after_a_symlinked_dir` |
| `--max-size` / `--min-size` on regular files only; `K`/`M`/`G` suffixes | measured | `size_limits_filter_files_and_protect_them_from_delete`, `bad_size_limits_fail_before_anything_connects` |
| `--files-from` baseline: paths relative to one source; implied parents created; a plain listed directory is copied without its contents unless `-r` is given explicitly (`-a` doesn't count); `--from0`; `-` reads stdin; blank entries and entries starting with `#` or `;` dropped in both separator modes (literal names remain reachable as `./#name` and `./;name`) | measured; see [file-list parsing differences](../../docs/rsync-compat.md#file-list-parsing-and-help) | `files_from_copies_listed_paths_with_their_parents`, `files_from_treats_hash_and_semicolon_entries_as_comments`, `files_from_creates_listed_and_implied_dirs_without_r`, `files_from_repeats_and_late_listed_dirs_across_chunks`, `files_from_root_may_be_a_symlink_and_root_lines_are_rejected` |
| `--delete-after` / `--delete-delay` accepted as synonyms of `--delete` (they describe what syq does) | by construction | `delete_after_and_delay_are_synonyms` |
| `--max-delete N` exists and exits 25 when it trips | believed (exit code matches rsync); see "Intentional divergences" for positive-limit semantics | `max_delete_refuses_everything_past_the_limit` |
| `--max-delete=0` reports destination-only entries without deleting them; `--max-delete=-1` is accepted as the historical synonym; without `--delete` the option has no effect | measured for syq; rsync behavior documented upstream | `max_delete_refuses_everything_past_the_limit` |
| A destination symlink named on the command line is followed when owned by root or by the receiving process's effective uid; a component owned by anyone else is refused | measured, including absolute and relative root/cross-uid cases | `symlink_destination_is_followed`, `destination_root_symlink_preserves_target_metadata_for_both_spellings`, `existing_updates_through_a_destination_root_symlink_to_a_dir`, `foreign_owned_destination_root_symlink_is_refused` |
| A symlink to a directory found *inside* the destination tree is replaced with a real directory; only the argument itself is followed (rsync without `-K`) | measured | `in_tree_destination_symlink_is_replaced_not_followed`, `existing_does_not_write_through_a_destination_symlink_dir` |
| `-P`, `-h`, `--partial`, `--numeric-ids`, `-V` accepted as no-ops/aliases; common unsupported flags are rejected with an explanation | by construction | `rsync_compat_noops_are_accepted`, `unsupported_rsync_flags_explain_themselves` |
| `-B` and `--block-size` select syq's transfer/hash block size | by construction | `checksum_repairs_silent_corruption` |
| A remote source and remote destination are refused before connecting, as by rsync | by construction | `rsync_rejects_remote_to_remote` |
| Source entries whose names look like syq's partial files (`.name.syq-part.<id>`) are copied as data like any other file (with one warning); only the exact case where a source path equals the partial file this copy would use for another file is refused, before anything is written | by construction | `sidecar_named_source_directory_is_payload`, `delete_treats_sidecar_patterned_files_as_ordinary_extras`, `partial_named_symlink_is_a_symlink_not_a_leftover` |

## Focused regression tests

### Deletion after transfer

*Tests: `delete_with_inplace_replacing_many_symlinks`,
   `delete_removes_only_this_jobs_orphaned_sidecars`.*

### Deletion ceiling

*Test:
   `max_delete_refuses_everything_past_the_limit`.*

### Symlinked file-list parents

*Tests:
   `files_from_rejects_symlinked_ancestors_and_recurses_only_listed_dirs`,
   `files_from_leaves_no_ancestors_behind_on_a_bad_chain`,
   `files_from_symlink_conflict_is_order_independent`.*

### Destination conflicts

*Tests: `duplicate_destination_rejected`,
   `exactly_repeated_sources_are_deduplicated_without_changing_placement`,
   `dir_vs_file_destination_collision_rejected`,
   `cross_source_collision_is_detected_before_any_change`,
   `copy_onto_itself_among_sources_is_order_independent`,
   `three_claimants_are_validated_as_a_group`.*

### Keeping existing entries

*Test: `ignore_existing_keeps_a_file_where_a_source_directory_maps`.*

### Verification scope

*Test: `verify_only_checks_the_filtered_scope`.*

### Source listing failure

*Tests:
   `unreadable_source_root_disables_delete`,
   `delete_is_skipped_when_the_source_scan_has_errors`.*

### File-list option restrictions

*Test:
   `files_from_rejections_and_stdin`.*

## Review tasks

These questions were moved from the public guide on 2026-09-05, against
`master` at `87c63e7`. They are review tasks, not promises to change behavior.
Keep the public guide's current limitations accurate if a decision changes.

- Review the `--files-from` path rules together: rejection of `..`, stripped
  trailing slashes, refusal of `.` and `/` entries, and the missing `-0` alias.
- Decide whether `-h` alone should print help while remaining a
  human-readable no-op in an option cluster.
- Measure rsync's `-u` behavior for symlinks and devices, then choose whether
  to align or document the difference. Syq currently checks regular files only.

Common unsupported flags are rejected by `reject_unsupported_rsync_flags` in
`src/cli.rs`; the public guide need not expose that implementation detail.
