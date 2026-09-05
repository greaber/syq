# rsync compatibility

`syq rsync` accepts rsync's command line for local copies, pushes, and pulls.
This page describes which behaviors match, which differ, and which options
are unavailable. See the [command reference](reference.md#rsync-compatibility)
for the accepted options.

**Measured** means compared with upstream rsync 3.5.0 at commit `7c20b077`,
with 3.2.7 also checked where the version matters. **Believed** means based on
upstream documentation rather than a direct comparison. The
[test documentation](https://github.com/greaber/syq/tree/master/tests/rsync-compat)
contains the test inventory and instructions for running it.

## Compatible

| Behavior | Status |
|---|---|
| Path rules: `src` copies the directory, `src/` its contents; a single file lands as `dest/file` when `dest` is a directory; several sources need a directory destination | measured |
| Quick check: size + mtime; without `-t` every file is re-sent | measured |
| `--delete` scope: only inside the directories being synced; a single-file source deletes nothing | measured |
| Ignored/excluded paths are protected from deletion by default; `--delete-excluded` lifts that | measured |
| A directory that can't be emptied because of protected content is reported and left (rsync: `cannot delete non-empty directory`; syq: `not deleting keep/: it holds ignored paths`) | measured |
| Deletion is skipped when listing the source hit errors (rsync: `IO error encountered -- skipping file deletion`) | measured; see "Compatible subsets or approximations" 1 for the transfer-time case |
| Files the source has but a rule skips (`-u`, `--existing`, `--ignore-existing`, `--max-size`/`--min-size`, symlinks without `-l`, specials without `-D`) are not deleted, even when the destination entry is a non-empty directory | measured on 3.2.7 and 3.5.0 |
| `-u`/`--update`: a destination regular file with a newer mtime is left alone | measured for regular files; see "Compatible subsets or approximations" for symlinks/devices |
| `--existing` / `--ignore-existing`, including `--existing` covering directories | measured |
| `--max-size` / `--min-size` on regular files only; `K`/`M`/`G` suffixes | measured |
| `--files-from` baseline: paths relative to one source; implied parents created; a plain listed directory is copied without its contents unless `-r` is given explicitly (`-a` doesn't count); `--from0`; `-` reads stdin; blank entries and entries starting with `#` or `;` dropped in both separator modes (literal names remain reachable as `./#name` and `./;name`) | measured; see [file-list parsing differences](#file-list-parsing-and-help) |
| `--delete-after` / `--delete-delay` accepted as synonyms of `--delete` (they describe what syq does) | by construction |
| `--max-delete N` exists and exits 25 when it trips | believed (exit code matches rsync); see "Intentional divergences" for positive-limit semantics |
| `--max-delete=0` reports destination-only entries without deleting them; `--max-delete=-1` is accepted as the historical synonym; without `--delete` the option has no effect | measured for syq; rsync behavior documented upstream |
| A destination symlink named on the command line is followed when owned by root or by the receiving process's effective uid; a component owned by anyone else is refused | measured, including absolute and relative root/cross-uid cases |
| A symlink to a directory found *inside* the destination tree is replaced with a real directory; only the argument itself is followed (rsync without `-K`) | measured |
| `-P`, `-h`, `--partial`, `--numeric-ids`, `-V` accepted as no-ops/aliases; common unsupported flags are rejected with an explanation | by construction |
| `-B` and `--block-size` select syq's transfer/hash block size | by construction |
| A remote source and remote destination are refused before connecting, as by rsync | by construction |
| Source entries whose names look like syq's partial files (`.name.syq-part.<id>`) are copied as data like any other file (with one warning); only the exact case where a source path equals the partial file this copy would use for another file is refused, before anything is written | by construction |

## Intentional divergences

Each item records the current reason syq does otherwise. Safety is one reason;
architecture and disproportionate implementation cost can also justify a
narrow divergence.

1. **`--delete` runs after the transfer, always; no `--delete-before` /
   `--delete-during`.** rsync defaults to delete-during. syq's rule means a run
   interrupted or failed during scanning or transfer never starts deletion,
   and deletion is computed against a destination that is no longer changing
   (no races with partial-file renames or in-place replaces). Interruption
   after deletion starts can still leave some destination-only paths removed
   and others not. The cost is that space is never
   freed before writing. We consider "the transfer failed after it already
   deleted destination-only files" a worse outcome than "ran out of space."
2. **A positive `--max-delete N` deletes *nothing* past the limit.** rsync
   deletes the first N and then stops. A safety cap that leaves the destination
   in a partially-deleted state is not much of a safety cap; syq refuses
   outright, says so, and exits 25 like rsync. Zero already means delete
   nothing in both programs.
3. **`--files-from` refuses a source parent that is a symlink.** That entry
   fails with exit 23 and leaves no implied directory at the destination;
   other valid entries still copy. A listed symlink together with a path
   through it is refused. Rsync's behavior depends on the version: 3.2.7
   followed the parent, while 3.5 created an implied directory and then
   refused the open. Syq refuses before creating that directory. On a local
   source, `--insecure-links` allows the parent to be followed and creates it
   as a real destination directory. A remote source always refuses traversal
   through symlinked parents; the flag is never sent to it.

4. **Two distinct sources mapping onto one destination file is an error.**
   Measured rsync silently keeps the first. Silent last-writer-wins (or
   first-writer-wins) on a collision is data loss with no message; syq refuses
   and names both. Exactly repeated source arguments are deduplicated before
   scanning while keeping the original source count for placement. Naming
   the destination file itself as one of the sources is a conflict too, not a
   licence for the other source to overwrite it.

5. **`--ignore-existing` keeps an existing non-directory even where the
   source maps a directory.** rsync exempts directories from the flag ("this
   does not ignore existing directories"), and consequently (believed from
   the manpage, not yet measured) deletes an existing destination file to
   make room for a source directory. Under a flag whose whole meaning is
   "what exists is authoritative", that is unrecoverable data loss; syq keeps
   the file and skips the mapped directory with its subtree, with a notice.

## Syq extensions

These options intentionally do not pretend to be rsync options:

| Option | Purpose |
|---|---|
| `--syq-connections N` | Fix syq's parallel connection/worker count |
| `--syq-ignore`, `--syq-ignore-from` | Use syq's ordered gitignore-style filter language |
| `--syq-progress-json` | Emit JSON progress events |
| `--syq-verify-only` | Compare the selected source and destination scope without changing anything |
| `--syq-no-bootstrap` | Require a compatible syq already in the remote `PATH` instead of installing the remote helper (a copy of syq that syq installs on the remote host the first time it connects) |
| `--syq-no-tcp`, `--syq-tcp-plain`, `--syq-tcp-ports`, `--syq-tcp-congestion` | Tune syq's TCP data connections |
| `--syq-pscope PATH` | Use a separate set of kept-alive SSH connections created by `syq persist on --ephemeral` |

The gitignore rules have a broadly similar purpose to rsync filters but are not
syntax-compatible: syq is last-match-wins with `!` re-inclusion, while rsync
uses first-match include/exclude/filter rules with side modifiers and
per-directory merge files. Rsync's `-i` remains `--itemize-changes` and is
rejected because itemized output is not implemented.

`--syq-verify-only` applies `-u`, size limits, `--existing`, and
`--ignore-existing` to the scope it compares; it checks exactly what the
corresponding copy would select.

## Compatible subsets or approximations

1. **Any error while listing the source disables deletion**, the same idea
   as rsync's file-list I/O check. A directory we couldn't read would
   otherwise look like one whose contents vanished. A read failure *during
   transfer* does not disable deletion: the failed file still counts as
   present on the source, so it is never treated as destination-only, and the
   set of destination-only paths is unaffected.
2. **`-u` applies to regular files only.** rsync also compares mtimes for
   symlinks and devices (believed, not measured). A *type change* replaces
   regardless of mtimes: a source directory still replaces a newer destination
   file (as in
   rsync): `-u` is about not regressing newer file content, not about
   protecting whatever exists; that stronger promise is
   `--ignore-existing`'s (see "Intentional divergences" 5).
3. **`--files-from` cannot combine with `--syq-ignore`/
   `--syq-ignore-from` or `--delete`.** Rsync allows filters and deletion with
   a file list. These are explicit restrictions rather than silent semantic
   choices. Syq does not apply filters to a file list or derive a deletion
   region from it.
4. **Deletions are executed over the SSH control connection** in batches of
   1000 (the destination deletes a batch in parallel), not spread over
   syq's TCP data connections. rsync has one connection anyway; this is a
   note about syq's own model.
5. **`--rsync-path PATH` must name syq, not rsync.** The standard spelling and
   placement in the remote-shell command agree, but syq speaks its own protocol
   and cannot launch an rsync peer. Unlike rsync's option, the current value is
   an exact executable path rather than a shell fragment with extra arguments.
6. **`-B`/`--block-size` controls syq's fixed transfer, hashing, and resume
   granularity.** Rsync uses the option within its rolling-checksum algorithm,
   which syq does not implement.

## Not implemented

rsync features syq doesn't have. The common ones are rejected with a one-line
explanation so a pasted rsync command says what to change.

- `--delete-before`, `--delete-during`, `--force`: see "Intentional
  divergences" 1; these are refused rather than pending.
- `-H`/`--hard-links`: separate source names are copied independently; hard
  links between them are not preserved.
- `-L`/`--copy-links`, `--copy-unsafe-links`, `-k`/`--copy-dirlinks`,
  `-K`/`--keep-dirlinks`. The first three would widen what the copy reads by
  following symlinks found inside the source; the last follows an existing
  destination directory link. They are rejected explicitly and are not
  enabled by `--insecure-links`.
- `--safe-links` and `--munge-links`; syq currently preserves selected
  symlink target bytes without filtering or rewriting them.
- `--backup`/`--backup-dir`/`--suffix`.
- `--link-dest`/`--compare-dest`/`--copy-dest`.
- `--relative` (`-R`), `--partial-dir`.
- `-A`/`--acls`, `-X`/`--xattrs`, `-S`/`--sparse`, `-x`/`--one-file-system`.
- `-i`/`--itemize-changes`: rejected with a specific explanation;
  `--syq-verify-only` compares contents but does not provide itemized output.
- `--size-only`, `--ignore-times`/`-I`, `--modify-window`, `--chmod`,
  `--log-file`.
- rsync filter rules (`--exclude`/`--include`/`--filter`); use
  `--syq-ignore` if gitignore semantics are suitable.
- rsync daemon mode / `rsync://`; syq speaks its own protocol.
- Rolling-checksum delta transfer; syq resumes at block granularity.
- Remote-to-remote transfer is deliberately absent from `syq rsync`, matching
  rsync itself; use native `syq cp` or `syq cp --prune`.

## File-list parsing and help

`--files-from` parsing differs from rsync's in these cases, measured against
3.2.7 and 3.5.0:

- A `..` component is rejected rather than clamped at the source root.
- A trailing slash is stripped: `dir/` and `dir` select the same thing.
  Rsync's `dir/` selects the directory's immediate children without `-r`.
- `.` and `/` are rejected rather than treated as entries selecting the root.
- Use `--from0` for NUL-separated input; `-0` is not accepted.

Unlike rsync, `-h` alone does not print help; use `--help`. Within an option
cluster such as `-avh`, it is the same human-readable no-op.
