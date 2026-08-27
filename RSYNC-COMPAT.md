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
its harness. A ten-test subset using only pcp-supported options passed eight;
the two useful failures are open issues 2 and 3 below.

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

## Compatible

| Behavior | Status |
|---|---|
| Path rules: `src` copies the directory, `src/` its contents; a single file lands as `dest/file` when `dest` is a directory; several sources need a directory destination | measured |
| Quick check: size + mtime; without `-t` every file is re-sent | measured |
| `--delete` scope: only inside the directories being synced; a single-file source deletes nothing | measured |
| Ignored/excluded paths are protected from deletion by default; `--delete-excluded` lifts that | measured |
| A directory that can't be emptied because of protected content is reported and left (rsync: `cannot delete non-empty directory`; pcp: `not deleting keep/: it holds ignored paths`) | measured |
| Deletion is skipped when the source scan hit errors (rsync: `IO error encountered -- skipping file deletion`) | measured; pcp is stricter, see "Different" |
| Files the source has but a rule skips — `-u`, `--existing`, `--ignore-existing`, `--max-size`/`--min-size`, symlinks without `-l`, specials without `-D` — are not deleted, even when the destination entry is a non-empty directory | measured on 3.2.7 and 3.5.0 (an earlier README claim that rsync deletes a `--max-size` casualty was wrong) |
| `-u`/`--update`: a destination regular file with a newer mtime is left alone | measured for regular files; see "Different" for symlinks/devices |
| `--existing` / `--ignore-existing`, including `--existing` covering directories | measured |
| `--max-size` / `--min-size` on regular files only; `K`/`M`/`G` suffixes | measured |
| `--files-from` baseline: paths relative to one source; implied parents created; a plain listed directory is copied without its contents unless `-r` is given explicitly (`-a` doesn't count); `--from0`; `-` reads stdin; blank entries dropped | measured; entry *parsing* has gaps, open issue 2 |
| `--delete-after` / `--delete-delay` accepted as synonyms of `--delete` (they describe what pcp does) | by construction |
| `--max-delete N` exists and exits 25 when it trips | believed (exit code matches rsync); see "Different" for the cap semantics |
| A destination *argument* that is a symlink to a directory is that directory | measured |
| A symlink to a directory found *inside* the destination tree is replaced with a real directory; only the argument itself is followed (rsync without `-K`) | measured |
| `-P`, `-h`, `--partial`, `--numeric-ids`, `-V` accepted as no-ops/aliases | by construction |

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
   — open issue 3.

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
   pcp's own model.

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
