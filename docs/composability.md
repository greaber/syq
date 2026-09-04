# Composability

Composability, for a file tool, means that other programs and other people can
build on it: they can ask what it would do before it does it, hand it
selection and placement as data instead of flags, and get results back as data
instead of a scrolling log. The classical commands fuse planning and
execution, which is why every serious deployment ends up wrapping `cp`,
`rsync`, and `rm` in scripts that re-derive what those tools already knew.

This document describes what syq offers under three headings.
[Mappings](mappings.md) is the detailed guide to mappings and their manifest
file format; the [command reference](reference.md) has the exact option
semantics.

## Planning before execution

`-n`/`--dry-run` connects to every host involved, scans both sides, and reports
what a real run would do, without creating, updating, or deleting anything:

```text
syq: dry-run summary
  mapping: ./dataset/ -> gpu01:/scratch/run42 (directory contents)
  changes: 82,411 regular files; 96 directories; 14 symlinks; 3 metadata-only entries; 2 type replacements among them
  deletions: 7 entries planned after a successful copy
  logical data: 1.70 TiB in 82,411 files needing content work (upper bound); 340 GiB in 18,204 files with unchanged content
  exclusions: 3 paths/subtrees skipped by ignore rules; 12 other entries
  route: encrypted TCP to gpu01; 16 initial connections (auto-tuned)
```

Add `-v` for a typed line per intended change (`create file PATH (destination
missing)`, `delete PATH (destination only)`). The details of each line are in
[Previewing a copy](reference.md#previewing-a-copy).

Several guarantees make the plan more than a printout:

- **Conflicts are refused before anything is written.** With several sources, syq scans
  them all before writing anything, so two sources that map onto one
  destination path, or a source that names the destination file itself, fail
  before the destination is touched. A mapping manifest gets the same check
  across every entry.
- **Placement preconditions are explicit.** Native `--into-new`,
  `--into-existing`, `--as-new`, and `--as-existing` state what the destination
  must look like, and a mismatch fails before transfer begins. Rsync's rule
  that the meaning of `dest` depends on whether it already exists applies only
  to `syq rsync` (rsync mode).
- **Deletion is guarded.** Pruning, that is, deleting paths that exist only at
  the destination (`cp --prune`, or `--delete` under `syq rsync`), runs only
  after the copy, only after a complete and error-free
  scan of both sides, and `--max-delete N` deletes nothing at all when more
  than N deletions are planned.
- **Capacity is checked up front.** When the destination is missing or an
  empty directory, the plan compares the copy's logical size and its number of
  objects (files, directories, symlinks, and special files)
  with the space and inodes available to the receiving user, prints the result
  as a `capacity` line, and a real run refuses to start if they do not fit. It
  is a sanity check, not a reservation.
- **`--dry-run` and `--syq-verify-only` are read-only by construction.** For a
  remote-to-remote copy through the restricted receiver (the command-restricted
  receiver, a forced command on hostB that syq installs when you enroll a
  destination), the signed grant marks a dry run read-only, and the receiver
  rejects every write even if the sending host attempts one. Verification-only
  is an rsync-mode option; it cannot run between two remote endpoints.

What a plan does not give you is a transaction. A filesystem cannot make a
change to several files all-or-nothing: permissions can change or a disk can
fill between the plan and the write, and a partially executed plan cannot
always be rolled back. syq writes each file to a partial file and renames it
into place, so each *file* appears either complete or not at all, and because
the partial file's name is derived from the command, a rerun finds it and
continues; but the run as a whole is not reversible. The check before anything
is written is also a snapshot of the tree at that moment, not a frozen plan
that can later be executed unchanged.

## Selection and placement as data

Everything a command line can express about *what* to move and *where*, a file
or a stream can express too:

- `--ignore PATTERN` and `--ignore-from FILE` (`--syq-ignore` and
  `--syq-ignore-from` under `syq rsync`) take gitignore syntax, so the
  `.gitignore` you already maintain filters a copy
  ([Ignoring paths](reference.md#ignoring-paths)).
- `syq rsync --files-from FILE` (and `--from0`) copies exactly the listed paths
  without walking the source, which is the point on a slow filesystem when the
  list is already known ([Copying a list](reference.md#copying-a-list---files-from)).
- Native selectors separate the host (`--from host`), the working
  directory (`-C DIR`), the selection (`--src`, `--srcs-in`, `--src-file`,
  `--src-dir`, and their plural forms), and the placement (`--into`, `--as`),
  so a program can compose a command from parts without re-implementing rsync's
  colon and trailing-slash rules ([Native
  commands](reference.md#native-commands)).
- A **mapping** is an NDJSON file, the manifest, of source→destination claims:
  each line names one source path and the destination path it claims. `syq
  map` emits one for any selection; `syq cp --mapping` executes one. Between
  them, any tool that edits JSON can reshape a transfer, and syq checks the
  whole manifest for conflicting destinations before a byte moves:

  ```bash
  set -o pipefail
  syq map --srcs-in photos \
    | jq -c 'select(.kind == "file")
          | .dst.value = (.mtime | gmtime | strftime("%Y/%m")) + "/" + .dst.value' \
    | syq cp --mapping - -C photos --to nas --into /archive
  ```

  Rsync hard-codes single instances of this idea as flags (`--iconv` renames,
  `-R` with `/./` re-places, `--min-size` filters); with a mapping they all
  have the same shape, and the manifest a program writes today is one `while
  read` loop of `rsync` calls replaced by one parallel, resumable run. See
  [Mappings](mappings.md).

## Results as data

- **Exit codes** distinguish complete success (0), a finished run with
  per-file failures (23), a deletion phase refused by `--max-delete` (25), a
  fatal error (1), and an argument or usage error (2), which produces no
  results stream at all. See [Exit codes](reference.md#exit-codes).
- `--progress-json` (`--syq-progress-json` under `syq rsync`) writes the
  progress stream, one JSON line per second on stderr, for progress displays
  and monitoring. The format of those lines is not a documented contract and
  may change; a new caller that needs stable machine-readable output should
  use `--results` instead. `--stats` prints the summary counts, the connection
  count the auto-tuner ended at, and the kernel's TCP counters.
- `--results FILE` on native `cp` (with or without `--prune`) and native `rm`
  writes the results stream, an NDJSON record of what the run did, to a
  freshly created file; `--results-fd N` writes to a file descriptor you
  opened instead. For a copy the stream carries a `run` record, sampled
  `progress` records, one `operation_result` per finished change to the
  destination and per failed mapping entry (with `retryable`, and an error
  `class` where known), `trace` records (one per change a real run would make)
  instead of results under `--dry-run`, an `error` record per counted error,
  and exactly one terminal `result` whose numbers also render the human
  summary; a removal has its own per-selector and per-entry record types. It
  is schema version 1, with a stated compatibility policy;
  [Automation results](automation.md) is the contract. The stream is always
  written on the machine you invoke syq from. For a remote-to-remote copy
  through the restricted receiver it is *receiver-attested*: built from
  hostB's signed receipt (its record of what it did) rather than from what
  hostA reported, each record marked `"provenance": "receiver_attested"`,
  while the data flows directly between the hosts; without an enrollment, the
  run fails unless `--coordinate-at local` explicitly routes the data through
  your machine. A remote-to-remote dry run with `--results` always needs
  `--coordinate-at local`, because only that coordinator produces the trace
  stream. Failed mapping entries carry `src`, `dst`, and `kind`; failed
  implicit ancestor directories can lack `src` and are non-retryable. Ordinary
  copy and deletion records have no `src`. Once the terminal record says the
  mapping run finished, a retry manifest is one filter away. The
  [mappings guide](mappings.md#machine-readable-results) has that filter,
  including the terminal-record check. This is what an exit code
  cannot express: which entries failed, and whether a retry could help.

## Reruns converge

A syq command is safe to run again. Files whose size and mtime already match
are skipped; an interrupted file resumes from its partial file; a destination file
that differs is hashed in blocks and only the mismatching blocks move; and
because the partial-file name is derived from the logical command rather than
chosen at random, the rerun finds its own state without a state file. Two
different commands into one tree produce the union of their files. The
[resume section](reference.md#resume) has the exact rules.
