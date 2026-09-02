# Composability

Composability, for a file tool, means that other programs and other people can
build on it: they can ask what it would do before it does it, hand it
selection and placement as data instead of flags, and get results back as data
instead of a scrolling log. The classical commands fuse planning and
execution, which is why every serious deployment ends up wrapping `cp`,
`rsync`, and `rm` in scripts that re-derive what those tools already knew.

This document describes what syq offers today under three headings, then the
automation interface that is in design. [Mappings](mappings.md) is the
detailed guide to the manifest format; the [command reference](reference.md)
has the exact option semantics.

## Planning before execution

`-n`/`--dry-run` connects to every endpoint, scans both sides, and reports
what a real run would do, without creating, updating, or deleting anything:

```text
syq: dry-run summary
  mapping: ./dataset/ -> gpu01:/scratch/run42 (directory contents)
  changes: 82,411 regular files; 96 directories; 14 symlinks; 3 metadata-only entries; 2 type replacements among them
  deletions: 7 entries planned after a successful copy
  logical data: 1.70 TiB in 82,411 files needing content work (upper bound); 340 GiB in 18,204 files with unchanged content
  exclusions: 3 paths/subtrees pruned by ignore rules; 12 other entries
  route: encrypted TCP to gpu01; 16 initial connections (auto-tuned)
```

Add `-v` for a typed line per intended change (`create file PATH (destination
missing)`, `delete PATH (destination only)`). The details of each line are in
[Previewing a copy](reference.md#previewing-a-copy).

Several guarantees make the plan more than a printout:

- **Conflicts are refused before mutation.** With several sources, syq scans
  them all before writing anything, so two sources that map onto one
  destination path, or a source that names the destination file itself, fail
  before the destination is touched. A mapping manifest gets the same check
  across every entry.
- **Placement preconditions are explicit.** Native `--into-new`,
  `--into-existing`, `--as-new`, and `--as-existing` state what the target must
  look like, and a mismatch fails before transfer begins. Rsync's rule that
  the meaning of `dest` depends on whether it already exists is confined to
  `syq rsync`.
- **Deletion is guarded.** `--delete` runs only after the copy, only after a
  complete and error-free scan of both sides, and `--max-delete N` deletes
  nothing at all when more than N deletions are planned.
- **`--dry-run` and `--verify-only` are read-only by construction.** Under the
  command-restricted remote-to-remote path, the signed grant marks them
  read-only and the receiver rejects every mutation even if the sending host
  attempts one.

What a plan does not give you is a transaction. Filesystems have no
multi-object atomicity: permissions can change or a disk can fill between the
plan and the write, and a partially executed plan cannot always be rolled back.
Syq's staged writes make each *file* appear atomically complete, and the
deterministic partial-file names make reruns converge, but the run as a whole
is not reversible. The current preflight is also an assessment of the tree at
that moment, not a frozen ledger that can later be executed unchanged; a plan
you can hand back to syq is part of the automation interface below.

## Selection and placement as data

Everything a command line can express about *what* to move and *where*, a file
or a stream can express too:

- `--ignore PATTERN` and `--ignore-from FILE` take gitignore syntax, so the
  `.gitignore` you already maintain filters a copy
  ([Ignoring paths](reference.md#ignoring-paths---ignore---ignore-from)).
- `--files-from FILE` (and `--from0`) copies exactly the listed paths without
  walking the source, which is the point on a slow filesystem when the list is
  already known ([Copying a list](reference.md#copying-a-list---files-from)).
- Native selectors separate the endpoint (`--from host`), the working
  directory (`-C DIR`), the selection (`--src`, `--src-src`, `--src-file`,
  `--src-dir`, and their plural forms), and the placement (`--into`, `--as`),
  so a program can compose a command from parts without re-implementing rsync's
  colon and trailing-slash rules ([Native
  commands](reference.md#native-commands)).
- A **mapping** is a JSON-lines manifest of source→destination claims. `syq
  map` emits one for any selection; `syq cp --mapping` executes one. Between
  them, any tool that edits JSON can reshape a transfer, and syq checks the
  whole manifest for conflicting destinations before a byte moves:

  ```sh
  syq map --src-src photos \
    | jq 'select(.kind == "file")
          | .dst.value = (.mtime | gmtime | strftime("%Y/%m")) + "/" + .dst.value' \
    | syq cp --mapping - -C photos --to nas --into /archive
  ```

  Rsync hard-codes single instances of this idea as flags (`--iconv` renames,
  `-R` with `/./` re-anchors, `--min-size` filters); with a mapping they all
  have the same shape, and the manifest a program writes today is one `while
  read` loop of `rsync` calls replaced by one parallel, resumable run. See
  [Mappings](mappings.md).

## Results as data

- **Exit codes** distinguish complete success (0), a finished run with
  per-file failures (23), a deletion phase refused by `--max-delete` (25), and
  a fatal error (1). See [Exit codes](reference.md#exit-codes).
- `--progress-json` writes one JSON line per second on stderr for progress
  displays and monitoring; `--stats` prints the summary counts, where the
  auto-tuner settled, and the kernel's TCP counters.
- `--results FILE` (or `-` for stdout, together with `-q`) on native `cp`
  writes an NDJSON outcome stream: a `run` record, one `operation_result` per
  settled mutation and per failed mapping entry, an `error` record per counted
  error, and exactly one terminal `result` with the exit code and aggregate
  counts. Failed operation records carry `src`, `dst`, and `kind`, so a retry
  manifest is one filter away:

  ```sh
  syq cp --mapping big.ndjson -C src --to nas --into /data --results r.ndjson
  jq -c 'select(.type == "operation_result" and .disposition == "failed"
                and .retryable != "no") | {src, dst, kind}' r.ndjson \
    | syq cp --mapping - -C src --to nas --into /data
  ```

  This is what an exit code cannot express: which entries failed, and whether
  a retry could help. The records carry `schema_version: 0`, an explicitly
  unstable preview of the automation interface below.

## Reruns converge

A syq command is safe to run again. Files whose size and mtime already match
are skipped; an interrupted file resumes from its partial; a destination file
that differs is hashed in blocks and only the mismatching blocks move; and
because the partial-file name is derived from the logical command rather than
chosen at random, the rerun finds its own state without a state file. Two
different commands into one tree produce the union of their files. The
[resume section](reference.md#resume-and-checkpoints) has the exact rules and
the one deliberate exception, `--checkpoint`, which trusts recorded
completions to skip destination lookups on very large repeated jobs.

## Programs and SDKs

Preview SDKs for Python, JavaScript/TypeScript, and Go live in
[`sdk/`](../sdk/). Each runs the `syq` executable with an argument array (never
a shell), pins one exact, tested syq release, and downloads and verifies that
release's official binary on first use, so the pairing an application tested
is the pairing it ships. They deliberately expose only raw execution and
version discovery today and do not parse human output.

Their typed surface will follow syq's versioned NDJSON automation interface,
which is in design. Its shape: a mapping is the input half (selection and
placement as a manifest, shipped as `--mapping`); an enveloped event stream is
the output half (the `--results` preview is its first slice); and a dry-run
*trace* of intended operations, in the same vocabulary as results, is the plan
you can inspect, filter, and hand back. The contract will be versioned, with
fixtures, before any SDK claims a stable copy API. Until then, `--dry-run`,
exit codes, `--progress-json`, `--results`, and mappings are the composition
points, and the executable remains authoritative for semantics, exit status,
and safety checks.
