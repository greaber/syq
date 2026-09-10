# Copy files

```sh
syq cp project --into backup
```

This copies `project` to `backup/project`. Existing files are updated when
needed; unrelated files stay.

The default final summary reports transferred files and bytes, unchanged
files and bytes, directories created, elapsed time, rate, and any errors.

Add `-v` to list copied paths. `-vv` also explains helper selection and
transport; `--stats` adds scan totals, excluded-file counts, connection count,
and available TCP statistics. For example:

```sh
syq cp -vv --stats project --into backup
```

See [diagnosing a slow copy](speed.md#diagnose-a-slow-copy) for interpreting
transport and performance details.

## See where files go

A named directory brings its name along. `--srcs-in` copies its contents;
`--as` chooses an exact destination name.

<div class="copy-demo" data-examples="assets/copy-examples.json">
  <div class="copy-demo-controls" hidden></div>
  <pre class="copy-demo-command"><code>syq cp project --to server --into /backup</code></pre>
  <p class="copy-demo-description" aria-live="polite">Copies project into /backup/project on server. Existing files outside that directory stay.</p>
  <p class="copy-demo-reset">Each example starts from the same files shown under Before.</p>
  <div class="copy-demo-trees">
    <section class="copy-demo-source" aria-label="Source on your machine">
      <h3>Your machine</h3>
      <pre>project/
├── index.html
└── images/
    └── logo.svg</pre>
    </section>
    <section class="copy-demo-before" aria-label="Destination before copying">
      <h3>Server · Before</h3>
      <pre>/backup/
├── index.html (old)
└── notes.txt</pre>
    </section>
    <section class="copy-demo-after" aria-label="Destination after copying">
      <h3>Server · After</h3>
      <pre>/backup/
├── index.html (kept)
├── notes.txt (kept)
└── project/ (new)
    ├── index.html
    └── images/
        └── logo.svg</pre>
    </section>
  </div>
</div>

Note to rsync users: trailing slashes have no special significance in syq's
native commands. `syq rsync` keeps rsync's slash rules.

## Copy over the network

Use `--to` to send files, or `--from` to fetch them:

```sh
# Copy project to /backup/project on server.
syq cp project --to server --into /backup

# Fetch /data/a and /data/b from server into ./data/a and ./data/b here.
syq cp --from server -C /data --src a --src b --into ./data
```

`-C DIR` is shorthand for `--cwd DIR`: look for the source files in `DIR`.
In the second example, `/data` is on the server and `./data` is on your machine.

To use the default destination:

```sh
syq cp project --to server       # put project in your home directory on server
syq cp --from server project     # fetch project into your current directory
```

Endpoints use `[USER@]HOST[:PORT]`, for example `alice@server:2222`.
Host names cannot start with a dash, including when using an `--rsh` wrapper.
Enclose IPv6 addresses in brackets: `alice@[2001:db8::1]:2222`.
A colon in a native path is simply part of the path.

For two remote endpoints, see [Copy between servers](remote-to-remote.md).
To send files to your laptop from a server shell, see
[Send files home from a server](receive.md).

## Progress

Syq shows a progress bar when running in a terminal. It tracks bytes processed;
while files are still being discovered, the percentage is unknown. Wider
terminals also show elapsed time, speed, ETA, and file counts.

Use `--progress` to force the display or `--no-progress` to hide it. `--quiet`
hides it too. After five seconds without a byte update, `no update` shows how
long it has been; this does not by itself mean the connection has failed.
Wait for the final summary to confirm success, even if the byte bar looks full.

The bar also covers `syq rm`, counting entries instead of bytes.
`--progress-json` provides JSON progress for displays; use
[results records](automation.md) to track completion in scripts.

## Choose a destination

| Option | Meaning |
|---|---|
| `--into DIR` | Put the selected names inside `DIR` |
| `--as PATH` | Copy one named source to exactly `PATH` |
| `--into-new DIR`, `--as-new PATH` | Also require the destination not to exist |
| `--into-existing DIR`, `--as-existing PATH` | Also require it to exist |

```sh
# Copy report.txt under a new name; refuse to overwrite an existing entry.
syq cp report.txt --as-new reports/final.txt
```

`--into` uses or creates a directory. `--as` can rename a directory too.
Sources that would collide at one destination are refused before copying.

## Choose which existing files to update

By default, selected destination entries are updated when needed.
These options apply to individual entries inside the copy:

| Option | Behavior |
|---|---|
| `--only-new` | Copy entries found missing; keep entries found present and their metadata |
| `--only-existing` | Update existing entries; create no missing entries or directories |
| `--skip-newer` | Skip regular files whose destination modification time is newer |

```sh
# Import new files without replacing existing files.
syq cp --only-new --srcs-in incoming --into archive

# Refresh only files already in the destination.
syq cp --only-existing --srcs-in project --into deployed
```

`--only-new` keeps existing entries and their metadata, while adding missing
children to existing directories. Those directories must be writable; syq
does not change their permissions to add files. Adding children can still
change directory timestamps. A dry run does not test write access.

If a source directory meets an existing non-directory, `--only-new` skips that
subtree. `--only-existing` skips a subtree when its destination is missing or
is not a directory. It cannot combine with `--into-new` or `--as-new`.
The placement options `--into-existing` and `--as-existing` check only the
placement path, rather than every copied entry.

`--skip-newer` compares timestamps, not the age of the contents. It affects only
regular-file pairs; replacing a different entry type still occurs. Combine it
with `--only-existing` to avoid creating missing entries too.

`--only-new` cannot combine with either policy. Neither `--only-new` nor
`--skip-newer` can combine with `--inplace`: an interrupted write could leave
an incomplete file that the next run skips. Restricted receivers also refuse
`--only-existing --inplace`.

These options do not disable `--prune`; requested pruning still removes extras.

## Preview changes

`--dry-run` previews a copy without changing the destination. On its own it
prints a summary; combine it with `-v` to list the planned changes by path:

```sh
syq cp --dry-run -v --srcs-in project --into backup
```

The summary shows where files would land, what would change, and how much
data may move. Copy data stays unchanged; a requested results file is still
written. The filesystem can change between preview and execution.

## Mirror a directory

`--prune` removes destination files that have no counterpart in the source:

```sh
syq cp --prune --max-delete 100 --srcs-in build --into-existing deploy
```

This updates `deploy` from `build`, then removes extras. Preview with
`--dry-run -v` first. If more than 100 removals are planned, none are performed
and the command exits 25.

Pruning stays inside the copied directories. Copying named directories `a`
and `b` into `backup` prunes `backup/a` and `backup/b`, leaving `backup/c` alone.
Ignored paths and files skipped by size limits are protected.

Scan or copy errors prevent deletion. Syq refuses to prune a destination
that it can identify as containing its source. Checks cover local paths and
ordinary SSH on the same host; checking SSH aliases also requires access to
the source’s temporary directory from the destination. The check cannot identify
shared storage across different hosts or restricted-receiver aliases. An
interruption after deletion starts can leave some extras removed. Do not prune
while another copy is writing into the same tree: its completed files can be treated as extras. Recognized partial files
and replacement recovery entries (`.syq-swap-<pid>-<number>`) are protected
from pruning, along with their contents and parent directories. With `-v`, syq
lists each extra file it keeps because its name matches the partial-file format.
When a copied path resolves to a different filename spelling at the destination,
pruning protects that entry. If hard links make the match ambiguous, it can keep
additional links to the same file.

## Ignoring paths

```sh
# Use the project's existing ignore rules.
syq cp --ignore-from .gitignore --srcs-in project --into backup

# Skip node_modules and object files.
syq cp --ignore node_modules --ignore '*.o' --srcs-in project --into backup
```

Patterns use gitignore syntax. Rules run in command-line order; the last
match wins. `!` re-includes a path.

| Pattern | Matches |
|---|---|
| `foo` | A file or directory named foo at any depth |
| `/foo` | foo at the source root |
| `foo/` | Directories named foo |
| `*` | Within one path component |
| `**` | Across path components |

Ignored directories are not scanned. To keep part of one, include the parent:

```sh
# Skip other logs, but copy logs/keep and its contents.
syq cp --ignore 'logs/*' --ignore '!logs/keep/' --srcs-in project --into backup
```

Ignored paths are also protected from pruning.

## Resume an interrupted copy

Rerun the command. Completed files are skipped; partially copied files can
reuse matching blocks. Each run writes its own fresh partial beside the
destination and replaces the final file only when complete. When resuming,
syq can copy bytes from a previous partial or the existing destination into its
own output, hash the bytes it copied, and transfer blocks that differ from the
source before publishing. The previous partial stays unchanged. Reuse is best
effort; local direct copies can be faster than looking for reusable blocks and
take priority.

Resuming requires space for the new output as well as the previous partial.
This can require enough free space for another complete file, even when only
a small amount remains to transfer.

Syq preserves filename bytes and reports names the destination cannot create as
copy errors. It checks exact destination and partial-file name conflicts, but
does not preflight case or Unicode equivalence. Source names that the destination
considers equivalent can overwrite one another; rename them before copying when
you need to preserve both files.

A directory cannot replace a file or symlink, and a file, symlink or special
file cannot replace a directory, even an empty one. Syq reports an error and
skips the conflicting directory's subtree. This follows cp's conservative
behavior and applies to both `syq cp` and `syq rsync`.

Replacements between non-directory entries stage the new entry before
publication. Some guarded replacements require an atomic exchange; if the
filesystem does not support it, the old entry is preserved and the operation
fails. An interrupted exchange can leave the previous entry beside its
replacement under a `.syq-swap-...` name; inspect it before removing it.

Concurrent copies use separate partials. With unchanged sources, each completed
file comes from one copy; different copies may win for different files. This
does not make a whole tree a snapshot. `--inplace` still exposes unfinished
updates, and pruning can delete another copy's completed files.

Partials are named `.FILENAME.syq-tmp.RANDOM`, with 16 random characters at the
end. The filename portion is shortened or omitted when space is tight. Syq
removes its own partial when it publishes the completed file. Interrupted runs
can leave partials behind, including after a later successful retry. Partials
with shortened or omitted filenames may not be reused.

To remove leftover partials, stop copies writing into the tree, then preview
and run:

```sh
syq clean-partials --dry-run -v backup
syq clean-partials backup
# Search several remote trees with the parallel removal workers.
syq clean-partials --on server --cwd /data -j 8 backup archive
```

This command removes regular files with the current partial-name format. It
keeps directories, other filenames, and symlinks, and does not follow symlinks.
Use `--root DIR` to confine traversal and `--results FILE` for removal results.
The results use the same `mode: "rm"` records as `syq rm`; they do not distinguish
a partial sweep from other removal commands.
A regular file deliberately named like a partial is also selected. Old partial
formats are neither reused nor selected by this command; remove those manually.

## Check file contents

Syq normally skips files whose size and modification time match, including
fractional seconds. It preserves the source timestamp at the destination, so
the machines' clocks do not need to agree. A changed timestamp triggers checking
even when it is older than the destination's, unless you request `--skip-newer`.
A destination that rounds timestamps to coarser precision can cause unchanged
files to be checked or copied again on later runs.

Matching metadata is a shortcut, not proof that contents match. An edit can
preserve both size and timestamp, and some filesystems record timestamps with
less precision. `--hash` checks contents even when those two attributes match:

```sh
syq cp --hash --srcs-in project --into backup
```

This changes how syq decides what needs copying. For larger network
copies, syq still compares blocks when size or modification time differs,
even without `--hash`, so it can reuse unchanged data. Local and small copies
may use faster paths instead.

Transferred data is always checked for corruption. For files being changed by
another program, stop the writer or copy a snapshot. No copy makes the whole
tree transactional or guarantees durability across power loss.

To compare without writing, use `--verify-only`:

```sh
syq cp --verify-only --srcs-in project --into backup
```

This compares file contents, symlink targets, and entry types without writing.
Missing or different entries make the command fail. It does not compare metadata
or look for extra destination files.

For two servers, add `--coordinate-at local` to compare through your machine
using ordinary SSH access, with no restricted receiver enrollment. This also
supports `--results`. See [remote verification](remote-reference.md#verification).

## In-place writes

By default, syq builds an updated file beside the old one and replaces it when
complete. `--inplace` writes directly into the destination file instead:

```sh
syq cp --inplace large-file --to server --into /backup
```

This saves temporary disk space and can avoid copying unchanged data into a
new file. Readers can see a mixture of old and new contents during the copy.
If interrupted, the incomplete file stays at its final name until you finish
the copy. Writes through a hard link also affect its other names.

Use the default when other programs need to read a complete file throughout
an update. [Copies sent back to your laptop](receive.md) do not support `--inplace`.

## Preserve metadata

Copy keeps modification times and copies symlinks as symlinks. New files use
the source read, write, and execute permissions limited by the destination
umask; existing files keep their destination permissions. For example, a new
script with mode `755` stays executable with umask `022`. Source setuid,
setgid, and sticky bits are not copied by default. On macOS, an existing
destination directory must be readable before syq can temporarily repair
missing write or search permission.

To copy source permissions exactly, including onto existing files, or request
ownership too:

```sh
syq cp --preserve=permissions,ownership project --into backup
```

`permissions` preserves modes; `ownership` requests numeric owner and group;
`specials` enables device, FIFO, and socket nodes. Ownership needs suitable
permissions on the destination. Hard links, ACLs, and xattrs are not preserved.

## Symlinks

A named symlink is copied as a link. Syq refuses to follow links in paths you
supply unless you ask it to:

| Option | Follow links in |
|---|---|
| `--follow-src` | Source paths |
| `--follow-dst` | Destination paths |
| `--follow` | Both, plus files named by options such as `--ignore-from` |

```sh
# Copy the directory current-project points to as backup/current-project.
syq cp --follow-src current-project --into backup
```

With `--as link`, the final link itself is replaced, even with `--follow-dst`.
Links found inside a directory are never followed. See the
[security explanation](security.md#filesystem-attacks).

## Keep sources inside a directory

`--root DIR` both sets the source directory and prevents selections from
escaping it:

```sh
# Copy /srv/data/reports and /srv/data/photos into backup.
syq cp --root /srv/data reports photos --into backup
```

Sources must be relative to that root. A selection such as `../private` is
refused; even with `--follow-src`, symlinks cannot lead outside the root.
Unlike `-C`, this is a boundary, not just a starting directory. It does not
constrain the destination.

## Output and diagnostics

Human output, including `persist status` and `persist receive status`, escapes
terminal control characters, Unicode line separators, and directional marks
in names and peer diagnostics. JSON status output keeps the original values.

## More options

`--src-non-dir` and `--src-dir` require a non-directory or directory respectively.
Use `--min-size` and `--max-size` to select regular files by size.

For parallelism and bandwidth controls, see [Speed](speed.md). For scripts,
see [Automation results](automation.md).

Use `--help` (or `-h`) for everyday options and `--help-all` for the full list,
including tuning, scripting, and manual setup. `syq help COMMAND` shows the
same help without running the command. In `syq rsync`, `-h` means
human-readable sizes; use `--help` for help.
