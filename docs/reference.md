# Copy files

```sh
syq cp project --into backup
```

This copies `project` to `backup/project`. Existing files are updated when
needed; unrelated files stay. See [`syq cp`](commands/cp.md) for the option list.

Choose the files, then choose their destination. `--from` and `--to` select
machines or buckets; omit them for local paths. Placement options decide
whether to keep the source name or give it a new one.

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

SSH endpoints use `[USER@]HOST[:PORT]`, for example `alice@server:2222`.
Host names cannot start with a dash, including when using an `--rsh` wrapper.
Enclose IPv6 addresses in brackets: `alice@[2001:db8::1]:2222`.
A colon in a native path is simply part of the path.

Use `--to @NAME` to send local source files to a registered receiving machine.
The `@` is required: `--to laptop` selects an SSH destination, while
`--to @laptop` requires that receiver to be connected and pass its identity check.
See [Send files home from a server](receive.md) for setup and destination paths.

Use S3 buckets with the same selectors and placement options:

```sh
syq cp photos --to s3://backups --into laptop
syq cp --from s3://backups laptop/photos --into restored
syq cp --from s3://backups --srcs-in laptop --to s3://archive --into laptop
```

See [S3 options and behavior](object-storage.md) for credentials and filesystem differences.

For two SSH endpoints, see [Copy between servers](remote-to-remote.md).

### Transport compression

Remote filesystem copies compress data in transit by default. Each connection
starts with LZ4 and can switch to Zstd level 1 or 3 when its writes drain more
slowly, then back to LZ4 as they speed up. This uses the observed transport
write rate, which includes SSH and receiver backpressure, rather than the
network interface's advertised speed.

Each block is compressed independently and sent compressed only when that
saves at least 1% of its size. A poorly compressing block does not stop syq
from trying the next one. Use `--no-compress` to disable transport compression.

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

For a missing or empty destination, syq checks available space and, where the
filesystem reports it, capacity for new files. It refuses a clear shortage,
but these estimates do not guarantee that the copy will fit.

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

For S3 downloads with these flags, the summary's unchanged-file count includes
skipped symlinks selected through a prefix, but excludes symlinks named
directly or through `--mapping`.

If a source directory meets an existing non-directory, `--only-new` skips that
subtree. `--only-existing` skips a subtree when its destination is missing or
is not a directory. It cannot combine with `--into-new` or `--as-new`.
The placement options `--into-existing` and `--as-existing` check only the
placement path, rather than every copied entry.

`--skip-newer` compares timestamps, not the age of the contents. It affects only
regular-file pairs; replacements between non-directory entry types still
occur, but replacing a directory with a non-directory or the reverse is
refused. Combine it with `--only-existing` to avoid creating missing entries too.
It cannot combine with `--as-fd`; use a named destination so syq can check its
timestamp before opening it.

`--only-new` cannot combine with either policy. Neither `--only-new` nor
`--skip-newer` can combine with `--inplace`: an interrupted write could leave
an incomplete file that the next run skips. Restricted receivers also refuse
`--only-existing --inplace`.

These options do not disable `--prune`; requested pruning still removes extras.

## Preview changes

`--dry-run` shows planned changes without carrying out the copy or deletions.
Add `-v` to list the changes by path:

```sh
syq cp --dry-run -v --srcs-in project --into backup
```

The summary shows where files would land, what would change, and how much
data may move. A requested results file is still written, and remote setup may
cache the helper or [install syq](install.md#automatic-installation-on-ssh-servers).
The filesystem can change between preview and execution.

## Mirror a directory

`--prune` removes destination files that have no counterpart in the source,
including [copies to and from S3](object-storage.md):

```sh
syq cp --prune --max-delete 100 --srcs-in build --into-existing deploy
```

This updates `deploy` from `build`, then removes extras. Preview with
`--dry-run -v` first. If more than 100 removals are planned, none are performed
and the command exits 25.

Pruning stays inside the copied directories. Copying named directories `a`
and `b` into `backup` prunes `backup/a` and `backup/b`, leaving `backup/c` alone.
Ignored paths are protected.

Scan or copy errors prevent deletion. An interruption after deletion starts
can leave some extras removed. Do not prune while another copy is writing into
the same tree: its completed files can be treated as extras.

Keep the source outside the destination you are pruning. Syq checks this for
local copies and remote paths with the same host name, user, and port, but
cannot detect overlap through different SSH aliases, local-to-SSH connections,
or shared storage across hosts.

Pruning keeps syq's partial files and [recovery entries](#resume-an-interrupted-copy),
including their contents and parent directories. Use `-v` to see files kept
because their names match the partial-file format. If different filename
spellings resolve to a copied file, syq protects it; this can also keep extra
hard links to it.

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

Rerun the command. Completed files are skipped, and syq can reuse matching
parts of an interrupted file. It writes a new temporary file beside the
destination and replaces the final file only when complete. Previous partials
stay unchanged. Reuse is not guaranteed; local copies may use the filesystem's
faster copy operations instead.

When resuming, syq reuses the interrupted copy rather than the old destination.
If the source changes between attempts, this can resend bytes that still match
the old destination.

Resuming requires space for the new output as well as the previous partial.
This can require enough free space for another complete file, even when only
a small amount remains to transfer.

Concurrent copies use separate temporary files. With unchanged sources, each
completed file comes from one copy, but the whole tree is not a snapshot.
[In-place writes](#in-place-writes) expose unfinished updates, and pruning can
delete another copy's completed files.

Partials are named `.FILENAME.syq-tmp.RANDOM`, with 16 random characters at the
end. The filename portion is shortened or omitted to fit the destination filesystem
and available pathname space. Syq
removes its own partial when it publishes the completed file. Interrupted runs
can leave partials behind, including after a later successful retry. Partials
with shortened or omitted filenames may not be reused.

To remove leftover partials, stop copies writing into the tree, then preview
and run:

```sh
syq clean-partials --dry-run -v backup
syq clean-partials backup
# Search several remote trees with the parallel removal workers.
syq clean-partials --on server --cwd /data --performance-tuning workers=8 backup archive
```

This command removes regular files with the current partial-name format. It
keeps directories, other filenames, and symlinks, and does not follow symlinks.
Use `--root DIR` to confine traversal and `--results FILE` for the same
[removal records](automation.md#removal-records) as `syq rm` (`mode: "rm"`).
A regular file deliberately named like a partial is also selected. Old partial
formats are neither reused nor selected by this command; remove those manually.

Interrupted replacements and macOS clones can also leave `.syq-swap-...`
entries beside the destination. These may contain displaced originals or
temporary clone data. Stop all copies using the destination, inspect each
entry, and recover anything you want to keep before removing it. Neither
`clean-partials` nor pruning removes these recovery entries.

## Conflicting names and file types

Some filesystems treat names that differ only in case or Unicode spelling as
the same name. Syq does not detect these collisions before copying, so one
source can overwrite another. Rename conflicting sources first to keep both.
Names the destination cannot create are reported as copy errors.

Both `syq cp` and `syq rsync` refuse to replace a directory with a file, symlink,
or special file, or the reverse, even when the directory is empty. The copy
reports an error and skips that directory's contents. Move or remove the
conflicting destination before retrying.

Other replacements can fail if the filesystem lacks the operation needed to
replace the old entry safely; the old entry is kept. See
[interrupted-copy recovery](#resume-an-interrupted-copy) for entries left beside
the destination.

## Check file contents

Syq normally skips files whose size and modification time match. Matching
metadata does not prove that contents match; use `--hash` to compare contents:

```sh
syq cp --hash --srcs-in project --into backup
```

Use [per-file expected hashes in mappings](mappings.md#the-format) to require
known contents, including when reusing destination bytes.

To compare without copying:

```sh
syq cp --verify-only --srcs-in project --into backup
```

Missing or different entries make the command fail. This compares contents,
symlink targets, and entry types, without comparing metadata or looking for
extra destination files.

The [Integrity checking reference](integrity-checking.md) covers timestamp
precision, every comparison and payload-check algorithm, expected hashes,
and verification restrictions. For consistent source data, stop concurrent
writers or copy a snapshot.

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
`specials` enables device, FIFO, and socket nodes. `times` requests source
modification times, which are already preserved for named destinations but are
opt-in for [output descriptors](commands/cp.md#file-descriptors). Setting ownership
or explicit timestamps needs suitable permissions on the destination. Hard links,
ACLs, and xattrs are not preserved.

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

The final summary shows what was copied or skipped, how long it took, and any
errors. Add `-v` to list copied paths. For connection and performance details,
see [diagnosing a slow copy](speed.md#diagnose-a-slow-copy).

Human output, including `persist status` and `persist receive status`, escapes
terminal control characters, Unicode line separators, and directional marks
in names and peer diagnostics. JSON status output keeps the original values.

## Performance and time limits

Local copies use filesystem copy optimizations when available. On the same
APFS volume, eligible files can share disk blocks while remaining independently
writable. See [local copies and NFS](speed.md#local-copies-and-nfs) for what this
means for storage use and reported speed.

File transfers have no fixed duration or stall deadline. They can continue
through slowdowns and pauses; cancel the command if you no longer want to wait.
Connection setup, SSH keepalives, and return-connection heartbeats still have
time limits, and
[restricted server-to-server copies](remote-reference.md#limits-and-unsupported-options)
must finish before their signed authorization expires. SDK callers can also
set their own deadlines.

## Shell pipelines and file descriptors

You can compress data while sending it, without first saving the compressed
file on your machine:

```sh
gzip -c data | syq cp --src-fd 0 --to server --as data.gz
```

Here `--src-fd 0` reads from stdin, and `--as data.gz` names the file to create
on the server. To feed a downloaded file into another program, use `--as-fd 1`
to write to stdout:

```sh
syq cp --from server data.gz --as-fd 1 | gzip -dc > data
```

Both examples also work with local files or S3 objects. A pipeline can leave
incomplete output if one of its commands fails, so check the whole pipeline's
status before using the result. See [file descriptors](commands/cp.md#file-descriptors)
for process substitution, named pipes, and failure handling.

## Environment variables and local files

Syq reads no configuration file. Besides the usual system variables such as
`HOME`, `TMPDIR`, and `SSH_AUTH_SOCK`, and the AWS credential, region, and
endpoint variables described under
[object storage](object-storage.md#s3-options), syq honors:

- `SYQ_CP_OPTIONS`, `SYQ_RSYNC_OPTIONS`, and `SYQ_RM_OPTIONS` hold extra
  arguments for `syq cp`, `syq rsync`, and `syq rm`, respectively. Use them to adjust a
  command inside a script or program that does not let you change its syq
  options. The value is split like a shell command line and inserted right
  after the command name, before the arguments the script supplies, so
  `SYQ_CP_OPTIONS='--resource-limits bandwidth=10M' ./nightly-backup.sh`
  limits every `syq cp` the script runs. An option that the script also
  gives is reported the way any repeated option is. Syq removes these
  variables from its own environment before starting any other program, so
  `ssh`, an `--rsh` command, and syq's own helper processes never see them.
  The rest of the environment reaches `ssh` unchanged.
- `SYQ_NO_UPDATE_CHECK` and `DO_NOT_TRACK` turn off
  [update reminders](install.md#updates).
- `SYQ_TUNING_CACHE` names the
  [remembered connection count](tuning.md#remembered-connection-counts) file;
  an empty value turns that cache off.
- `SYQ_DEBUG` adds internal diagnostics to stderr, and `SYQ_S3_DIAGNOSTICS=1`
  does the same for object storage requests. Their content changes between
  versions.
- `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, and `XDG_RUNTIME_DIR` relocate the
  files below; `HOME` supplies the defaults.

Syq keeps these files on the machine where you run it:

| File | Purpose |
|---|---|
| `~/.cache/syq/tuning.json` | remembered connection counts per host route |
| `~/.cache/syq/completion-endpoints.json` | hosts offered by shell completion |
| `~/.cache/syq/helpers/` | helper binaries fetched for installing on servers |
| `~/.config/syq/persistence.json` | whether `syq persist on` is in effect |
| `~/.config/syq/receive.json` | receiving profiles from `syq persist receive on` |
| `~/.config/syq/install.json`, `last-update-check` | standalone install receipt and reminder timing |
| `$XDG_RUNTIME_DIR/syq-persist-UID/` | live persistent connection sockets |
| `~/.syq-destinations-v3/` | return destinations (`@NAME`) registered by connected receivers |
| `~/.local/share/syq/restricted/` | receiver enrollment state on a receiving server |

None of the caches or the update stamp are required. When they cannot be
written, for example from a read-only home directory, syq skips them and the
copy proceeds; the remembered connection counts are still read if the file
exists. Persistent connections do need a writable runtime directory, and a
server that receives files must be able to keep its enrollment state.

On an SSH server, the helper syq installs lives under
`~/.cache/syq/helpers/` in the server account. When that directory cannot be
created, the copy fails with a message saying so; point `--syq-path` at an
installed helper or pass `--no-bootstrap` when one is already on the server's
`PATH`.

## More options

`--src-non-dir` and `--src-dir` require a non-directory or directory respectively.

For parallelism and bandwidth controls, see [Speed](speed.md). For scripts,
see [Automation results](automation.md).

The [`cp` command reference](commands/cp.md) lists every option, including tuning,
scripting, and manual setup. In a terminal, use `--help` (or `-h`) for everyday
options and `--help-all` for the full list. `syq help COMMAND` shows the
same help without running the command. In `syq rsync`, `-h` means
human-readable sizes; use `--help` for help.
