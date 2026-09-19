# Copy files

```sh
syq cp project --into backup
```

This copies `project` to `backup/project`. Existing files are updated when
needed; unrelated files stay.

<a id="more-options"></a>

See [`syq cp`](commands/cp.md) for every option, or run `syq cp --help`.

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
Enclose IPv6 addresses in brackets: `alice@[2001:db8::1]:2222`.
A colon in a native path is simply part of the path.

Use `--to @NAME` to send local source files to a registered receiving machine.
The `@` is required: `--to laptop` selects an SSH destination, while
`--to @laptop` selects your connected receiving machine.
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

Remote filesystem copies compress data in transit by default, adjusting
compression to the observed transfer speed. Blocks that do not shrink enough
are sent uncompressed. Use `--no-compress` to disable transport compression,
for example when comparing its effect on CPU use and copy speed.

<a id="output-and-diagnostics"></a>
<a id="performance-and-time-limits"></a>

## Progress

Syq shows a progress bar in a terminal, with elapsed time, speed, and an
estimated finish time. The final summary reports copied and skipped files
and any errors. Add `-v` to list copied paths.

Use `--progress` to show the bar when output is redirected, or `--no-progress`
to hide it. For connection details and ways to investigate performance, see
[Speed](speed.md).

## Choose a destination

| Option | Meaning |
|---|---|
| `--into DIR` | Put the selected names inside `DIR`, creating it if needed |
| `--as PATH` | Give one source this exact destination name |
| `--into-new DIR`, `--as-new PATH` | Also require the destination not to exist |
| `--into-existing DIR`, `--as-existing PATH` | Also require it to exist |

```sh
# Rename the copy and refuse to overwrite an existing entry.
syq cp report.txt --as-new reports/final.txt
```

`--as` can rename a directory too. If you select several sources, each needs
a different destination name. Use [mappings](mappings.md) to rename them
individually.

<a id="conflicting-names-and-file-types"></a>

Syq refuses to replace a directory with a file, or a file with a directory.
See [filename and type conflicts](commands/cp.md#filename-and-type-conflicts)
when copying between filesystems with different naming rules.

## Choose which existing files to update

By default, syq adds missing files and updates files that differ. To change
which files it copies:

| Option | Behavior |
|---|---|
| `--only-new` | Add missing entries and leave existing ones alone |
| `--only-existing` | Update existing entries without adding new ones |
| `--skip-newer` | Leave regular files alone when their destination timestamp is newer |

```sh
# Import new files without replacing existing files.
syq cp --only-new --srcs-in incoming --into archive

# Refresh only files already in the destination.
syq cp --only-existing --srcs-in project --into deployed
```

See [Update policies](commands/cp.md#update-policies) for supported combinations.

## Preview changes

Add `--dry-run -v` to list planned changes without copying or deleting files:

```sh
syq cp --dry-run -v --srcs-in project --into backup
```

A dry run can still install syq on the server; see
[Automatic installation on SSH servers](install.md#automatic-installation-on-ssh-servers).

## Mirror a directory

Use `--prune` to remove destination entries that are absent from the source:

```sh
syq cp --prune --max-delete 100 --srcs-in build --into-existing deploy
```

This makes the contents of `deploy` match `build`: it copies changes, then
removes extras. Preview with `--dry-run -v` first. If more than 100 removals
are planned, syq refuses all deletions. Scan or copy errors also prevent deletion.
Ignored paths and files excluded by size limits are kept.

Placement determines where pruning happens. Compare:

```sh
# Mirror build inside backup/build; leave the rest of backup alone.
syq cp --prune build --into backup

# Mirror build directly inside backup; remove extras throughout backup.
syq cp --prune --srcs-in build --into backup
```

See [Pruning](commands/cp.md#pruning) for restrictions and files kept for recovery.

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

Rerun the same command. Syq skips completed files and can reuse matching parts
of interrupted files. It assembles each updated file beside the destination
and replaces the destination when complete.

Partial files may remain after a successful retry. To remove them:

```sh
syq clean-partials --dry-run -v backup
syq clean-partials backup
```

See [`syq clean-partials`](commands/clean-partials.md) for remote cleanup and
recovery entries that need inspection before removal.

## Check file contents

Syq normally skips files whose size and modification time match. Use `--hash`
to compare their contents instead:

```sh
syq cp --hash --srcs-in project --into backup
```

This copies missing or changed files. To check whether the destination already
matches, without changing it, use `--verify-only`:

```sh
syq cp --verify-only --srcs-in project --into backup
```

This checks each selected source entry against its destination without copying
or deleting anything. It reads and compares file contents even when sizes and
timestamps match. It also compares entry types and symlink targets, but ignores
permissions, timestamps, and extra destination files.

The final summary reports the number of matching files and differences or
errors. Missing or different paths are listed on stderr as `MISSING path` or
`DIFFERS path`. The command exits with status `0` if everything selected matches,
or `23` if any entry differs, is missing, or cannot be checked. Setup failures
return `1`. For scripts, use the exit status and [Automation results](automation.md).

See [Integrity checking](integrity-checking.md) for comparison options and
checking against known hashes.

## In-place writes

By default, syq builds an updated file beside the old one and replaces it when
complete. `--inplace` writes directly into the destination file instead:

```sh
syq cp --inplace large-file --to server --into /backup
```

This avoids the disk space for a second full copy and can reduce disk I/O.
However, readers can see a mixture of old and new contents during the copy or
after an interruption. Writes through a hard link also affect its other names.
See [Update policies](commands/cp.md#update-policies) before combining
in-place writes with other copy policies.

## Preserve metadata

Syq preserves modification times and copies symlinks as links, like rsync with
`-t -l`. Existing files keep their destination permissions. New files use the
source read, write, and execute permissions, limited by the destination umask.
For example, a new script with mode `755` stays executable with umask `022`.

To preserve source permissions and ownership as well:

```sh
syq cp --preserve=permissions,ownership project --into backup
```

| Syq option | Corresponding rsync option |
|---|---|
| `--preserve=permissions` | `-p` |
| `--preserve=ownership` | `-o -g --numeric-ids` |
| `--preserve=specials` | `-D` (devices and special files) |

Setting ownership requires suitable destination permissions. Syq does not
preserve hard links, ACLs, or extended attributes. See the
[rsync option definitions](https://download.samba.org/pub/rsync/rsync.1#opt--perms)
and [metadata details](commands/cp.md#metadata-details).

## Symlinks

To copy through a symlink in a path you supply, use `--follow-src` for source
paths or `--follow-dst` for destination paths. `--follow` enables both and
also follows paths supplied by options such as `--ignore-from`.

```sh
# Copy the directory current-project points to as backup/current-project.
syq cp --follow-src current-project --into backup

# Put project inside the directory that backup points to.
syq cp project --follow-dst --into backup
```

`--as PATH` names the entry to replace, so `--follow-dst` only applies to its
parent directories. For example, `syq cp report.txt --as latest --follow-dst`
replaces a symlink named `latest`, leaving its target unchanged.

Links discovered inside a copied directory remain links; these options do not
follow them. See [Filesystem attacks](security.md#filesystem-attacks) for the security details.

<a id="keep-sources-inside-a-directory"></a>

## Choose a source directory

Use `-C DIR` (or `--cwd DIR`) to resolve source paths from another directory:

```sh
syq cp -C /srv/data reports photos --into backup
```

This copies `/srv/data/reports` and `/srv/data/photos` into `backup`. The source
base belongs to the machine selected by `--from`; it does not change where
relative destination paths start.

Use `--root DIR` instead of `-C DIR` when selections must stay inside that
directory. Sources must then be relative: `../private` is refused, and even
with `--follow-src`, symlinks cannot lead outside the root. `-C` permits both.

## Shell pipelines and file descriptors

Use `--src-fd 0` to read bytes from standard input, or `--as-fd 1`
to send a file's contents to another program:

```sh
# Save generated data directly on the server.
python make_report.py | syq cp --src-fd 0 --to server --as report.csv

# Feed a remote file to a local program.
syq cp --from server report.csv --as-fd 1 | python analyze_report.py
```

Replace the Python scripts with your own producer and consumer commands. The
same options work with local files and S3 objects. Other descriptor numbers
let scripts pass files they have already opened.

Check the whole pipeline's status: a failed producer can leave syq with an
incomplete stream that ends normally. See [file descriptors](commands/cp.md#file-descriptors)
for process substitution, named pipes, and failure handling.

<a id="environment-variables-and-local-files"></a>

For environment overrides and cache locations, see
[Environment and local files](environment.md).
