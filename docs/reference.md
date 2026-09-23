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

For TCP data connections, syq can try other addresses advertised by the same
receiver if the initial address is unreachable. See
[TCP access](server-tuning.md#make-tcp-reachable) if copies fall back to SSH.

Use `--to @NAME` to send local source files to a registered receiving machine.
The `@` is required: `--to laptop` selects an SSH destination, while
`--to @laptop` selects your connected receiving machine.
See [Use your laptop from a server](receive.md) for setup and destination paths.

Use `--from s3://BUCKET` or `--to s3://BUCKET` for object storage. See
[Use S3 storage](object-storage.md) for credentials, examples, and filesystem
differences.

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

By default, syq adds missing files and updates files that differ. Use
`--only-new` to add missing entries and leave existing ones alone.

```sh
# Import new files without replacing existing files.
syq cp --only-new --srcs-in incoming --into archive
```

See [Update policies](commands/cp.md#update-policies) for supported combinations.

## Preview changes

Add `--dry-run -v` to list planned changes without copying or deleting files.
Include `--hash` to compare file contents during the preview:

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
Ignored paths are kept.

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

Use [per-file expected hashes in mappings](mappings.md#the-format) to require
known contents, including when reusing destination bytes.

Use [`--dry-run --hash`](#preview-changes) to compare without copying.

The [Integrity checking reference](integrity-checking.md) covers timestamp
precision, every comparison and payload-check algorithm, expected hashes,
and transfer checks. For consistent source data, stop concurrent
writers or copy a snapshot.

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
| `--preserve=hardlinks` | `-H` (regular files) |
| `--preserve=acls` | `-A` (Linux POSIX ACLs; implies permissions) |
| `--preserve=xattrs` | `-X` (Linux extended attributes) |

Setting ownership requires suitable destination permissions. See the
[rsync option definitions](https://download.samba.org/pub/rsync/rsync.1#opt--perms)
and [metadata details](commands/cp.md#metadata-details).

With `--preserve=hardlinks`, selected names for the same source regular file
share one destination inode. This works for local and ordinary SSH copies,
including updates, reruns, and `--inplace`. Only names eligible under the
overwrite policy join the group; links outside the selected sources are not
reconstructed. Existing extra destination links are not necessarily split.
With `--inplace`, writes still affect every existing name for that destination
inode, including names outside the copy.

A group transfers one payload. Creating another name is reported as a successful
file operation with zero transferred bytes. Conflicting per-path metadata fails
the copy. Every supplied expected hash must match the shared contents: omitted
hashes impose no requirement, identical hashes are checked once, and different
algorithms are checked together in one read. Different values for the same
algorithm are rejected before copying the group. Hardlinks across destination
filesystems fail visibly. Multiply linked symlinks and special files are currently unsupported,
as are hardlink requests with descriptors, streams, S3, and command-restricted
or receiving destinations. `-a` retains its existing meaning; add `-H` explicitly.

On Linux, add ACLs and xattrs for filesystem archival copies:

```sh
syq cp --preserve=permissions,ownership,specials,hardlinks,acls,xattrs --srcs-in source --into backup
# The rsync-compatible spelling:
syq rsync -aHAX --numeric-ids source/ backup/
```

ACL preservation copies POSIX access ACLs and directory default ACLs using
numeric IDs. It also preserves permissions. It removes destination named ACL
entries or default ACLs absent from the source, including on unchanged files.
A mapping's explicit mode changes the access ACL's owner, mask (or group), and
other permissions as `chmod` does. POSIX ACLs do not apply to Linux symlinks;
NFSv4 ACL conversion is unsupported.

Xattr preservation copies names and binary values, including empty values,
and removes destination-only attributes within the selected namespace scope.
A nonroot source selects `user.*`; a root source selects all namespaces except
`system.*`, including `security.selinux` and `security.capability`. ACL attributes
are handled only by ACL preservation. Excluded namespaces remain untouched.
Reading or applying a selected attribute can require privileges; failures make
the copy unsuccessful. Each inode's selected ACLs and xattrs must fit within
4 MiB, and individual values must fit Linux's limits.

| Linux entry type | Hardlinks (`-H`) | ACLs (`-A`) | Xattrs (`-X`) |
|---|---|---|---|
| Regular file | Selected source group | Access ACL | Selected namespaces |
| Directory | Not applicable | Access and default ACL | Selected namespaces |
| Symlink | Non-regular groups rejected | Not applicable | Attributes on the link itself, where supported |
| FIFO, device, socket | Non-regular groups rejected | Access ACL, where supported | Selected namespaces, where supported |

Copying special files also requires `--preserve=specials` or `-D` (included in
`-a`), and creating devices requires suitable privileges. Filesystem restrictions
on particular attribute namespaces still apply.

ACLs and xattrs work for local and ordinary SSH filesystem copies, including
updates, unchanged-content reruns, and `--inplace`. Both endpoints must be Linux.
Descriptors, stream mappings, S3, and command-restricted or receiving destinations
reject these options. Existing descriptor-backed regular-file copies support
only their original time, permission, and ownership options. Neither `-a` nor
native copy defaults select ACLs, xattrs, or hardlinks. Access times, birth times,
and sparse allocation are not preserved by these options.

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
