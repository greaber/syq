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
estimated finish time. Buffered local copies report progress while a large file
is still being copied; filesystem clones and copy offloads report when the
operation completes. The final summary reports copied and skipped files and any
errors. Add `-v` to list copied paths.

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

## Select files by metadata

Use `--where` to select source entries and `--copy-if` to decide which
source/destination pairs may be updated:

```sh
syq cp --srcs-in project --into backup \
  --where 'src.kind = "file" and src.size >= 1MiB' \
  --copy-if 'not dst.exists or src.mtime > dst.mtime'
```

Directories remain traversable so matching descendants can be found. Excluded
source entries protect their destination counterparts from pruning. See
[expressions](expressions.md) for fields, operators, and directory behavior.

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
of interrupted files. Partial-file resume is independent of
[`block-reuse`](tuning.md#compare-block-reuse-with-full-replacement), which controls
comparison against an existing final destination. Unless `--inplace` is selected,
syq assembles each updated file beside the destination and replaces it when
complete. With `--inplace`, interrupted bytes are in the final file itself;
reusing them follows the block-reuse policy.

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
Changing an existing file’s contents requires write permission; an unchanged
read-only file can still be checked with `--hash`. New files keep owner-write
permission until the copy succeeds and applies their final permissions; an
interrupted copy can leave that write permission in place.
See [Update policies](commands/cp.md#update-policies) before combining
in-place writes with other copy policies.

## Preserve metadata

Syq preserves modification times and copies symlinks as links, like rsync with
`-t -l`. Use `--preserve=-mtime` to leave modification times as produced by
writing. `--preserve=mtime` enables preservation again; `times` remains an alias
for `mtime`. Repeated settings take effect in order, with the last one winning.
Other preservation features are off unless requested and have no negative form.
Disabling modification-time preservation can make later copies do more work
because source and destination times no longer match. Explicit mapping
`metadata.mtime` still sets the requested destination time.

Existing files keep their destination permissions. New files use the
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
| `--preserve=acls` | `-A` (native ACLs; implies permissions) |
| `--preserve=xattrs` | `-X` (extended attributes) |
| `--preserve=atimes` | `-U` (access times) |
| `--preserve=crtimes` | `-N` (birth times; macOS destination) |

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

Hardlink preservation scans all selected sources before changing the destination.
Large trees therefore take longer to start copying and require memory for the
complete file list.

A group transfers one payload. Creating another name is reported as a successful
file operation with zero transferred bytes. Conflicting per-path metadata fails
the copy. Every supplied expected hash must match the shared contents: omitted
hashes impose no requirement, identical hashes are checked once, and different
algorithms are checked together in one read. Different values for the same
algorithm are rejected before copying the group. Hardlinks across destination
filesystems fail visibly. Multiply linked symlinks and special files are currently unsupported,
as are hardlink requests with descriptors, streams, S3, and command-restricted
or receiving destinations. `-a` retains its existing meaning; add `-H` explicitly.

Add ACLs and xattrs for filesystem archival copies on Linux or macOS:

```sh
syq cp --preserve=permissions,ownership,specials,hardlinks,acls,xattrs --srcs-in source --into backup
# The rsync-compatible spelling:
syq rsync -aHAX --numeric-ids source/ backup/
```

On Linux, ACL preservation copies POSIX access ACLs and directory default ACLs using
numeric IDs. It also preserves permissions. It removes destination named ACL
entries or default ACLs absent from the source, including on unchanged files.
A mapping's explicit mode changes the access ACL's owner, mask (or group), and
other permissions as `chmod` does. POSIX ACLs do not apply to Linux symlinks;
NFSv4 ACL conversion is unsupported. On macOS, it copies the native ordered
allow/deny entries, UUID principals and inheritance flags, removing destination
entries absent from the source. It does not translate principal names or UUIDs
between hosts. Both endpoints must use the same ACL model; Linux↔macOS ACL
conversion is rejected before destination setup.
Selecting multiple hardlink names with a macOS ACL containing a deletion-denying
entry is rejected before copying: that ACL prevents publishing the additional
names. Copy those names independently without `-H` to preserve their ACLs.
Copying just one selected name remains supported, including with `-H`.

Xattr preservation copies names and binary values, including empty values,
and removes destination-only attributes within the selected namespace scope.
A nonroot Linux source selects `user.*`; a root Linux source selects all namespaces except
`system.*`, including `security.selinux` and `security.capability`. ACL attributes
are handled only by ACL preservation. Excluded namespaces remain untouched.
Reading or applying a selected attribute can require privileges; failures make
the copy unsuccessful. Each inode's selected ACLs and xattrs must fit within
4 MiB, and individual names and values must fit the destination platform's limits.

On macOS, xattrs include Finder information, resource forks and application
attributes. ACL storage and filesystem compression attributes are excluded;
compressed contents are copied as logical bytes. Changing a user resource fork
on an existing compressed destination is rejected; copy to an uncompressed
destination for that case. Across Linux and macOS, Linux `user.NAME` corresponds
to macOS `NAME`. Other Linux namespaces cannot be copied to macOS and are
rejected. On macOS-to-macOS copies, names are preserved literally.

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
updates, unchanged-content reruns, and `--inplace`. macOS also supports native
metadata on directories, symlinks and copied special nodes where the filesystem
permits it.
Descriptors, stream mappings, S3, and command-restricted or receiving destinations
reject these options. Existing descriptor-backed regular-file copies support
only their original time, permission, and ownership options. Neither `-a` nor
native copy defaults select ACLs, xattrs, hardlinks, or access times.

These options do not preserve filesystem flags such as immutable or append-only,
restore ctime or inode numbers, or create rsync `--fake-super` backup records.

Use `--preserve=atimes` (rsync `-U`/`--atimes`) to restore access times captured
before reading the source. It covers regular files, directories, links themselves,
and copied special nodes on local and ordinary SSH filesystem copies. Linux
requires kernel 5.8 or later; macOS support depends on the filesystem. Restoration
runs after content checks and copying, including metadata-only updates and reruns.
Reading copied files afterward can change their access times again. Descriptors,
streams, S3, and command-restricted or receiving destinations reject this option.

`--open-noatime` requests file reads without updating access times. Repeating
`-U` (`-UU`) enables it too. Linux permits this for a file's owner or a process
with suitable privileges. If unavailable, syq warns and continues; this option
does not promise unchanged source access times, including directory scans and
symlink reads. Destination access-time preservation remains independently selected
and restoration errors make the copy unsuccessful.

Use `--preserve=crtimes` (rsync `-N`/`--crtimes`) to preserve birth (creation)
times. The source filesystem must report birth times and the destination must
be macOS with a filesystem that permits setting them. Linux destinations reject
this option before copying. It supports the same named filesystem routes and
entry types as access-time preservation. Neither `-a` nor native defaults select
it. Inode change time (`ctime`) cannot normally be restored.

Use `--sparse` (rsync `-S`) to turn written zero ranges into holes on local or
ordinary SSH filesystem copies. It applies to regular files, independently of
metadata options, and is not included in `-a` or native defaults. It preserves
bytes and length, not an exact source extent layout. Eligible local clones still
use filesystem cloning; other writes skip zeros or clear old blocks into holes.
The destination filesystem must support sparse files; ranged, resumed, and
in-place writes also require hole punching. A failed hole operation makes the
copy unsuccessful. Filesystem allocation units can limit the space reclaimed by
in-place hole punches, especially with small comparison blocks. Unchanged files
and reused blocks are not rewritten just to change their allocation. Descriptors, streams, S3, and command-restricted or
receiving destinations reject this option.

Sparse mode avoids full-size preallocation.

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
