# Copy files

```sh
syq cp project --into backup
```

This copies `project` to `backup/project`. Existing files are updated when their contents differ. Unrelated files stay.

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
A colon in a native path is simply part of the path. If copies fall back to
SSH when you expect TCP, see [TCP access](server-tuning.md#make-tcp-reachable).

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
compression to the transfer speed. Use `--no-compress` to turn it off, for
example to compare its effect on CPU use and copy speed.

<a id="output-and-diagnostics"></a>
<a id="performance-and-time-limits"></a>

## Progress

Syq shows a progress bar in a terminal, with elapsed time, speed, and an
estimated finish time. Use `--progress` to show it when output is redirected,
or `--no-progress` to hide it. Elapsed time and speed cover the file work
itself, not setup before it or finalization after it.

The final summary reports copied and skipped files and any errors; add `-v` to
list copied paths. Interactive copies also print a timing line with setup,
planning, transfer, finalization, any helper installation, and the total;
`--stats` and `--progress` print it when output is redirected. The
[automation reference](automation.md#result) defines these measurements. For
connection details and ways to investigate performance, see [Speed](speed.md).

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

An rclone mount works as a source, but as a destination it needs rclone's
`--vfs-cache-mode writes` or `full`. In rclone's default mode a file can only
be written once, from start to end, so most syq copies and updates fail there;
see [rclone's file caching](https://rclone.org/commands/rclone_mount/#vfs-file-caching).

## Choose which existing files to update

By default, syq copies missing files and updates existing files whose contents
differ. Existing directories remain containers. Choose another policy with `--if-exists`:

| Value | Existing files |
|---|---|
| `error-if-different` | Accept matching contents; reject differences |
| `error` | Reject every existing file, including identical files |
| `keep` | Leave contents and metadata alone |
| `update` (default) | Update differing contents and apply requested metadata |
| `update-if-older` | Keep newer destinations; otherwise update differing contents |

How syq compares files is separate from the policy: matching size and
modification time count as equal unless you add `--hash`. When
`error-if-different` cannot establish equality from size and time, it compares
contents before accepting a file; bucket-to-bucket copies instead require
matching object metadata or identifiers (see
[S3 copies](object-storage.md#copies-between-s3-buckets)). Requested metadata
is applied only after the contents are accepted, so a content conflict leaves
that file's metadata alone. `--as-new` and `--into-new` apply only to the
destination you name; `--if-exists` applies to each entry the copy places.

`error`, `error-if-different` and `--as-new` also refuse a file another
program creates at the name during the copy: syq keeps that file and reports
its copy as failed. `keep` keeps it too and skips it, though in an S3 bucket
that file's copy is reported as failed. `--into-new` stops without writing into
a directory that appears first. `update` and `update-if-older` replace the
file. A file created in the last moment before syq renames its own into place
can still be replaced under `keep` on filesystems without an atomic no-replace
rename, such as NFS, and under `keep`, the error policies and `--as-new` on FAT
and exFAT on macOS and on rclone mounts.

See [Update policies](commands/cp.md#update-policies) for supported combinations.

## Choose a transfer strategy

`--transfer-strategy` chooses how filesystem copies transfer the contents of
files selected for copying in `syq cp`.

| Strategy | Behavior |
|---|---|
| `whole-file` | Copy the selected file without comparing or reusing blocks from the final destination |
| `aligned-block` | Compare each replaced file with the destination file and reuse matching blocks at the same offsets; shifted blocks and blocks from other files are not matched |
| `locality` (default) | Use `whole-file` for local copies and `aligned-block` when a syq endpoint is remote |

With a remote syq endpoint, `locality` compares every file it replaces, as
rsync does by default, and sends only the blocks that differ; comparing costs
about a read of the old file on the destination. Unlike rsync, only blocks at
the same offsets match, so data appended to a file is cheap to send but data
inserted near its start is not. `locality` treats mounted network filesystems
as local. To choose explicitly:

```sh
syq cp --srcs-in source --to server --into destination \
  --transfer-strategy whole-file
```

`syq rsync` uses rsync's spellings: `-W` / `--whole-file` selects whole-file
copying; `--no-W` / `--no-whole-file` selects aligned-block reuse. If both are
specified, the last one wins. Its default is `locality`.

S3 and descriptor copies do not accept `--transfer-strategy`. See
[comparison tuning](tuning.md#compare-block-reuse-with-full-replacement)
for block size and controlled comparisons.

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
Ignored paths are kept. Use `--prune-before` instead of `--prune` to free space
before copying. Source selection must finish first; a later copy failure does
not restore removed extras. The same `--max-delete` limit applies.

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

Patterns use gitignore syntax and match paths relative to each selected source
directory, for both filesystem and S3 copies. `syq rsync` uses the same matching
rules with `--syq-ignore` and `--syq-ignore-from`. For example, `/build/` excludes
the top-level `build` directory inside every selected source; it does not exclude
the selected directory itself. Explicitly selected non-directory sources match
by their source basename: `--ignore '*.txt'` excludes `notes/report.txt` even when
copied with `--as renamed`. Rules run in command-line order; the last match wins.
`!` re-includes a path.

`--mapping` cannot be combined with `--ignore` or `--ignore-from`. Filter the
mapping entries themselves instead.

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

Rerunning a copy reuses completed files and matching parts of interrupted
files. Placement conditions and `--if-exists` apply on every run, so a `-new`
placement or `--if-exists=error` can prevent a retry once entries have been
created. With `--if-exists=error-if-different`, a retry rejects a differing
final file, because it cannot tell incomplete output from a file that must
remain untouched. Changing to `--if-exists=update` allows updates to all
differing selected files.

A directory the interrupted copy created may still have temporary permissions,
and a retry treats it as an existing directory, so its permissions and
modification time can differ from an uninterrupted copy's.
`--copy-metadata=permissions,mtime` makes them match the source.

If you interrupt a copy with Ctrl-C or SIGTERM, or its connection to a remote
syq is lost, the receiving side removes its temporary files but keeps larger
partial files for a later copy to resume from. A copy within one machine that
copies files whole cannot reuse them, so it removes them. With `--in-place`,
the interrupted bytes are in the final file itself, and a rerun reuses them
only as the [transfer strategy](#choose-a-transfer-strategy) allows.

Partial files may remain after a successful retry, and a copy that was killed
can leave temporary files. Syq does not remove them during a copy, since
another copy may still be writing one, but says how many files had them. To
remove them:

```sh
syq clean-partials --dry-run -v backup
syq clean-partials backup
```

See [`syq clean-partials`](commands/clean-partials.md) for remote cleanup and
recovery entries that need inspection before removal.

## Check file contents

Syq normally skips files whose size and modification time match. Use `--hash`
to compare contents instead; a file whose contents already match is left alone:

```sh
syq cp --hash --srcs-in project --into backup
```

`--hash-or-copy` also checks files whose size and time match, but compares
only the files that the [transfer strategy](#choose-a-transfer-strategy) would
compare and copies the rest whole, so files that already match may be
rewritten. With the default strategy, that means comparing every file when a
syq endpoint is remote, and copying every file on the same machine.

FAT keeps modification times in two-second steps, so when syq copies into a
directory on FAT, times less than two seconds apart count as matching, as
rsync's `--modify-window=1` would make them. This does not apply when syq
updates one named file, copies with `--existing`, or copies to a restricted
receiver.

Use [per-file expected hashes in mappings](integrity-checking.md#expected-hashes)
to require known contents, including when reusing destination bytes.
Use [`--dry-run --hash`](#preview-changes) to compare without copying.

The [Integrity checking reference](integrity-checking.md) covers timestamp
precision, every comparison and payload-check algorithm, expected hashes,
and transfer checks. For consistent source data, stop concurrent
writers or copy a snapshot.

## In-place writes

By default, syq builds each file beside its final name and renames it into
place when complete. `--in-place=new` writes the files the copy creates
directly at their final names instead, which saves a temporary name and a
rename for each new file:

```sh
syq cp --in-place=new large-file --to server --into /backup
```

Readers can see a new file before it is complete, and an interruption leaves
it incomplete at its final name until a rerun finishes it. Existing files are
still replaced as without the option, which needs write permission on their
directory and room for a second copy.

`--in-place=update` also writes into existing files where they are, and only
the parts that changed, so a small change to a large file needs no second
copy (`syq rsync --inplace` does the same):

```sh
syq cp --in-place=update disk.img --to server --into /vm
```

This has two risks:

- Anyone who already has the file open, or opens it during the copy, can
  read the new contents.
- An interruption leaves the file partly updated, a mixture of old and new
  contents, until a rerun finishes it.

It also assumes that nothing else writes to the file during the copy.

Syq updates a file in place only when that can't give anyone access the copy
would not, and replaces any other existing file, for example one with other
names or another owner, or any file on a filesystem
[where syq can't tell it has no other names](#how-syq-changes-existing-files-and-directories).
The summary, and `replaced_not_in_place` in
[`--results`](automation.md#result), say how many it replaced and why; a dry
run's counts are estimates.

Files written in place keep owner-write permission, and some stay open only to
their owner, until the copy succeeds and applies their final permissions. An
interrupted copy can leave them that way, and a rerun keeps that mode unless it
also copies permissions. See [Update policies](commands/cp.md#update-policies)
before combining in-place writes with other copy policies.

<a id="preserve-metadata"></a>

## Copy metadata

Creating a named file or updating its contents sets its modification time to
the source time. Accepting unchanged contents leaves destination metadata
alone. Use `--copy-metadata=mtime` (or its alias `times`) to make modification
times match on unchanged files too. Otherwise identical files with different
times may have their contents read again on every run, including downloading
an S3 object that has no usable stored hash. A mapping's explicit
`metadata.mtime` also sets the destination time. S3-to-S3 copies also support
[content headers, user metadata, tags, and storage
class](object-storage.md#copies-between-s3-buckets).

New files use the source read, write, and execute permissions, limited by the
umask, or by the directory's default ACL if it has one. For example, a new
script with mode `755` stays executable with umask `022`. Existing files and
directories keep their destination permissions unless you request permission
or ACL metadata. To preserve source permissions and ownership as well:

```sh
syq cp --copy-metadata=permissions,ownership project --into backup
```

| Syq option | Corresponding rsync option |
|---|---|
| `--copy-metadata=permissions` | `-p` |
| `--copy-metadata=ownership` | `-o -g --numeric-ids` |
| `--copy-metadata=specials` | `-D` (devices and special files) |
| `--copy-metadata=hardlinks` | `-H` (regular files) |
| `--copy-metadata=acls` | `-A` (native ACLs; implies permissions) |
| `--copy-metadata=xattrs` | `-X` (extended attributes) |
| `--copy-metadata=atimes` | `-U` (access times) |
| `--copy-metadata=crtimes` | `-N` (birth times; macOS destination) |

Setting ownership requires suitable destination permissions. See the
[rsync option definitions](https://download.samba.org/pub/rsync/rsync.1#opt--perms)
and [metadata details](commands/cp.md#metadata-details). Neither
`syq rsync -a` nor the `syq cp` defaults select hard links, ACLs, xattrs,
access times, or birth times. Descriptors, stream mappings, and S3 reject
these; descriptor copies of regular files support only `mtime`,
`permissions`, and `ownership`. None of these options preserves filesystem
flags such as immutable or append-only, restores ctime or inode numbers, or
creates rsync `--fake-super` backup records.

### Hard links, ACLs, and extended attributes

Add hard links, ACLs and xattrs for archival copies on Linux or macOS:

```sh
syq cp --copy-metadata=permissions,ownership,specials,hardlinks,acls,xattrs --srcs-in source --into backup
# The rsync-compatible spelling:
syq rsync -aHAX --numeric-ids source/ backup/
```

With `hardlinks`, selected names for the same source regular file share one
destination inode, on local and SSH filesystem copies. Links to files outside
the selected sources are not reconstructed. Syq scans all selected sources
before changing the destination, so large trees take longer to start copying
and need memory for the complete file list. Hard links across destination
filesystems fail. On a filesystem without hard links, such as FAT, exFAT or an
rclone mount, syq copies one name of each group and reports the others as
failed. A source symlink or special file with several names is rejected.

On Linux, `acls` copies POSIX access ACLs and directory default ACLs by
numeric ID, and also preserves permissions. It removes destination ACL entries
absent from the source, including on unchanged files. A mapping's explicit
mode changes the access ACL as `chmod` does. NFSv4 ACLs are not supported. On
macOS, it copies the native entries with their UUID principals and inheritance
flags, without translating principals between hosts. Both endpoints must use
the same ACL model; copying ACLs between Linux and macOS is rejected before
anything changes.

`xattrs` copies names and values and removes destination-only attributes in
the selected namespaces. A Linux source read by an ordinary user selects
`user.*`; read by root, it selects every namespace except `system.*`,
including `security.selinux` and `security.capability`. On macOS, xattrs
include Finder information, resource forks and application attributes;
filesystem compression attributes are left out, and compressed files are
copied as their contents. Between Linux and macOS, Linux `user.NAME`
corresponds to macOS `NAME`; other Linux namespaces cannot be copied to macOS.

ACLs and xattrs also apply to directories and special files, and xattrs to
symlinks, where the filesystem supports it. Reading or setting them can
require privileges, and failures make the copy unsuccessful. Each file's
selected ACLs and xattrs must fit within 4 MiB. Copying special files requires
`specials` (`-D`, included in `-a`), and creating devices requires suitable
privileges.

### Times and sparse files

Where a filesystem can't set a symlink's own modification time, such as
SSHFS, syq leaves it alone.

`--copy-metadata=atimes` (rsync `-U`/`--atimes`) gives destination entries the
access times their source had before syq read it; Linux requires kernel 5.8 or
later. Separately, `--open-noatime` asks the system not to update source access
times while syq reads; `-UU` selects both. Linux permits that only for a file's
owner or a privileged process, and where it is unavailable syq warns and
continues.
`--copy-metadata=crtimes` (rsync `-N`/`--crtimes`) preserves birth times when
the source filesystem reports them and the destination is a macOS filesystem
that can set them; Linux destinations reject it.

Use `--sparse` (rsync `-S`) to turn written runs of zeros into holes on local
or SSH filesystem copies; it is not part of `-a` or the `syq cp` defaults. It
preserves contents and length, not the source's exact layout. The destination
filesystem must support sparse files, and resumed and in-place writes also
need hole punching; a failed hole operation makes the copy unsuccessful.
Unchanged files and reused blocks are not rewritten just to change their
allocation. Descriptors, streams, and S3 reject this option.

### How syq changes existing files and directories

When only an existing file's metadata differs, syq changes it in place if it
can tell the file has no other names, the file belongs to the account syq runs
as, and the change adds no set-ID bit and changes no security attribute. Run
as root, it changes in place whatever the file's owner could change, and
replaces the file to give it another owner or group.
Otherwise syq rewrites the file as if its contents had changed: that takes as
long as copying it, needs write permission on its directory and room for a
second copy, gives the file a new inode number, and drops attributes the copy
does not select, such as ACLs or extended attributes. Access times are always
set in place. A symlink, device or named pipe whose metadata differs is
created again.

Syq can't tell whether a file has other names on some filesystems, such as
SMB, SSHFS and other FUSE filesystems, filesystems it does not recognize, and
on macOS anything but APFS and HFS+. There every metadata-only change rewrites
the file, and `--in-place=update` replaces files instead of updating them.

A directory receives its copied permissions and ACLs after its contents. Until
then, syq keeps a new directory open only to its owner whenever its final group
or ACL could keep others out, and with `--copy-metadata=permissions` it narrows
an existing directory that allows more than its source before creating anything
in it. Someone who opened an existing directory earlier can keep listing the
names syq creates in it.

When a directory you own lacks the write or search permission a change needs,
`--widen-dirs` (`--syq-widen-dirs` for `syq rsync`) decides whether syq
briefly adds the owner permission it lacks: search to pass through it, write
to change its entries, and read to list it.

- `none`, the `syq cp` default, never does. Syq names the directory once (a dry
  run lists it too), and the changes in it fail.
- `rsync`, the `syq rsync` default, widens the directories the copy includes,
  as rsync does: the destination of a contents copy, an existing `--as`
  directory, and the directories beneath them that the copy fills or prunes.
  It does not widen the directory a named source or an `--as` target goes
  into, or enter destination-only directories it cannot read.
- `all` also widens the directory the copy goes into and the directories above
  it, and enters unreadable destination-only directories to prune them.

Under `none` and `rsync`, both commands refuse a destination they cannot
search, as rsync does. Syq restores each directory's exact mode afterwards,
also when the copy fails, unless you request permissions. Other
processes can see the temporary permissions, and a crash can leave them in
place. On a receiving machine, the approval prompt says when a copy can open
folders you own; adding read permission shows the sender the names inside.

Dry runs never change permissions. A dry run reports a directory you own but
cannot search as not inspected, and exits with status 23.

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

One copy accepts up to 1,024 named sources, such as the names a shell glob
expands to, and fewer with long paths when a [receiving machine](receive.md)
approves the copy or a server coordinates a
[copy between two servers](remote-to-remote.md). For more, select their parent
directory with `--srcs-in` and leave out what you don't want with `--ignore`
or `--where`, or split the copy.

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
