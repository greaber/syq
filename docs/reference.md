# Copy files

`syq cp` copies files locally, to and from SSH servers, and to and from S3
buckets. This page covers the choices you make in a copy: what to copy, where
it lands, and what happens to files already there.

```sh
syq cp project --into backup
```

This copies `project` to `backup/project`. Files already in the destination
are updated when their contents differ, and files the copy doesn't include
are left alone.

<a id="more-options"></a>

See [`syq cp`](commands/cp.md) for every option, or run `syq cp --help`.

## See where files go

Naming a directory copies the directory itself, so its name appears in the
destination. `--srcs-in` copies only its contents, and `--as` gives the copy a
name you choose.

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

Note to rsync users: trailing slashes don't matter in `syq cp`. `syq rsync`
keeps rsync's slash rules.

## Copy over the network

Use `--to` to send files, or `--from` to fetch them:

```sh
# Copy project to /backup/project on server.
syq cp project --to server --into /backup

# Fetch /data/a and /data/b from server into ./data/a and ./data/b here.
syq cp --from server -C /data --src a --src b --into ./data
```

`-C DIR` (`--cwd DIR`) says where to find the sources: in the second example,
`/data` on the server. Without `--into` or `--as`, `--to server` puts files in
your home directory there, and `--from server` puts them in your current
directory.

Write a server as `[USER@]HOST[:PORT]`, for example `alice@server:2222` or
`alice@[2001:db8::1]:2222`. Unlike in `scp`, a colon in a path is just part of
the path. Syq sends file data over its own encrypted TCP connection when it
can; if copies fall back to SSH, see
[TCP access](server-tuning.md#make-tcp-reachable).

Other routes use the same options:

- `--to @NAME` sends files to your laptop from a server's shell; without the
  `@`, `--to laptop` names an SSH server. See
  [Use your laptop from a server](receive.md).
- `--from s3://BUCKET` and `--to s3://BUCKET` copy to and from S3. See
  [Use S3 storage](object-storage.md).
- `--from` and `--to` with two servers copy directly between them. See
  [Copy between servers](remote-to-remote.md).

<a id="transport-compression"></a>

Copies to and from servers compress data in transit. Use `--no-compress` to
compare its effect on CPU use and copy speed.

<a id="output-and-diagnostics"></a>
<a id="performance-and-time-limits"></a>

## Progress

In a terminal, syq shows a progress bar with speed and an estimated finish
time. When the copy ends, it prints a summary of copied and skipped files and
any errors, and a timing line that splits the total into setup, planning,
transfer, and finalization. Add `-v` to list the copied paths, or
`--no-progress` to hide the bar. When output is redirected, `--progress` shows
the bar and the timing line, and `--stats` prints the timing line. See
[Speed](speed.md) to investigate a slow copy.

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

`--as` can rename a directory too. To rename several sources, use
[mappings](mappings.md).

<a id="conflicting-names-and-file-types"></a>

Syq refuses to replace a directory with a file, or a file with a directory.
See [filename and type conflicts](commands/cp.md#filename-and-type-conflicts)
when copying between filesystems with different naming rules.

As a destination, an rclone mount needs rclone's `--vfs-cache-mode writes` or
`full`; otherwise most copies fail. See
[rclone's file caching](https://rclone.org/commands/rclone_mount/#vfs-file-caching).

## Choose which existing files to update

By default, syq copies missing files and updates existing files whose contents
differ. Existing directories remain containers. To protect existing files, or
update only older ones, choose another policy with `--if-exists`:

| Value | Existing files |
|---|---|
| `error-if-different` | Accept matching contents; reject differences |
| `error` | Reject every existing file, including identical files |
| `keep` | Leave contents and metadata alone |
| `update` (default) | Update differing contents and apply requested metadata |
| `update-if-older` | Keep newer destinations; otherwise update differing contents |

A file counts as unchanged when its size and modification time match, unless
you add [`--hash`](#check-file-contents). `error-if-different` compares
contents before rejecting a file whose time differs, so it accepts identical
files (between S3 buckets it compares metadata instead; see
[Copies between S3 buckets](object-storage.md#copies-between-s3-buckets)). A
file rejected for its contents keeps its metadata too. `--as-new` and
`--into-new` check only the destination you name; `--if-exists` applies to
every entry the copy writes.

`keep`, `error`, `error-if-different` and `--as-new` also keep a file that
another program creates at the same name during the copy. A file created just
before syq moves its copy into place can still be replaced under `keep` on
filesystems without an atomic no-replace rename, such as NFS, and under all of
them on FAT and exFAT on macOS and on rclone mounts.

See [Update policies](commands/cp.md#update-policies) for supported
combinations.

## Choose a transfer strategy

You rarely need this option. By default, a copy between machines compares each
file it replaces with the old destination file and sends only the blocks that
differ, as rsync does, at the cost of reading the old file. Unlike rsync, it
matches blocks only at the same offset: data appended to a file is cheap to
send, but data inserted near its start is not. A copy within one machine,
including to a mounted network filesystem, copies whole files.

`--transfer-strategy` changes this:

| Strategy | Behavior |
|---|---|
| `whole-file` | Copy each file in full, without looking at the old destination file |
| `aligned-block` | Send only the blocks that differ from the old destination file, matching blocks at the same offset |
| `locality` (default) | `whole-file` within one machine, `aligned-block` between machines |

```sh
syq cp --srcs-in source --to server --into destination \
  --transfer-strategy whole-file
```

In `syq rsync`, `-W` (`--whole-file`) selects `whole-file` and `--no-W`
selects `aligned-block`. S3 and descriptor copies don't accept the option. See
[comparison tuning](tuning.md#compare-block-reuse-with-full-replacement) for
block size and controlled comparisons.

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
are planned, or reading the source or copying fails, syq deletes nothing.
Ignored paths are kept.

Placement decides where pruning happens. Compare:

```sh
# Mirror build inside backup/build; leave the rest of backup alone.
syq cp --prune build --into backup

# Mirror build directly inside backup; remove extras throughout backup.
syq cp --prune --srcs-in build --into backup
```

To free space first, use `--prune-before`. It removes extras after syq has
listed the source but before copying. If the copy then fails, the extras stay
deleted. `--max-delete` applies as with `--prune`. See [Pruning](commands/cp.md#pruning) for restrictions and files kept
for recovery.

## Select files by metadata

Use `--where` to select source entries, and `--copy-if` to decide, for each
entry, whether the copy may create or update its destination:

```sh
syq cp --srcs-in project --into backup \
  --where 'src.kind = "file" and src.size >= 1MiB' \
  --copy-if 'not dst.exists or src.mtime > dst.mtime'
```

Excluded source entries protect their destination counterparts from pruning.
See [expressions](expressions.md) for fields and operators.

## Ignoring paths

```sh
# Use the project's existing ignore rules.
syq cp --ignore-from .gitignore --srcs-in project --into backup

# Skip node_modules and object files.
syq cp --ignore node_modules --ignore '*.o' --srcs-in project --into backup
```

Patterns use gitignore syntax and match paths relative to each selected source
directory, in filesystem and S3 copies alike. For example, `/build/` excludes
the top-level `build` directory inside every selected source, but not a
selected directory named `build`. Rules apply in command-line order, the last
match wins, and `!` re-includes a path. `syq rsync` uses the same rules with
`--syq-ignore` and `--syq-ignore-from`.

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

## Resume an interrupted copy

Rerun the same command. Syq reuses completed files and, where it kept them,
the matching parts of interrupted ones.

The rerun applies the same placement and `--if-exists` checks, so a `-new`
placement or `--if-exists=error` refuses entries the first run created, and
`error-if-different` refuses files that differ, because it can't tell a partly
written file from one it must leave alone. To finish such a copy, rerun with
`--if-exists=update`, which also updates every other differing file the first
policy protected, or, for a `-new` placement, with `--into` or `--as`.
Directories the first run created can keep temporary
permissions; add `--copy-metadata=permissions,mtime` to the rerun to make them
match the source.

Partial files from an interrupted copy, and temporary files from one that was
killed, can remain even after a successful rerun. Syq says how many files have
them. To remove them:

```sh
syq clean-partials --dry-run -v backup
syq clean-partials backup
```

See [`syq clean-partials`](commands/clean-partials.md) for remote cleanup and
recovery entries that need inspection before removal.

## Check file contents

By default, syq skips files whose size and modification time match. If a file
could change without changing either, use `--hash` to compare contents
instead; a file whose contents already match is left alone:

```sh
syq cp --hash --srcs-in project --into backup
```

`--hash-or-copy` also rechecks those files, but compares contents only where
the [transfer strategy](#choose-a-transfer-strategy) compares blocks, and
recopies other files whole. With the default strategy, it recopies every file
in a copy within one machine.

On FAT, which keeps times in two-second steps, times less than two seconds
apart count as matching. This doesn't apply when syq updates one named file
or copies with `--existing`.

To require known contents, give
[expected hashes in a mapping](integrity-checking.md#expected-hashes). See
[Integrity checking](integrity-checking.md) for timestamp precision and the
algorithms. For consistent source data, stop other writers or copy a snapshot.

## In-place writes

Syq normally writes each file under a temporary name and renames it into place
when it's complete. Replacing a file this way needs write permission on its
directory and room for a second copy. Use `--in-place` when that cost matters:

- `--in-place=new` writes new files directly at their final names, which
  saves a temporary name and a rename for each one; existing files are still
  replaced as usual. Readers can see a file before it's complete, and an
  interruption leaves it incomplete until a rerun finishes it.
- `--in-place=update` also updates existing files where they are, writing
  only the changed parts, so a small change to a large file needs no second
  copy.
  Anyone who has the file open, or opens it during the copy, can read the new
  contents, and an interruption leaves a mix of old and new contents until a
  rerun finishes it. Nothing else should write to the file during the copy.
  `syq rsync --inplace` does the same.

```sh
syq cp --in-place=update disk.img --to server --into /vm
```

Syq writes into an existing file only when doing so gives nobody access to
the new contents that an ordinary copy wouldn't. It replaces other files as
usual, such as a file with other hard links or another owner, or one on a
filesystem
[where syq can't tell whether it has other names](#how-syq-changes-existing-files-and-directories);
the summary says how many and why. Until the copy succeeds, files written in
place stay writable by their owner, and some are readable only by their
owner; an interrupted copy can leave them that way, and a rerun fixes this
only with `--copy-metadata=permissions`. See
[Update policies](commands/cp.md#update-policies) before combining in-place
writes with other policies.

<a id="preserve-metadata"></a>

## Copy metadata

By default, new and updated files get the source's modification time. New
files also get the source's read, write and execute permissions, limited by
the umask or the directory's default ACL; existing files and directories keep
theirs. Files whose contents already match keep all their metadata, so if
their times differ, they can be read again on every run; add
`--copy-metadata=mtime` (alias `times`) to make the times match.

To preserve more, choose what to copy, as with rsync's options:

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
| `--copy-metadata=atimes` | `-U` (access times; Linux 5.8 or later) |
| `--copy-metadata=crtimes` | `-N` (birth times; macOS destination) |
| `--open-noatime` | `--open-noatime` (reading doesn't update source access times); `-UU` selects it with `-U` |

Setting ownership needs suitable privileges on the destination. Hard links,
ACLs, xattrs, access times and birth times are not part of `syq rsync -a`, and
descriptor, stream-mapping and S3 copies reject them. No option preserves
filesystem flags such as immutable, or restores ctime or inode numbers. See
[metadata details](commands/cp.md#metadata-details), and
[Copies between S3 buckets](object-storage.md#copies-between-s3-buckets) for
S3 headers, tags and storage class.

<a id="times-and-sparse-files"></a>

`--sparse` (rsync `-S`) turns runs of zeros into holes in local and SSH
copies. The destination filesystem must support holes, or the copy fails. It
isn't part of `-a`.

### Hard links, ACLs, and extended attributes

For archival copies on Linux or macOS:

```sh
syq cp --copy-metadata=permissions,ownership,specials,hardlinks,acls,xattrs --srcs-in source --into backup
# The rsync-compatible spelling:
syq rsync -aHAX --numeric-ids source/ backup/
```

With `hardlinks`, selected names for the same file share one destination file
in local and SSH copies; links to files outside the selection are not
reconstructed. A large tree takes longer to start copying. On a filesystem
without hard links, such as FAT, exFAT or an rclone mount, syq copies one name
of each group and reports the others as failed.

`acls` copies POSIX ACLs on Linux and native ACLs on macOS, along with
permissions; copying ACLs between Linux and macOS is refused. `xattrs` copies
extended attributes: on a Linux source, a non-root user copies `user.*`
attributes, and root copies every namespace except `system.*`, including
`security.selinux` and `security.capability`. Both remove destination entries
the source lacks, and a failure to read or set them makes the copy fail.

### How syq changes existing files and directories

Read this if destination files have other hard links or another owner, or if
updating only metadata is unexpectedly slow. When only an existing file's
metadata differs, syq changes the metadata in place if all of these
hold:

- syq can tell the file has no other names (hard links),
- the file belongs to the account syq runs as, and
- the change adds no set-ID bit and changes no security attribute.

Run as root, syq changes in place whatever the file's owner could change, and
replaces the file to give it another owner or group.

Otherwise syq rewrites the file as if its contents had changed. That takes as
long as copying it, needs room for a second copy, gives the file a new inode
number, and drops attributes the copy doesn't select, such as ACLs. Access
times are always set in place.

Syq can't tell whether a file has other names on some filesystems, such as
SMB, SSHFS and other FUSE filesystems, and on macOS anything but APFS and
HFS+. There every metadata-only change rewrites the file, and
`--in-place=update` replaces files instead of updating them.

A directory gets its copied permissions after its contents, so an interrupted
copy can leave a new directory open only to its owner.

If a directory you own lacks the write or search permission a change needs,
`syq cp` names it and the changes in it fail;
[`--widen-dirs`](commands/cp.md#metadata-and-symlinks) lets syq briefly add
the missing owner permission and restore it afterwards, as `syq rsync` does by
default.

## Symlinks

Syq copies symlinks as links. To copy through a symlink in a path you supply,
use `--follow-src` for source paths or `--follow-dst` for destination paths.
`--follow` does both, and also follows paths given to options such as
`--ignore-from`.

```sh
# Copy the directory current-project points to as backup/current-project.
syq cp --follow-src current-project --into backup

# Put project inside the directory that backup points to.
syq cp project --follow-dst --into backup
```

`--as PATH` names the entry to replace, so `--follow-dst` only applies to its
parent directories: `syq cp report.txt --as latest --follow-dst` replaces a
symlink named `latest`, leaving its target unchanged. Links inside a copied
directory always stay links. See [Filesystem attacks](security.md#filesystem-attacks)
for the security details.

<a id="keep-sources-inside-a-directory"></a>

## Choose a source directory

Use `-C DIR` (or `--cwd DIR`) to resolve source paths from another directory:

```sh
syq cp -C /srv/data reports photos --into backup
```

This copies `/srv/data/reports` and `/srv/data/photos` into `backup`. `-C`
applies on the machine selected by `--from`, and doesn't change where relative
destination paths start.

Use `--root DIR` instead when selections must stay inside that directory.
Sources must then be relative: `../private` is refused, and even with
`--follow-src`, symlinks can't lead outside the root.

One copy accepts up to 1,024 named sources, such as a shell glob's expansion.
For more, select their parent directory with `--srcs-in` and leave out what
you don't want with `--ignore` or `--where`, or split the copy.

## Shell pipelines and file descriptors

Use `--src-fd 0` to read bytes from standard input, or `--as-fd 1`
to send a file's contents to another program:

```sh
# Save generated data directly on the server.
python make_report.py | syq cp --src-fd 0 --to server --as report.csv

# Feed a remote file to a local program.
syq cp --from server report.csv --as-fd 1 | python analyze_report.py
```

The same options work with local files and S3 objects. Check the whole
pipeline's status: a failed producer can leave syq with an incomplete stream
that ends normally. See [file descriptors](commands/cp.md#file-descriptors)
for process substitution, named pipes, and failure handling.

<a id="environment-variables-and-local-files"></a>

For environment overrides and cache locations, see
[Environment and local files](environment.md).
