# Copy files with syq

Syq copies and removes files in parallel, on one machine or over SSH. It can
resume interrupted copies and transfer directly between servers without
forwarding your SSH agent.

[Discussions](https://github.com/greaber/syq/discussions)

In published tests, syq copied a folder from Amsterdam to Tokyo
[5.2× faster than rsync](https://greaber.github.io/syq-bench/#fly-cross-region-memory),
and 20,000 small files to NFS
[4.6× faster than cp](https://greaber.github.io/syq-bench/#nfs-directory-trees).
These are workload-specific results; the benchmarks include cases where other
tools win.

[Install syq](install.md), then try a copy:

```sh
syq cp project --to server --into /backup
```

This creates or updates `/backup/project` on `server`. To copy the contents
of `project` directly into `/backup`, use `--srcs-in`:

```sh
syq cp --srcs-in project --to server --into /backup
```

Directories are copied recursively; no recursion flag is needed. Native
copies preserve modification times. To preserve permissions too, including
executable permissions on scripts, add `--preserve=permissions`:

```sh
syq cp --preserve=permissions project --to server --into /backup
```

The final summary shows transferred and unchanged files and bytes, directories
created, elapsed time, rate, and errors. Add `-v` for copied paths, `-vv` for
helper and transport details, or `--stats` for more totals and connection
statistics. See [understanding a copy result](reference.md).

Use `--dry-run` to preview a summary without copying, or `--dry-run -v`
to list the planned changes by path.
Existing destination files are updated when needed. Unrelated files stay
unless you request `--prune`.

## Already use rsync?

Start with your usual command, prefixed by `syq`:

```sh
syq rsync -av project/ server:backup/project/
syq rsync -av server:data/ ./data/
```

Syq supports common rsync options, but uses its own protocol. Rsync filter
rules, hard links, ACLs, xattrs, sparse files, and rolling-checksum deltas
are not supported. Check [rsync compatibility](rsync-compat.md) before
substituting it in an existing script.

## Common tasks

| I want to… | Start here |
|---|---|
| Choose exactly where files land | [Copy and placement](reference.md) |
| Preview changes | [Dry runs](reference.md#preview-changes) |
| Skip build files or use `.gitignore` | [Ignoring paths](reference.md#ignoring-paths) |
| Mirror a directory | [Mirroring](reference.md#mirror-a-directory) |
| Remove files in parallel | [Removal](remove.md) |
| Copy between two servers | [Remote-to-remote transfers](remote-to-remote.md) |
| Rename or reorganize files during a copy | [Mappings](mappings.md) |
| Read results from a script | [Automation results](automation.md) |
| Make copies faster | [Speed](speed.md) |
