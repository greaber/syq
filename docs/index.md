# Copy files with syq

Syq copies and removes files in parallel, on one machine or over SSH. It can
resume interrupted copies and transfer directly between servers without
forwarding your SSH agent.

[Install syq](install.md), then try a copy:

```sh
syq cp project --to server --into /backup
```

This creates or updates `/backup/project` on `server`. To copy the contents
of `project` directly into `/backup`, use `--srcs-in`:

```sh
syq cp --srcs-in project --to server --into /backup
```

Preview either command with `--dry-run`; add `-v` to see individual changes.
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
| Choose exactly where files land | [Copy and placement](reference.md#native-commands) |
| Preview changes | [Dry runs](reference.md#previewing-a-copy) |
| Skip build files or use `.gitignore` | [Ignoring paths](reference.md#ignoring-paths) |
| Mirror a directory | [Deleting extras](reference.md#deleting-extras---delete) |
| Remove files in parallel | [Removal](reference.md#removing-files) |
| Copy between two servers | [Remote-to-remote transfers](remote-to-remote.md) |
| Rename or reorganize files during a copy | [Mappings](mappings.md) |
| Read results from a script | [Automation results](automation.md) |
| Diagnose a slow copy | [Speed](speed.md) |

## Before you rely on it

Rsync mode is the most stable interface; native `cp`, `rm`, and `map` are
experimental and their command lines may change between releases. Syq runs on
Linux and macOS.

Interrupted copies can be resumed by rerunning the same command. A copy is
not a transaction or a filesystem snapshot; use snapshots for files that
other programs are actively changing. Read the short [security guide](security.md)
for the trust boundaries.
