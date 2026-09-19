# syq rsync

Copy with rsync-style arguments:

```sh
syq rsync -av project/ server:backup/project/
```

Check [Rsync compatibility](../rsync-compat.md) before replacing a script.
Trailing slashes follow rsync's rules. Here `-h` means human-readable sizes;
use `--help` for help. `SYQ_RSYNC_OPTIONS` supplies
[extra arguments](../reference.md#environment-variables-and-local-files).

<!-- CLI: rsync -->
```text
syq rsync [OPTIONS] SRC... DEST
syq rsync [OPTIONS] [USER@]HOST:SRC... DEST
syq rsync [OPTIONS] SRC... [USER@]HOST:DEST
```

## Copy policy and filtering

| Argument / option | Meaning |
|---|---|
| `-a, --archive` | Archive mode; same as -rlptgoD |
| `-r, --recursive` | Recurse into directories |
| `-l, --links` | Copy symlinks as symlinks |
| `--insecure-links` | Follow symlinks in this machine's rsync operator paths regardless of ownership (local only, as in rsync) |
| `-p, --perms` | Preserve permissions |
| `-t, --times` | Preserve modification times |
| `-g, --group` | Preserve group |
| `-o, --owner` | Preserve owner (root only) |
| `-D` | Preserve device and special files |
| `-h, --human-readable` | No-op accepted for rsync compatibility (sizes are always human-readable) |
| `--numeric-ids` | No-op accepted for rsync compatibility (syq always uses numeric uid/gid) |
| `--bwlimit <RATE>` | Limit the aggregate file-data rate across all workers (default unit: KiB/s; 0 disables) |
| `-P` | Same as --progress --partial |
| `--partial` | No-op accepted for rsync compatibility (syq always keeps partial files) |
| `-c, --checksum` | Skip quick check; compare file contents block by block and repair differences |
| `--syq-verify-only` | Syq extension: only compare source and destination contents; transfer nothing |
| `--inplace` | Update files in place instead of writing a partial and renaming. Use this to modify a large existing file without copying it first (saves time and disk space when only part of it changes). Cannot be combined with -u or --ignore-existing: an interrupted in-place write leaves a newer-looking final file those filters would then skip forever |
| `--syq-ignore <PATTERN>` | Syq extension: skip paths matching PATTERN (gitignore syntax: `foo` matches at any depth, `/foo` only at the source root, `foo/` only directories, `!pat` re-includes). Repeatable; together with --syq-ignore-from the patterns act like the lines of one .gitignore file, in command-line order, anchored at each source root. Skipping a directory skips its whole subtree, so to copy only *.jpg use: --syq-ignore '*' --syq-ignore '!*/' --syq-ignore '!*.jpg' |
| `--syq-ignore-from <FILE>` | Syq extension: securely open and read ignore patterns from raw-byte FILE (one per line, # comments); repeatable |
| `--delete` | Delete extraneous files from the destination directories (paths the source does not have). Deletion happens after the transfer and is skipped entirely if the source scan reported any error. Ignored paths (--syq-ignore) are protected on both sides. rsync's --delete-after and --delete-delay mean the same thing and are accepted. Cannot be combined with --syq-verify-only or --files-from |
| `--delete-excluded` | With --delete, also remove destination paths that the --syq-ignore patterns exclude |
| `--max-delete <N>` | With --delete, refuse all deletions if more than N are planned (exit 25). Unlike positive rsync limits, this is atomic; 0 and -1 both prohibit deletion |
| `-u, --update` | Skip regular files that are newer on the destination (directories, symlinks and specials are unaffected) |
| `--ignore-existing` | Skip updating files that already exist on the destination |
| `--existing` | Never create anything that doesn't exist yet on the destination — files, symlinks, specials, directories, or the destination root itself; existing files are still updated |
| `--max-size <SIZE>` | Don't transfer regular files larger than SIZE (e.g. 100M). With --delete the destination copy of such a file is left alone |
| `--min-size <SIZE>` | Don't transfer regular files smaller than SIZE |
| `--files-from <FILE>` | Copy only the paths listed in raw-byte FILE, securely opened before transfer (one per line, relative to the single source directory; `-` reads stdin). Listed directories are copied without their contents unless -r is given explicitly; missing parent directories are created |
| `--from0` | --files-from entries are NUL-separated instead of one per line |

## Preview and output

| Argument / option | Meaning |
|---|---|
| `-v, --verbose...` | List files with -v; explain helpers and transport with -vv |
| `-q, --quiet` | Suppress non-error messages |
| `-n, --dry-run` | Resolve mappings and transport, then estimate transfers, exclusions, and deletions; leave source and destination data unchanged (remote setup may still cache the helper or install syq) |

## SSH and transport

| Argument / option | Meaning |
|---|---|
| `-z, --compress` | Compress remote data in transit automatically (default) |
| `--no-compress` | Disable transport compression |
| `-e, --rsh <COMMAND>` | Remote shell command (default: ssh); controls agent forwarding when set |
| `--rsync-path <PATH>` | Use this exact syq executable on the remote instead of the managed helper |
| `--syq-no-bootstrap` | Syq extension: require syq on the remote PATH instead of installing a versioned helper |
| `--syq-tcp-plain` | Syq extension: use TCP data connections without encryption (trusted networks only) |
| `--syq-no-tcp` | Syq extension: send all data over ssh instead of separate TCP data connections |
| `--syq-tcp-ports <LO-HI>` | Syq extension: port range the remote listens on for TCP data connections<br><br>[default: 47600-47699] |
| `--syq-tcp-congestion <ALGO>` | Syq extension: use this congestion-control algorithm for TCP data sockets (Linux only) |
| `--syq-pscope <PATH>` | Syq extension: use an isolated SSH persistence scope created by `syq persist on --ephemeral` |

## Performance tuning

| Argument / option | Meaning |
|---|---|
| `-B, --block-size <SIZE>` | Comparison and reuse block size (64K through 64M)<br><br>[default: 4M] |
| `--performance-tuning <KEY=VALUE,...>` | [Workers, request sizes, and copy methods](../tuning.md) |

## Resource limits

| Argument / option | Meaning |
|---|---|
| `--resource-limits <KEY=VALUE,...>` | [Bandwidth and concurrency ceilings](../resource-limits.md) |

## Integrity checking

| Argument / option | Meaning |
|---|---|
| `--integrity-checking <KEY=VALUE,...>` | [Comparison and transfer checksums](../integrity-checking.md) |
| `--syq-expected-hash <ALGORITHM:HEX>` | Require one regular file to match ALGORITHM:HEX |

## Progress and results

| Argument / option | Meaning |
|---|---|
| `--progress` | Show progress (default when stderr is a terminal) |
| `--no-progress` | Never show progress |
| `--syq-progress-json` | Syq extension: emit machine-readable progress lines (JSON) on stderr |
| `--stats` | Print transfer statistics, worker waits, endpoint operations and CPU at the end |

## Sources and selection

| Argument / option | Meaning |
|---|---|
| `[PATH]...` | Source(s) and destination |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-V, --version` | Print version |
| `--help-all` | Show all options and details |
| `--help` | Show common usage and options |

<!-- /CLI -->
