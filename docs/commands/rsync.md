# syq rsync

Copy with rsync-style arguments:

```sh
syq rsync -av project/ server:backup/project/
```

Check [Rsync compatibility](../rsync-compat.md) before replacing a script.
Trailing slashes follow rsync's rules. Here `-h` means human-readable sizes;
use `--help` for help. `SYQ_RSYNC_OPTIONS` supplies
[extra arguments](../environment.md#add-options-through-the-environment).

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
| `--insecure-links` | Follow symlinks in the local paths you give, whoever owns them (as in rsync) |
| `-H, --hard-links` | Preserve hard links between selected regular files |
| `-A, --acls` | Preserve native Linux or macOS ACLs; implies permissions |
| `-X, --xattrs` | Preserve extended attributes |
| `-p, --perms` | Preserve permissions |
| `-t, --times` | Preserve modification times |
| `-U, --atimes...` | Preserve access times; give it twice to also apply --open-noatime |
| `-N, --crtimes` | Preserve birth (creation) times; requires a macOS destination |
| `--open-noatime` | Request reads without access-time updates; warn and continue if unavailable |
| `-S, --sparse` | Turn written zero ranges into sparse holes |
| `-g, --group` | Preserve group |
| `-o, --owner` | Preserve owner (root only) |
| `-D` | Preserve device and special files |
| `-h, --human-readable` | No-op accepted for rsync compatibility (sizes are always human-readable) |
| `--numeric-ids` | No-op accepted for rsync compatibility (syq always uses numeric uid/gid) |
| `--bwlimit <RATE>` | Limit the total transfer rate, the same limit as the bandwidth resource limit; SSH and TCP copies count compressed bytes (default unit: KiB/s; 0 disables) |
| `-P` | Same as --progress --partial |
| `--partial` | No-op accepted for rsync compatibility (syq keeps partial files a later copy can resume from) |
| `-c, --checksum` | Skip quick check; compare file contents block by block and repair differences |
| `-I, --ignore-times` | Don't skip files whose size and modification time match: compare them where blocks are reused (by default, between different machines) and copy the rest whole |
| `--inplace` | Update existing files in place, writing only what changed, as syq cp --in-place=update does. Cannot be combined with -u or --ignore-existing, which would skip a file that an interrupted update left incomplete |
| `--syq-ignore <PATTERN>` | Syq extension: skip paths matching a gitignore-style PATTERN (repeatable). Skipping a directory skips its whole subtree, so to copy only *.jpg use: --syq-ignore '*' --syq-ignore '!*/' --syq-ignore '!*.jpg' |
| `--syq-ignore-from <FILE>` | Syq extension: read gitignore-style patterns from FILE (repeatable) |
| `--syq-widen-dirs <MODE>` | Syq extension: which directories you own may briefly get the owner permission the copy needs; each is restored afterwards<br><br>Possible values:<br>- none: Never change directory permissions<br>- rsync: Directories the copy includes, as rsync does, but not the directory it copies into<br>- all: Also the directory the copy goes into and the directories above it<br><br>[default: rsync] |
| `--delete` | After copying, delete destination files the source does not have; skipped if scanning reported errors, and ignored paths are kept. Also accepted as --delete-after or --delete-delay. Cannot be combined with --files-from |
| `--delete-excluded` | With --delete, also remove destination paths that the --syq-ignore patterns exclude |
| `--max-delete <N>` | With --delete, refuse all deletions if more than N are planned (exit 25). Unlike positive rsync limits, this is atomic; 0 and -1 both prohibit deletion |
| `-u, --update` | Skip regular files that are newer on the destination (directories, symlinks and specials are unaffected) |
| `--ignore-existing` | Skip updating files that already exist on the destination |
| `--existing` | Never create anything that doesn't exist yet on the destination — files, symlinks, specials, directories, or the destination root itself; existing files are still updated |
| `--max-size <SIZE>` | Don't transfer regular files larger than SIZE (e.g. 100M). With --delete the destination copy of such a file is left alone |
| `--min-size <SIZE>` | Don't transfer regular files smaller than SIZE |
| `--files-from <FILE>` | Copy only the paths listed in FILE, one per line, relative to the single source directory (`-` reads stdin). Listed directories are copied without their contents unless -r is given explicitly |
| `--from0` | --files-from entries are NUL-separated instead of one per line |

## Preview and output

| Argument / option | Meaning |
|---|---|
| `-v, --verbose...` | List files with -v; show connection details with -vv |
| `-q, --quiet` | Suppress non-error messages |
| `-n, --dry-run` | Show what would be transferred, skipped, and deleted without changing source or destination files (remote setup may still install syq) |

## SSH and transport

| Argument / option | Meaning |
|---|---|
| `-z, --compress` | Compress remote data in transit automatically (default) |
| `--no-compress` | Disable transport compression |
| `-e, --rsh <COMMAND>` | Remote shell command (default: ssh); when set, it controls SSH options and agent forwarding |
| `--syq-auth-from <auto\|ssh\|@NAME\|HOST>` | Whose SSH access to use: this machine's own (auto or ssh), or access approved by a receiving machine (@NAME) or SSH authorization provider (HOST). When omitted, use SYQ_AUTH_FROM, then the saved choice, then auto |
| `--rsync-path <PATH>` | Run the remote syq at PATH instead of syq's automatically installed copy |
| `--syq-no-bootstrap` | Syq extension: run the syq found in the remote $PATH instead of syq's automatically installed copy |
| `--syq-no-tcp-encryption` | Syq extension: send TCP data without encryption or authentication; use only on trusted networks |
| `--syq-no-tcp` | Syq extension: send all data over ssh instead of separate TCP data connections |
| `--syq-tcp-ports <LO-HI>` | Syq extension: port range the remote listens on for TCP data connections<br><br>[default: 47600-47699] |
| `--syq-tcp-congestion <ALGO>` | Syq extension: use this congestion-control algorithm for TCP data sockets (Linux only) |
| `--syq-pscope <PATH>` | Syq extension: use the isolated connections and settings that `syq persist on --ephemeral` created at PATH; requires the default ssh or an -e ssh command |

## Performance tuning

| Argument / option | Meaning |
|---|---|
| `-B, --block-size <SIZE>` | Block size for comparing files and reusing matching blocks (64K through 64M)<br><br>[default: 4M] |
| `-W, --whole-file` | Copy selected files whole; the default for local copies |
| `--no-whole-file` | Reuse matching blocks at the same offsets in the destination file; the default for remote copies<br><br>[alias: --no-W] |
| `--performance-tuning <KEY=VALUE,...>` | [Workers, request sizes, and copy methods](../tuning.md) |

## Resource limits

| Argument / option | Meaning |
|---|---|
| `--resource-limits <KEY=VALUE,...>` | [Bandwidth and concurrency ceilings](../resource-limits.md) |

## Integrity checking

| Argument / option | Meaning |
|---|---|
| `--integrity-checking <KEY=VALUE,...>` | [Payload checks](../integrity-checking.md) |

## Progress and results

| Argument / option | Meaning |
|---|---|
| `--progress` | Show progress (default when stderr is a terminal) |
| `--no-progress` | Never show progress |
| `--stats` | Print transfer statistics at the end |

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
