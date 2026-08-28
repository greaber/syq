# syq

`syq` copies file trees between local filesystems and hosts reachable over SSH.
It uses rsync-style source and destination arguments, but scans directories and
transfers independent files and ranges of large files in parallel. The number
of active connections is tuned automatically unless `-j N` is given.

Syq supports local-to-local, local-to-remote, remote-to-local, and direct
remote-to-remote copies. Release binaries are available for Linux and macOS.

## Compared with rsync

Syq keeps the familiar rsync workflow and many common options, but it is not an
rsync protocol implementation or a drop-in replacement. Its main additions and
deliberate differences are:

- **Parallel metadata and data work.** Directory scanning, separate files, and
  ranges of one large file can run concurrently. This hides metadata latency
  as well as keeping multiple storage and network operations in flight. Rsync
  transfers file data in one stream.
- **Direct data paths and multiple interfaces.** SSH handles authentication and
  control; by default, separately encrypted TCP connections carry the file data
  when reachable, without SSH's per-channel window or single cipher process.
  Syq probes the remote host's advertised addresses and can use a fast data
  interface even when SSH arrived over another one, or spread connections
  across comparable interfaces. This includes IP interfaces backed by an
  already configured RoCE fabric; syq itself uses TCP, not RDMA. It falls back
  to separate SSH processes when TCP is unreachable.
- **Kernel and server-side local copies.** On Linux, same-machine copies use
  `copy_file_range(2)`. The kernel can turn this into a reflink or, on a
  supporting NFS server, copy the data without sending it through the client.
- **Automatic resume and optional lookup avoidance.** Syq always stages normal
  writes in deterministic partial files. Run the same logical command again
  and it reuses matching blocks when possible; no checkpoint or `--partial`
  option is required. For unusually large repeated jobs, an explicit
  checkpoint can also skip completed-file destination lookups when the
  destination is not independently modified.
- **Direct remote-to-remote copies.** `syq hostA:src/ hostB:dst/` sends data
  from host A to host B. Rsync does not accept two remote endpoints. Syq can
  also relay through the invoking machine when requested.
- **Explicit verification.** `--verify-only` compares source and destination
  content without writing. `-c` compares every regular file block by block and
  repairs differences.
- **One filter language.** `--ignore` and `--ignore-from` use ordered
  gitignore syntax instead of rsync's include, exclude, and filter rule
  language.
- **Guarded planning and deletion.** If distinct sources would write the same
  destination path, syq refuses the command before changing the destination;
  rsync silently keeps the first source. Syq always runs `--delete` after
  copying, skips all deletion after a source or destination scan error, and
  makes `--max-delete` all-or-nothing.

Syq does not yet implement several rsync features, including rolling-checksum
delta transfer for shifted data, hard-link preservation, ACLs, extended
attributes, sparse-file preservation, `--link-dest`, and backup directories.
See [Compatibility and limitations](#compatibility-and-limitations).

## Install

With Homebrew:

```sh
brew install greaber/tap/syq
```

Or install the matching Linux or macOS release in `~/.local/bin` without
`sudo`:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

Other release files are available on the
[releases page](https://github.com/greaber/syq/releases). To build from source
with the pinned Rust toolchain:

```sh
cargo build --release
cargo install --locked --path .
```

An official release automatically starts its exact matching helper on a remote
host. On first use, the remote downloads and caches that helper. A host without
access to the release files needs a matching binary installed manually; select
it with `--syq-path`, or put it on the non-interactive `PATH` and use
`--no-bootstrap`.

The [installation reference](docs/reference.md#install) covers supported
platforms, self-updates, source builds, and remote helper verification.

## Usage

```text
syq [OPTIONS] SRC... DEST
syq [OPTIONS] [USER@]HOST:SRC... DEST
syq [OPTIONS] SRC... [USER@]HOST:DEST
```

```sh
# Push and pull over SSH.
syq -a project/ server:backup/project/
syq -a server:data/ ./data/

# Copy between filesystems on this machine, including mounted NFS filesystems.
syq -a /mnt/nfs/tree/ /local/tree/

# Copy directly from one remote host to another.
syq -a hostA:dataset/ hostB:dataset/

# Use gitignore-style filters.
syq -a --ignore node_modules --ignore .git project/ server:project/

# Preview a copy, repair content differences, or only verify them.
syq -a --dry-run -v project/ server:project/
syq -ac project/ server:project/
syq -a --verify-only project/ server:project/
```

Source placement follows rsync's trailing-slash rule:

- `syq -a src dest` copies the directory as `dest/src`.
- `syq -a src/ dest` copies the contents of `src` into `dest`.
- A single file is placed inside `dest` when `dest` is an existing directory;
  otherwise `dest` is the exact output path.
- Multiple sources require a directory destination.

Run `syq --help` for all options. The
[detailed reference](docs/reference.md) documents filtering, deletion, resume,
checkpoints, remote-to-remote operation, and the complete path rules.

## Resume, verification, and deletion

With `-t` (included in `-a`), syq uses the same size-and-modification-time quick
check as rsync. Files that need content changes are normally written beside the
destination and renamed into place when complete, so an interrupted update does
not expose a partially written final file. The partial is retained for the next
run. Use `--inplace` only when avoiding the time or free space for a staged
replacement of a large existing file is more important than atomic publication
and safe interruption.

Every block sent through syq's data protocol is checked on receipt. Syq also
retries a file whose size or modification time changes while it is being read.
These checks do not make a changing tree a point-in-time snapshot; use a
filesystem or application snapshot when that consistency is required.

`--delete` removes destination-only paths after copying finishes. Source or
destination scan errors suppress all deletion, and `--max-delete N` refuses
the entire deletion phase when the limit would be exceeded. Inspect a
destructive operation with `--dry-run -v` first.

## When parallelism applies

Parallelism helps when a single SSH process, network flow, or serial filesystem
operation leaves available capacity unused. Syq adjusts its active connection
count while a copy runs, so most users do not need to choose `-j`. It may offer
little benefit for short copies or when one operation already saturates the
limiting storage device.

The TCP data path, interface selection, and optional host configuration are
described in [Server performance tuning](SERVER-TUNING.md).

## Compatibility and limitations

The current CLI follows rsync's source placement rules and supports a useful
subset of its options. Syq speaks its own peer protocol and cannot connect to
an rsync daemon. Unsupported common rsync flags are rejected with an
explanation rather than silently ignored.

The [rsync compatibility record](RSYNC-COMPAT.md) states which behavior has
been measured, what differs deliberately, and what is not implemented. The
README describes the current interface; compatibility means the documented
behavior, not that every rsync command will work unchanged.

## Documentation

- [Detailed command and behavior reference](docs/reference.md)
- [Rsync compatibility record](RSYNC-COMPAT.md)
- [Server performance tuning](SERVER-TUNING.md)
- [Security policy](SECURITY.md)

## License

MIT. See [LICENSE](LICENSE).
