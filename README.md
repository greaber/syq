# syq

`syq` is a parallel file-tree copier for local filesystems and hosts reachable
over SSH. It uses an rsync-shaped command line, scans the source and destination
in parallel, and transfers independent files and ranges of large files over
multiple connections.

It supports local-to-local, local-to-remote, remote-to-local, and direct
remote-to-remote copies. Release binaries are available for Linux and macOS.

## Key properties

- Parallel directory scanning and file transfer, with automatic connection
  tuning or an explicit `-j N`.
- Large files can be divided into ranges so multiple workers can transfer one
  file.
- Interrupted staged transfers resume from deterministic partial files when the
  same logical command is run again. No checkpoint is needed for ordinary
  resumption.
- Content-changing writes are staged beside the destination and published with
  an atomic rename unless `--inplace` is requested.
- `--verify-only` compares source and destination content without writing;
  `-c` compares every regular file block by block and repairs differences.
- SSH authenticates remote operations. File data uses encrypted TCP connections
  when they are reachable and otherwise falls back to independent SSH
  processes.
- A direct remote-to-remote copy sends data from the source host to the
  destination host rather than through the invoking machine. `--relay` selects
  the relayed path explicitly.

`syq` is not an rsync protocol implementation or a general cloud-storage tool.
It does not currently preserve hard links, ACLs, or extended attributes, and it
does not implement rsync's rolling-checksum delta algorithm. See
[Compatibility and scope](#compatibility-and-scope).

## Quick start

```text
syq [OPTIONS] SRC... DEST
syq [OPTIONS] [USER@]HOST:SRC... DEST
syq [OPTIONS] SRC... [USER@]HOST:DEST
```

```sh
# Push and pull over SSH.
syq -a project/ server:backup/project/
syq -a server:data/ ./data/

# Copy between filesystems on this machine. This is useful with NFS and other
# high-latency filesystems as well as fast local storage.
syq -a /mnt/nfs/tree/ /local/tree/

# Copy directly from one remote host to another.
syq -a hostA:dataset/ hostB:dataset/

# Show what would be copied without changing the destination.
syq -a --dry-run -v project/ server:backup/project/

# Compare every block and repair differing blocks.
syq -ac project/ server:backup/project/

# Compare content without writing.
syq -a --verify-only project/ server:backup/project/
```

Source placement follows rsync's trailing-slash rule:

- `syq -a src dest` copies the directory as `dest/src`.
- `syq -a src/ dest` copies the contents of `src` into `dest`.
- A single file is placed inside `dest` when `dest` is an existing directory;
  otherwise `dest` is the exact output path.
- Multiple sources require a directory destination.

Run `syq --help` for the complete option list. The
[detailed reference](docs/reference.md) documents placement, filtering,
deletion, resume, checkpoints, remote-to-remote operation, and all other
current behavior.

## Install

With Homebrew:

```sh
brew install greaber/tap/syq
```

The standalone installer selects the matching Linux or macOS release and
installs it in `~/.local/bin` without `sudo`:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

To inspect the installer first, download the same URL and run the saved script.
The installer verifies the release archive before replacing an existing managed
installation. Versioned binaries, checksums, manifests, and installers are
available on the [releases page](https://github.com/greaber/syq/releases).

To build from source with the pinned Rust toolchain:

```sh
cargo build --release
cargo install --locked --path .
```

An official release automatically starts its exact matching helper on a remote
host. On first use of that release, the remote downloads and verifies the
helper under `~/.cache/syq/helpers/`; subsequent runs reuse it. A remote host
without access to the release assets needs a manually installed matching
binary selected with `--syq-path`, or a matching binary on its non-interactive
`PATH` with `--no-bootstrap`.

See the [installation reference](docs/reference.md#install) for supported
platforms, installer verification, self-updates, static builds, and remote
helper details.

## Transfer behavior

With `-t` (included in `-a`), syq uses a size-and-modification-time quick check
to skip files that appear unchanged. Without `-t`, it transfers every regular
file. Files that need content changes are written to a sidecar next to the
destination. Workers may write different ranges concurrently; after the file
is complete, syq applies the requested metadata and renames the sidecar over
the destination.

Every block sent through syq's data protocol carries a hash checked on receipt.
Syq also re-stats the source after transfer and retries a file that changed
while it was being read. These checks do not make a live tree a point-in-time
snapshot. Use a filesystem or application snapshot when the source requires
snapshot consistency.

The default staging path gives old-or-new visibility and supports interruption
and retry, but syq does not `fsync` file data. It therefore does not promise
durability across a power loss. `--inplace` avoids the second copy but permits
readers to observe partial content and can leave an incomplete destination
after interruption.

`--delete` removes destination-only paths after transfers finish. Source or
destination scan errors suppress all deletions, and `--max-delete N` refuses
the entire deletion phase when the limit would be exceeded. Always inspect a
destructive operation with `--dry-run -v` first.

For the complete contract, see [Resume and checkpoints](docs/reference.md#resume-and-checkpoints),
[Verification and consistency](docs/reference.md#verification-and-consistency),
and [Deleting extras](docs/reference.md#deleting-extras---delete).

## Where parallelism applies

Parallelism can help when one SSH process, one network flow, filesystem
metadata latency, or a single I/O request leaves available capacity unused.
Typical cases include fast LANs, high-latency WANs, NFS and FUSE filesystems,
NVMe arrays, and trees containing many independent files.

It can hurt on a single rotating disk by turning sequential I/O into seeks. Use
`-j 1` or a larger `--min-split` when the storage device is the limiting
resource. Short transfers can also spend more time establishing connections
than they save.

Syq first tries separate AES-256-GCM-protected TCP data connections whose key is
exchanged over the authenticated SSH control connection. If the destination's
TCP port range is unreachable, it reports the fallback and transfers over
separate SSH processes instead. `--no-tcp` selects the SSH data path directly.
See [Server performance tuning](SERVER-TUNING.md) for optional, measured changes
to firewall, SSH, and host configuration.

The scheduler and connection-tuning behavior are described in the
[detailed reference](docs/reference.md#how-many-connections--j).

## Compatibility and scope

The command line intentionally resembles rsync so common source and destination
spellings remain familiar. Syq speaks its own peer protocol and cannot connect
to an rsync daemon. Some rsync options are unsupported, and a few behaviors are
deliberately different where syq uses a safer or simpler rule.

The [rsync compatibility record](RSYNC-COMPAT.md) states what has been measured,
what differs, what is not implemented, and which integration test holds each
claim.

Notable current omissions include:

- rsync filter rules; syq uses ordered gitignore-style `--ignore` and
  `--ignore-from` rules;
- hard-link, ACL, extended-attribute, and sparse-file preservation;
- `--link-dest`, `--backup`, and rsync daemon mode;
- rolling-checksum delta transfer for data shifted within an existing file;
- cloud and object-storage backends.

Use rsync when those features or exact rsync compatibility matter. Use rclone
or a backend-specific client for cloud and object storage. Syq's current scope
is copying filesystem trees between local or SSH-accessible POSIX systems.

## Documentation

- [Detailed command and behavior reference](docs/reference.md)
- [Rsync compatibility record](RSYNC-COMPAT.md)
- [Server performance tuning](SERVER-TUNING.md)
- [Security policy](SECURITY.md)

## License

MIT. See [LICENSE](LICENSE).
