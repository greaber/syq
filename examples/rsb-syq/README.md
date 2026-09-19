# RSB archives through syq

This Rust client packs and restores RSB-compatible tar shards without storing
archive bodies on disk. Archive workers run on threads while one syq subprocess
transfers the batch over shared connections. It uses the same tar, Parquet-index,
and optional `.rsb` record layout as RSB; the original Python RSB package is not
needed to run it.

Build with the repository's pinned Rust toolchain:

```sh
CARGO_TARGET_DIR=target/rsb-client cargo build --release --locked \
  --manifest-path examples/rsb-syq/Cargo.toml
```

Use a syq build supporting [stream mappings](../../docs/stream-mappings.md).
The client finds `syq` on PATH, or accepts `--syq /path/to/syq`.

```sh
rsb-syq push ./dataset datasets/run-1 --to s3://bucket
rsb-syq pull datasets/run-1 ./restored --from s3://bucket
```

Omit `--to` or `--from` for local paths; an SSH endpoint is also accepted.
`--jobs` controls concurrent archives (default 8), and `push --shard-bytes`
controls the target archive size (default 512 MiB). A shard also closes after
10,000 entries. Syq controls transfer connections independently. Forward tuning
or connection options with repeated arguments, for example:

```sh
rsb-syq --syq-arg=--no-compress --syq-arg=--resource-limits=bandwidth=100M \
  push ./dataset datasets/run-2 --to server
```

Push requires a new destination prefix. It uploads shards and `empty_dirs.tar`,
then publishes `manifest.parquet`. To publish an existing RSB record afterward:

```sh
rsb-syq push ./dataset datasets/run-3 --to s3://bucket \
  --record dataset.rsb --remote-name archive
```

This preserves the record's fields, appends the remote name to `pushes`, and sets
stage `ap` (uploaded). It does not claim RSB's separate verification step ran.
The record is written to `datasets/run-3.rsb` only if it does not already exist.
Without `--record`, the client writes the archive layout and manifest only.

Pull restores into `DESTINATION.unsharding` and renames that directory after all
transfers and extraction succeed. It requires an absent destination. Failure
leaves the staging tree for inspection; remove it before retrying. Failed pushes
can leave completed shards at the new prefix. Neither operation modifies source
data or automatically retries archive production.

Use trusted RSB archives. Files, symlinks, empty directories, modes, and timestamps
are preserved; archive ownership is restored when running as root. Intermediate
directories have the same limited metadata representation as RSB. Manifest paths
must be UTF-8. Only the Parquet index uses a temporary file during restoration.
This example implements push and pull, not RSB's repository configuration,
Glacier workflows, or remote management commands.

To run the client tests against a local syq build:

```sh
SYQ_CANDIDATE_EXECUTABLE="$PWD/target/debug/syq" CARGO_TARGET_DIR=target/rsb-client \
  cargo test --locked --manifest-path examples/rsb-syq/Cargo.toml -- --include-ignored
```
