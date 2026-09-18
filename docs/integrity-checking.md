# Integrity checking

`--integrity-checking` controls how `syq cp` and `syq rsync` compare contents
and check transferred data. These are all its keys:

| Key | Default | Accepted values |
|---|---|---|
| `compare` | `size-mtime` | `size-mtime`, `blake3`, `sha256`, `md5`, `xxh3-128` |
| `transfer` | `off` | `off`, `blake3`, `sha256`, `md5`, `xxh3-128` |

Supply comma-separated `KEY=VALUE` pairs, or repeat the option with different
keys. Unknown keys, duplicate keys, and unsupported values are errors. Settings
apply to this command only. Comparison and transfer algorithms may differ:

```sh
syq cp data --into backup --integrity-checking compare=blake3,transfer=sha256
```

BLAKE3 and SHA-256 are cryptographic hashes. MD5 supports existing manifests;
XXH3-128 is a fast noncryptographic checksum. Neither MD5 nor XXH3-128 provides
cryptographic collision resistance. For authenticity, an expected digest must
come from a trusted source; see [code and transport integrity](security.md#code-and-transport-integrity).

## Comparison

Syq normally skips files whose size and modification time match. `syq cp`
compares whole seconds exactly and ignores as many trailing fractional digits
as are zero in the destination timestamp. For example, destination `.120000000`
seconds matches source `.123456789`; a whole-second destination timestamp
ignores the source fraction entirely. This accommodates destinations that
truncate fractional seconds. Directory metadata previews use the same fractional
precision rule. `syq rsync` compares whole seconds only when checking file contents.

Syq preserves the source timestamp at the destination, so the machines' clocks
do not need to agree. A timestamp difference outside that precision triggers
checking even when the source is older, unless you request `--skip-newer`.

Matching metadata is a shortcut, not proof that contents match. An edit can
preserve both size and timestamp, and changes within the ignored fraction can
be missed. `--hash` checks contents even when those two attributes match:

```sh
syq cp --hash --srcs-in project --into backup
```

This changes how syq decides what needs copying. For larger network
copies, syq still compares blocks when size or modification time differs,
even without `--hash`, so it can reuse unchanged data. Local and small copies
may use faster paths instead.

`--hash` is shorthand for `compare=blake3`. It conflicts with a different
explicit comparison choice. In rsync syntax, use `-c` or `--checksum` for the
same BLAKE3 comparison. Use `compare=size-mtime` for the default metadata check.

## Payload checks

Extra payload checks default to `transfer=off`. Enable them with, for example,
`--integrity-checking transfer=blake3`. These checks do not change which files
are selected for copying.

SSH and encrypted TCP retain their transport authentication independently.
`--tcp-plain` does not enable payload checks automatically, and checksums do
not authenticate plaintext traffic. Content comparison, verification, and
recovery still hash data when needed even with `transfer=off`.

Same-host copies keep their kernel-copy and whole-file shortcuts. To validate
the complete local result, use an expected digest as described below.

For local/S3 copies, provider request checksums remain enabled. The `transfer`
algorithm records a whole-file digest on upload and checks stored digests on
download when present. It cannot supply a missing independent digest for an
object uploaded by another tool; use an expected digest in that case. See
[S3 metadata and integrity](object-storage.md#metadata-and-integrity).

Server-side S3 copies preserve stored digests without reading or verifying
object bodies. They do not support content-hash comparison, extra transfer
hashing, expected digests, or `--verify-only`. `syq stream` does not accept
`--integrity-checking` or expected digests.

## Expected digests

To require a particular whole-file digest, use `--expected-hash ALGORITHM:HEX`
with one named regular file:

```sh
syq cp data.bin --as backup.bin --expected-hash md5:900150983cd24fb0d6963f7d28e17f72
```

This checks all resulting bytes, including reused data, before reporting success;
a metadata match alone is insufficient. When size and modification time match,
syq validates the existing destination and skips copying if its digest matches.
Otherwise it copies and validates the result; a mismatch fails that file. With normal
staging, validation happens before replacing the destination. With `--inplace`,
the file has already been modified when validation finishes. Use
[per-file mapping expectations](mappings.md#the-format) for a batch. Selection
filters still exclude files, and excluded files are not digest-verified.
The expected digest's algorithm can differ from either integrity-checking hash type. Dry runs
preview changes without validating the expectation.

The algorithms are `blake3`, `sha256`, `md5`, and `xxh3-128`. Supply 64 hex
digits for BLAKE3 or SHA-256, and 32 for MD5 or XXH3-128. In `syq rsync`, use
`--syq-expected-hash ALGORITHM:HEX`.

## Compare without copying

To compare without writing, use `--verify-only`:

```sh
syq cp --verify-only --srcs-in project --into backup
```

This compares file contents, symlink targets, and entry types without writing.
Missing or different entries make the command fail. It does not compare metadata
or look for extra destination files.

For two servers, add `--coordinate-at local` to compare through your machine
using ordinary SSH access, with no restricted receiver enrollment. This also
supports `--results`. See [remote verification](remote-reference.md#verification).

`--verify-only` cannot combine with `--dry-run`, `--prune`, `--inplace`, or
an overwrite policy. Filters and size limits still select what is compared;
special files require `--preserve=specials`. In rsync syntax, use
`--syq-verify-only`.

For files being changed by another program, stop the writer or copy a snapshot.
No copy makes the whole tree transactional or guarantees durability across
power loss.
