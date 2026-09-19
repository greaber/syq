# Integrity checking

`--integrity-checking` controls how `syq cp` and `syq rsync` compare contents
and check transferred data:

| Key | Default | Accepted values |
|---|---|---|
| `compare` | `size-mtime` | `size-mtime`, `blake3`, `sha256`, `md5`, `xxh3-128` |
| `transfer` | `off` | `off`, `blake3`, `sha256`, `md5`, `xxh3-128` |

Supply comma-separated `KEY=VALUE` pairs, or repeat the option with different
keys. Comparison and transfer algorithms may differ:

```sh
syq cp data --into backup --integrity-checking compare=blake3,transfer=sha256
```

BLAKE3 and SHA-256 are cryptographic hashes. MD5 supports existing manifests;
XXH3-128 is a noncryptographic checksum. Use BLAKE3 or SHA-256 with an expected
hash from a trusted source to check authenticity; see [Expected hashes](#expected-hashes).

## Comparison

Syq normally skips files whose size and modification time match. `syq cp`
compares whole seconds exactly and ignores as many trailing fractional digits
as are zero in the destination timestamp. For example, destination `.120000000`
seconds matches source `.123456789`; a whole-second destination timestamp
ignores the source fraction entirely. This accommodates destinations that
truncate fractional seconds, but it also ignores coincidental trailing zeros;
the rule uses the timestamp, not a measurement of filesystem precision.
Directory metadata previews use the same fractional precision rule. `syq rsync`
compares whole seconds only when checking file contents.

A timestamp difference outside that precision triggers checking even when the
source is older, unless you request `--skip-newer`. Use `--hash` to check contents
even when size and timestamp match:

```sh
syq cp --hash --srcs-in project --into backup
```

`--hash` is shorthand for `compare=blake3`. It conflicts with a different
explicit comparison choice. In rsync syntax, use `-c` or `--checksum` for the
same BLAKE3 comparison.

## Payload checks

Extra payload checks default to `transfer=off`. Enable them with, for example,
`--integrity-checking transfer=blake3`.

SSH and encrypted TCP retain their transport authentication independently.
`--tcp-plain` does not enable payload checks automatically, and checksums do
not authenticate plaintext traffic: an attacker can replace both the data and
its checksum.

For a complete check of a local copy, use an [expected hash](#expected-hashes).

For local/S3 copies, provider request checksums remain enabled. The `transfer`
algorithm records a whole-file hash on upload and checks stored hashes on
download when present. Use an expected hash for objects without a stored
hash. See [Filesystem differences](object-storage.md#filesystem-differences).

Server-side S3 copies preserve stored hashes without reading or verifying
object bodies. They do not support content-hash comparison, extra transfer
hashing, or expected hashes.

Filesystem descriptor copies accept `transfer=ALGORITHM` for optional payload
checks. S3 descriptor copies reject extra transfer hashing: they keep provider
checksums but do not store syq hash metadata. Descriptor copies do not reread the result by default.

<a id="expected-digests"></a>

## Expected hashes

Supply `expected_hash` on individual [mapping entries](commands/map.md#mapping-format)
to require known whole-file contents. The expectation includes its algorithm
and hexadecimal value, independently of the comparison and transfer settings.

Syq checks the complete result, including reused bytes. A mismatch fails the
file. With normal staging, checking happens before replacing the destination;
with `--inplace`, the destination has already been modified. Matching size and
time allow syq to check the existing destination first and skip copying if its
hash matches. Selection filters still apply. Dry runs do not check expectations.

## Compare without copying

Use `--dry-run --hash` to compare without copying:

```sh
syq cp --dry-run --hash --srcs-in project --into backup
```

Differences appear as planned changes. For machine-readable output, add
[`--results`](automation.md); for two servers, see
[remote comparisons](remote-reference.md#verification).

S3 comparisons may use a stored object hash without reading the object body.

## Consistency and durability

A copy reads files over time. If another program changes them while syq is
reading, the result may combine data from different moments. Syq does not
create a snapshot; use a filesystem snapshot or stop the writer when you need
a consistent view. `--inplace` also lets destination readers see partial
updates, including after an interrupted copy.

Successful completion does not guarantee that the copy will survive an
immediate power loss. Normal file copies do not force transferred data onto
durable storage with `fsync`.
