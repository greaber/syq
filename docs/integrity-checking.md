# Integrity checking

`--integrity-checking` controls extra payload checks:

| Key | Default | Accepted values |
|---|---|---|
| `transfer` | `off` | `off`, `blake3`, `sha256`, `md5`, `xxh3-128` |

BLAKE3 and SHA-256 are cryptographic hashes. MD5 supports existing manifests;
XXH3-128 is a noncryptographic checksum. Use BLAKE3 or SHA-256 with an expected
hash from a trusted source to check authenticity; see [Expected hashes](#expected-hashes).

## Comparison

Syq normally skips files whose size and modification time match. For filesystem
copies, `syq cp` compares whole seconds exactly and ignores as many trailing
fractional digits as are zero in the destination timestamp: destination
`.120000000` seconds matches source `.123456789`, and a whole-second destination
timestamp ignores the source fraction entirely. This accommodates destinations
that truncate fractional seconds. `syq rsync` compares whole seconds, as rsync
does.

Local/S3 copies compare timestamps exactly, including stored nanoseconds.
Uploads need syq metadata on the existing object for this shortcut. Downloads
use the stored source timestamp, or S3's modification time in whole seconds when
syq metadata is absent.

A timestamp difference outside that precision triggers checking even when the
source is older. Use `--hash` to check contents even when size and timestamp
match:

```sh
syq cp --hash --srcs-in project --into backup
```

`--hash` uses BLAKE3. In rsync syntax, use `-c` or `--checksum` for the same
comparison. The comparison only decides which files need copying. A file that
differs is copied the same way as without `--hash`, so local copies keep the
filesystem's copy optimizations.

File uploads store a whole-file hash in the object's syq metadata: BLAKE3,
unless a `transfer` algorithm or expected hash selects another. When a local/S3
copy has matching size but a different timestamp, syq compares the local file
with that stored hash when one is available. A matching hash avoids uploading or
downloading the object and leaves the destination timestamp alone;
`error-if-different` copies also use stored hashes. `--hash` needs a stored
BLAKE3 hash; without one, syq reads the object's contents to compute it.

## Payload checks

SSH and encrypted TCP retain their transport authentication independently.
`--no-tcp-encryption` turns on `transfer=xxh3-128` unless `--integrity-checking`
sets `transfer`, including `transfer=off`. That check catches data corrupted in
transit, but no checksum authenticates unencrypted traffic: an attacker can
replace both the data and its checksum.

For a complete check of a local copy, use an [expected hash](#expected-hashes).

For local/S3 copies, uploads over HTTPS rely on it to protect the transfer and
send no request checksum. Uploads to a plain `http://` endpoint send Content-MD5,
which the destination checks and the request signature covers, so bytes changed
in transit are rejected. Syq also sends Content-MD5 to a destination that
requires a checksum, as AWS does for buckets with an Object Lock default
retention period. When a destination reports that it received corrupted data,
syq warns and resends it, within the `s3-retries` budget. With
[storage authorization](object-storage.md#authorize-from-your-laptop), uploads
send SHA-256 or MD5 request checksums. With a `transfer` algorithm, downloads
also check the object's stored hash when it has one; use an expected hash for
objects without a stored hash. See
[Filesystem differences](object-storage.md#filesystem-differences).

Server-side S3 copies preserve stored hashes without reading or verifying
object bodies. They do not support content-hash comparison, extra transfer
hashing, or expected hashes.

Filesystem descriptor copies accept `transfer=ALGORITHM` for optional payload
checks. S3 descriptor copies reject extra transfer hashing because they do not
store syq hash metadata. Descriptor copies do not reread the result by default.

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

Differences are shown as planned updates. Add `--if-exists=error-if-different`
to report them as errors instead. For machine-readable output, add
[`--results`](automation.md); for two servers, see
[remote comparisons](remote-reference.md#verification).

## Consistency and durability

A copy reads files over time. If another program changes them while syq is
reading, the result may combine data from different moments. Syq does not
create a snapshot; use a filesystem snapshot or stop the writer when you need
a consistent view. Filesystem-to-filesystem copies recheck source size and
modification time after reading, before replacing the destination. A detected
change can trigger a retry; a failed check leaves the previous destination in
place. These checks do not detect every concurrent change. `--inplace` lets
destination readers see partial updates, including after an interrupted copy.


Successful completion does not guarantee that the copy will survive an
immediate power loss. Normal file copies do not force transferred data onto
durable storage with `fsync`.
