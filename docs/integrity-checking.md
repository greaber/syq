# Integrity checking

`--integrity-checking` controls extra payload checks:

| Key | Default | Accepted values |
|---|---|---|
| `transfer` | `off` | `off`, `blake3`, `sha256`, `md5`, `xxh3-128` |

BLAKE3 and SHA-256 are cryptographic hashes. MD5 supports existing manifests;
XXH3-128 is a noncryptographic checksum. Use BLAKE3 or SHA-256 with an expected
hash from a trusted source to check authenticity; see [Expected hashes](#expected-hashes).

## Comparison

Syq normally skips files whose size and modification time match. `syq cp`
compares filesystem timestamps at the precision the destination keeps: it
ignores as many trailing fractional digits as are zero in the destination
timestamp, so destination `.120000000` seconds matches source `.123456789`, and
a whole-second destination ignores the source fraction entirely. `syq rsync`
compares whole seconds, as rsync does. When either command copies into a
directory on FAT, which keeps times in two-second steps, times less than two
seconds apart count as matching; [Check file contents](reference.md#check-file-contents)
lists the exceptions. A difference outside that precision causes a check even
when the source is older.

Copies between local files and S3 compare timestamps exactly, using the time
syq stores with each uploaded object. Downloads of objects without one use
S3's modification time in whole seconds.

Use `--hash` to check contents even when size and timestamp match:

```sh
syq cp --hash --srcs-in project --into backup
```

`--hash` uses BLAKE3; in rsync syntax, use `-c` or `--checksum`. A file whose
contents already match is left alone, keeping its inode and any other hard
links to it, and only its metadata is updated.

`--hash-or-copy` (rsync `-I` or `--ignore-times`) also stops trusting matching
size and timestamp, but compares only the files the
[transfer strategy](reference.md#choose-a-transfer-strategy) would compare and
copies the rest whole, so a file whose contents already match may be
rewritten. `-c` takes precedence when both are given.

Uploads store a whole-file hash in the object's syq metadata. When a copy
between local files and S3 finds matching sizes but different timestamps, syq
compares the local file with that stored hash, if there is one, instead of
transferring the object. `--hash` needs a stored BLAKE3 hash; without one, syq
reads the object to compute it.

## Payload checks

SSH and encrypted TCP authenticate the data they carry. `--no-tcp-encryption`
turns on `transfer=xxh3-128` unless `--integrity-checking` sets `transfer`,
including `transfer=off`. That check catches data corrupted in transit, but no
checksum authenticates unencrypted traffic: an attacker can replace both the
data and its checksum.

Syq doesn't write data that fails the check. Depending on how the file was
being sent, it either sends the file again in the same run, or reports it as
failed with `data corrupted in transit; rerun the command to retry` and ends
with exit status 23. For a complete check of a local copy, use an
[expected hash](#expected-hashes).

For S3, HTTPS protects uploads; uploads to a plain `http://` endpoint send
Content-MD5, so the service rejects data changed in transit. Syq resends data
the service reports as corrupted, within its [`--s3-retries`](object-storage.md#retries).
With a `transfer` algorithm, downloads also check the object's stored hash when
it has one. Copies between buckets preserve stored hashes without reading the
objects, and do not support content comparison, transfer hashing, or expected
hashes. S3 descriptor copies also reject transfer hashing, and descriptor
copies do not reread the result.

<a id="expected-digests"></a>

## Expected hashes

Supply `expected_hash` on individual [mapping entries](commands/map.md#mapping-format)
to require known whole-file contents. The expectation includes its algorithm
and hexadecimal value, independently of the comparison and transfer settings.

Syq checks the complete result, including reused bytes, and a mismatch fails
the file. The check happens before an existing destination is replaced, but a
file written in place, with `--in-place=new` or `--in-place=update`, is already
at its name and keeps the copied contents when the check fails. When size and
time match, syq checks the existing destination and skips copying if its hash
matches. Selection filters still apply. Dry runs do not check expectations.

## Compare without copying

Use `--dry-run --hash` to compare without copying, with `-v` to list each
difference:

```sh
syq cp --dry-run -v --hash --srcs-in project --into backup
```

Each file whose contents differ is listed as a planned update. Add
`--if-exists=error-if-different` to report them as errors instead. For
machine-readable output, add [`--results`](automation.md); for two servers, see
[remote comparisons](remote-reference.md#verification).

## Consistency and durability

A copy reads files over time. If another program changes them while syq is
reading, the result may combine data from different moments. Syq does not
create a snapshot; use a filesystem snapshot or stop the writer when you need a
consistent view. Filesystem copies recheck each source's size and modification
time before replacing the destination; a change causes a retry or leaves the
previous destination in place. These checks do not detect every concurrent
change. Both `--in-place` modes let destination readers see incomplete files,
including after an interrupted copy.

When syq replaces a destination file on Linux ext2/3/4, XFS, Btrfs, ZFS, or
tmpfs, it makes sure the blocks it reuses from the old file still match what it
compared, even if another program writes that file meanwhile. While syq
protects a file of 1 MiB or more this way, another program opening it for
writing waits up to about 20 ms, or up to the kernel's lease-break time, 45
seconds by default, if syq is suspended; an open that does not wait fails and
must be retried. On macOS and on other Linux filesystems, including OverlayFS,
F2FS, network and FUSE filesystems, a program writing a destination file while
syq updates it can leave its bytes in the published file. For network storage,
copying over SSH to a receiver on one of the supported Linux filesystems avoids
this.

On Linux, and on NFS or SMB destinations mounted on macOS, syq checks for
delayed write errors, such as a full NFS export, before replacing files, and
keeps the previous destination when it finds one. This does not catch every
delayed write error, and a successful copy may not survive an immediate power
loss.
