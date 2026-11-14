# Integrity checking

This page explains how syq decides which files to copy and how you can check
what it copied.

## Comparison

By default, syq skips files whose size and modification time match. `syq cp`
compares timestamps at the precision the destination keeps, so a destination
that truncates fractions of a second still matches. `syq rsync` compares whole
seconds, as rsync does. When the destination is on FAT, which keeps times in
two-second steps, times less than two seconds apart match, except when you
copy to one existing file named as the destination or use `syq rsync
--existing`. A larger difference counts as a change, even when the source is
older.

Copies between local files and S3 compare timestamps exactly, using the time
syq stores with each uploaded object. Downloads of objects without one use
S3's modification time in whole seconds.

To compare contents even when size and timestamp match, use `--hash` (`-c` or
`--checksum` in rsync syntax), which uses BLAKE3:

```sh
syq cp --hash --srcs-in project --into backup
```

A file whose contents already match keeps its inode and any other hard links;
only its metadata is updated. `--hash-or-copy` (rsync `-I`) also stops trusting
size and timestamp, but can rewrite files that already match; see
[Check file contents](reference.md#check-file-contents).

Syq stores a hash with each object it uploads. In copies between local files
and S3, when sizes match but timestamps differ, syq compares the local file
with that hash, if the object has one, instead of copying it. With `--hash`, it
compares every file whose size matches, reading any object that has no stored
BLAKE3 hash.

## Payload checks

SSH and syq's encrypted TCP authenticate the data they carry, so by default
syq adds no check of its own. To add one, use `--integrity-checking`:

| Key | Default | Accepted values |
|---|---|---|
| `transfer` | `off` | `off`, `blake3`, `sha256`, `md5`, `xxh3-128` |

BLAKE3 and SHA-256 are cryptographic hashes. MD5 supports existing manifests;
XXH3-128 is a noncryptographic checksum. To check authenticity, use BLAKE3 or
SHA-256 with an [expected hash](#expected-hashes) from a trusted source.

`--no-tcp-encryption` turns on `transfer=xxh3-128`, unless `--integrity-checking`
sets `transfer` itself, even to `off`. That catches data corrupted in transit,
but no checksum authenticates unencrypted traffic: an attacker can replace both
the data and its checksum.

Data that fails the check is never written: syq either sends the file again in
the same run, or reports it as failed and exits with status 23. For a complete
check of a local copy, use an [expected hash](#expected-hashes).

For S3, HTTPS protects uploads, and uploads to a plain `http://` endpoint send
Content-MD5 so that the service rejects data changed in transit. With a
`transfer` algorithm, downloads also check the object's stored hash when it has
one. Copies between buckets keep stored hashes without reading the objects, and
no descriptor copy reads back what it wrote.

<a id="expected-digests"></a>

## Expected hashes

To require known contents, give a [mapping entry](commands/map.md#mapping-format)
an `expected_hash` with its algorithm and hexadecimal value. It applies
whatever the comparison and transfer settings are.

Syq checks the complete result, including reused bytes, and a mismatch fails
the file. The check happens before an existing destination is replaced. A file
written in place, with `--in-place=new` or `--in-place=update`, is already at
its name, so it keeps the copied contents when the check fails. When size and
time match, syq checks the existing destination and skips copying if its hash
matches. Dry runs don't check expectations.

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

A copy reads files over time, so if another program changes them meanwhile, the
result can mix data from different moments. For a consistent copy, use a
filesystem snapshot or stop the writer. Filesystem copies recheck each source's
size and modification time before replacing the destination, and retry or keep
the previous destination if they changed, but that doesn't catch every change.
Both `--in-place` modes let readers see incomplete files, also after an
interrupted copy.

If another program writes to a destination file while syq replaces it, its
writes can end up in the new file, except on Linux ext2/3/4, XFS, Btrfs, ZFS,
and tmpfs, where its open waits briefly or fails instead. Syq keeps the
previous destination when it detects a delayed write error, such as a full NFS
export, but not every one, and a successful copy may not survive an immediate
power loss.
