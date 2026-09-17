# Copy to and from object storage

Use `s3://BUCKET` with `--to` or `--from`. Source selectors and placement
options name keys inside that bucket:

```sh
syq cp photos --to s3://backups --into laptop
syq cp --from s3://backups laptop/photos --into restored
syq cp --srcs-in build --to s3://artifacts --into releases/current
syq cp --from s3://artifacts releases/current/app.tar --as app.tar
```

Exactly one endpoint must be local. Run syq on the machine holding the files.
A bucket must already exist. Keys are relative UTF-8 paths; syq rejects empty
components, `.` and `..`, absolute paths, and file/directory collisions.
Shell wildcards expand locally; use `--srcs-in PREFIX` to select object keys
beneath a prefix. A named selector selects an exact object when it exists,
otherwise the objects beneath `NAME/`.

## Credentials and providers

Syq uses the AWS SDK credential chain, including environment variables, shared
configuration profiles, and workload credentials. Use `--s3-profile NAME` to
select a profile and `--s3-region REGION` to override its signing region.
Without a configured region, syq uses `us-east-1`.

For an S3-compatible service, set `AWS_ENDPOINT_URL_S3` or pass
`--s3-endpoint https://storage.example`. `AWS_ENDPOINT_URL` is also accepted;
the S3-specific variable takes precedence. Endpoint URLs in the selected AWS
configuration profile are also honored. Custom endpoints use path-style bucket
addressing. Use HTTPS for a service outside your machine.

For example, with Tigris credentials in `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY`:

```sh
export AWS_ENDPOINT_URL_S3=https://t3.storage.dev
export AWS_REGION=auto
syq cp data --to s3://my-bucket --into backup
syq cp --from s3://my-bucket backup/data --into restored
```

`--s3-header 'NAME: VALUE'` is repeatable. Headers are added before signing to
every request, including listing, multipart operations, and retries. Use
provider headers that are valid on all these operations. Repeating the same
name uses the last value. Syq refuses overrides of authentication, request
framing, ranges, conditional writes, checksums, and its own metadata headers.
Header values are omitted from results and recovery records. Command-line
arguments may still be visible to other processes on the machine.

The account needs object read/write and bucket listing permissions. Multipart
recovery also needs permission to list uploaded parts and abort obsolete
uploads. Syq does not change bucket policies or lifecycle rules.

## Parallelism

Uploads use multipart requests and downloads use concurrent byte ranges. Syq
chooses starting settings from file sizes, the backend and observed request
latency, then adjusts its shared data-request budget during the copy. Downloads
of small files over high-latency paths start with more simultaneous requests,
because short copies may finish before the budget can grow. These choices
apply independently of integrity checking, and S3 tuning writes no cache files.

For deliberate overrides, use `--performance-tuning`. These settings choose
parallelism rather than bounding the process's total resource use:

| Key | Meaning |
|---|---|
| `s3-max-concurrent-requests=N` | Maximum simultaneous data requests across all objects; 1–65536 |
| `s3-max-concurrent-objects=N` | Maximum objects in progress; 1–65536 |
| `s3-max-concurrent-parts-per-object=N` | Maximum simultaneous parts or ranges for each object; 1–1024 |
| `s3-part-size=SIZE` | Part/range size; 5M–5G |
| `s3-retries=N` | Transient failure and throttling retry budget; 0–100, default 10 |

These are nested concurrency limits, not counts of worker threads. An object
stays in progress through preparation, hashing, data transfer and finalization.
A large object's transfer can use several parts at once; a small object needs
fewer parts. Every data request also needs a shared request slot.

For example:

```sh
--performance-tuning s3-max-concurrent-objects=4,s3-max-concurrent-parts-per-object=8,s3-max-concurrent-requests=16
```

This allows up to four objects in progress and up to eight parts per object,
with at most sixteen simultaneous data requests across them. It does not reserve
eight slots for every object. An object no larger than the part size uses one
data request. Upload part size increases when necessary to stay within 10,000
parts.

An explicit maximum disables automatic adjustment of that setting; actual
concurrency can be lower when there is insufficient ready work. The shared
request limit covers uploads, range downloads and content-verification GETs.
Metadata requests and idle SDK sockets are separate, so these settings do not
cap total open sockets. The payload buffer budget still applies; an explicit
object maximum beyond the available small-upload capacity is rejected.

Small uploads share a 256 MiB payload-buffer budget. TLS and request bookkeeping
use additional memory. Large objects stream through bounded buffers. Discovery
and collision checks finish before copying starts, so planning memory grows
with the number of selected objects.

`--resource-limits bandwidth=RATE` limits the aggregate scheduled data rate,
with bursts up to a part on upload. `--no-compress` has no effect because object
bodies are transferred without compression.

## Metadata and integrity

A regular file remains an ordinary object body, readable with other S3 tools.
Syq adds versioned `x-amz-meta-syq-*` fields for its type, permission bits,
numeric owner/group, modification time with nanoseconds, and an optional content digest.
Directories use empty objects whose keys end in `/`; symlinks store the link
target as the body. Directory times and permissions are restored after children.

Downloads restore modification times. Use `--preserve=permissions` to restore
permission bits exactly, and `--preserve=ownership` for numeric owners/groups
when your local privileges allow it. Without permission preservation, existing
files keep their mode and new files use source permissions filtered through
the local umask. ACLs, extended attributes, hard-link relationships, and special
files are not represented.

Objects from other tools work without syq metadata: their body becomes a file,
using the object's modification time and the local umask. A zero-byte key
ending in `/` is treated as a directory marker. Unknown syq metadata versions
fail explicitly; syq does not guess how to restore them.

Uploads send checksums for the service to validate: SHA-256, or Content-MD5
with Cloudflare R2 endpoints. These provider checks remain active regardless of
`--integrity-checking transfer=blake3`. Syq reuses their part checksums to identify interrupted
uploads, without computing another whole-file hash by default. ETags identify
objects; syq does not assume they are content hashes.

`--integrity-checking transfer=blake3` records a whole-file digest on upload and
checks that digest, when present, before publishing a download. Choose its
algorithm in the `transfer` value, for example `transfer=sha256`. A single-part upload shares this computation
with the provider checksum when their algorithms match. Multipart provider
checksums cover individual parts and cannot replace an expected whole-file hash.
When an upload has an expected digest, syq stores and reuses that digest for
whole-file checks, avoiding a second whole-file hash with another algorithm.

`--expected-hash ALGORITHM:HEX` checks one selected regular file, including an
existing destination that passes the usual size/time quick check. Explicit
selection filters such as `--only-new` still exclude files. A mismatch prevents
publishing the replacement. Downloads can use expected hashes for objects
uploaded by any tool. For batches, put `expected_digest` on each regular-file
[mapping entry](mappings.md); failed result records preserve it for retry.
Resumed or parallel multipart downloads verify the
assembled temporary file before publication. Without an expected or stored
digest, syq cannot invent an independent whole-file checksum for an object.
Download length, range, and object-identity checks always apply; available SDK
response-checksum checks also remain enabled.

Existing BLAKE3 object metadata remains readable. Other digest algorithms use
metadata format 2; older syq binaries reject those objects explicitly rather
than interpreting the digest as BLAKE3.

Large downloads can use direct I/O when supported, so their data may not
populate the page cache. This does not promise crash durability. Downloads
requiring an assembled-file digest use buffered writes to avoid an expensive
disk readback. Buffered writes share one bounded queue per file.

`--hash` uses contents to decide whether an existing file needs copying.
`--verify-only` reads both sides and reports differences without copying.
These checks can download objects even when no replacement is needed.

## Overwrites and recovery

The [copy placement and overwrite options](reference.md) also apply to object
storage, including mappings, ignore rules, size filters, `--dry-run`,
`--only-new`, `--only-existing`, and `--skip-newer`. A prefix exists if it has
objects beneath it; it is not an independent directory in S3. New-object
uploads use conditional writes to avoid replacing an object created concurrently.
A prefix existence check is not a transaction over the bucket.

Use `--prune` to mirror selected directories or prefixes in either direction:

```sh
syq cp --srcs-in build --to s3://my-bucket --into site --prune --max-delete 100
```

This copies `build` into `site/`, then removes destination-only objects there.
S3 directory-marker objects count as individual removals.
An S3 source prefix with no objects is rejected, so it cannot empty a local
destination. Deleting from a versioned bucket uses normal S3 deletion semantics;
it does not remove historical versions. See [mirroring](reference.md#mirror-a-directory)
for scopes, exclusions, error handling, and `--max-delete`.

Rerun an interrupted copy with the same endpoint, keys,
destination and options to resume completed multipart uploads or download ranges. Recovery records live
in `$XDG_CACHE_HOME/syq/s3`, or `~/.cache/syq/s3`. Download partials live beside
the destination. Syq checks their identity and rehashes saved ranges before
reuse. Single-request downloads restart and discard their temporary file on
failure or cancellation. Existing destination files remain visible until a
replacement has passed the requested checks.

Incomplete multipart uploads remain at the provider for recovery. If you
abandon one, abort it using your provider's tools; a bucket lifecycle rule can
also expire incomplete uploads. Removing only the local recovery record does
not remove uploaded parts. Syq does not delete unrelated objects.

S3 copies support `--results` and the Python `cp` API. Automation endpoints use
`kind: "s3"` and `host: "s3://BUCKET"`, requiring an SDK that understands S3
endpoints. SSH delegation, `--inplace`, `rm`, and S3-to-S3 copies are
not supported for object storage.
