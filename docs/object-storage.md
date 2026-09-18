# Copy to and from object storage

Use `s3://BUCKET` with `--to` or `--from`. Source selectors and placement
options name keys inside that bucket:

```sh
syq cp photos --to s3://backups --into laptop
syq cp --from s3://backups laptop/photos --into restored
syq cp --srcs-in build --to s3://artifacts --into releases/current
syq cp --from s3://artifacts releases/current/app.tar --as app.tar
```

For local/S3 copies, run syq on the machine holding the files. Two S3 endpoints
can also copy within one service, as described below. SSH/S3 copies are not supported.
A bucket must already exist. Keys are relative UTF-8 paths; syq rejects empty
components, `.` and `..`, absolute paths, and file/directory collisions in
the selected source tree.
Shell wildcards expand locally; use `--srcs-in PREFIX` to select object keys
beneath a prefix. A named selector selects an exact object when it exists,
otherwise the objects beneath `NAME/`.

Ignore patterns containing `/` match bucket-relative object keys. Ignore
rules can let syq skip entire object subtrees. Download exclusion totals count
individual excluded files and count each ignored subtree once, without counting
its descendants. Keys inside ignored subtrees are not validated.

For complete option lists, see [`cp`](commands/cp.md), [`rm`](commands/rm.md),
and [`stream`](commands/stream.md).

## Shell pipelines

`syq stream` transfers one object's contents without creating a local temporary
file. Upload from stdin, or download to stdout:

```sh
gzip -c data | syq stream --to s3://backups --as data.gz
pg_dump -Fc appdb | syq stream --to s3://backups --as appdb.dump
syq stream --from s3://backups data.gz | gzip -dc > data
```

Generation and uploading can overlap, as can downloading and consumption.
Keys are exact UTF-8 object names: no prefix selection, wildcard expansion by
syq, or filesystem path normalization. Quote keys containing shell metacharacters.
The command transfers raw contents, without applying syq file metadata.
Credentials, profiles, endpoints, regions, and custom headers work as for `cp`.
[`SYQ_STREAM_OPTIONS`](reference.md#environment-variables-and-local-files) supplies
extra options when you cannot change a script's command line.

To use a descriptor your application already opened, pass `--read-fd N` for
uploads or `--write-fd N` for downloads:

```sh
syq stream --from s3://backups data.gz --write-fd 3 3>data.gz
```

The descriptor must be inherited by syq and open for the requested direction.
Any descriptor except 2 (reserved for diagnostics) is accepted. Dedicate it to
this transfer while syq runs. Syq leaves its blocking
or nonblocking mode unchanged. Regular-file descriptors use their current offset and
are not truncated, renamed, or given copied metadata. Progress and summaries
are not written; stdout contains only payload when it is the selected output.

Uploads replace the destination object on completion. EOF ends the upload;
syq cannot distinguish a successful producer from one that exited early.
In Bash, `set -o pipefail` makes a producer or consumer failure fail the pipeline,
but it cannot undo an object already uploaded. Downloads can leave partial bytes
in the consumer after failure. Require a successful exit status before treating
the transfer as complete; a consumer closing early makes syq fail.

Streams use four parallel parts of 16 MiB by default. Payload buffering is
bounded by approximately one part per worker plus one input/output part, with
additional memory for HTTP/TLS. Slow producers or consumers apply backpressure.
Override these settings with `--performance-tuning s3-part-size=SIZE`,
`s3-max-concurrent-parts-per-object=N`, or `s3-retries=N`; other tuning keys
are not accepted for streams. Increasing part size or concurrency increases
memory use. Stream concurrency does not adjust automatically.

An unknown-length upload can contain at most 10,000 parts. With the default
16 MiB part size that is 156.25 GiB; choose a larger part size before starting a
larger stream. An oversized upload fails instead of publishing a truncated
object. Provider object-size limits also apply.

Buffered upload parts and incomplete download ranges can be retried within the
configured retry budget. There is no saved state for restarting a stream after
syq exits. On a handled failure or interruption, syq attempts to abort its
multipart upload. Forced termination or a lost cleanup response can leave an
incomplete upload; use the provider's incomplete-upload cleanup facilities.
A lost completion response can mean the object was published even though syq
reported failure. Streams do not launch remote programs or support SSH endpoints.

## Credentials and providers

Syq uses the AWS SDK credential chain, including environment variables, shared
configuration profiles, and workload credentials. Use `--s3-profile NAME` to
select a profile.

On AWS you do not need to tell syq where a bucket is. Before copying, it asks
S3 which region holds the bucket, which costs one request and needs no extra
permissions. A region in your environment or profile only decides where that
question is sent. `--s3-region REGION` skips the question and is used as
given: if the bucket is elsewhere, the copy fails and names the bucket's
region. With a custom endpoint syq never asks; it signs for the configured
region, or `us-east-1` without one.

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
name uses the last value. Headers are passed through, not interpreted as a
metadata-editing operation. S3-to-S3 copies reject custom `x-amz-meta-*`,
`Content-Type`, `Content-Encoding`, `Content-Language`,
`Content-Disposition`, `Cache-Control`, `Expires`, `x-amz-tagging`, and
`x-amz-website-redirect-location`
headers because overrides behave differently for single-request and multipart
copies. Provider controls such as Tigris consistency headers and
`x-amz-storage-class` remain available.
Syq refuses overrides of authentication, request
framing, ranges, conditional writes, checksums, and its own metadata headers.
It also refuses `x-amz-copy-source*`, `x-amz-metadata-directive`, and
`x-amz-tagging-directive` on every S3 route; syq controls the copy source and
metadata/tagging directives.
Header values are omitted from results and recovery records. Command-line
arguments may still be visible to other processes on the machine.

The account needs object read/write and bucket listing permissions. Downloads
and server-side copies pin the source version when the service supplies a
version ID. On AWS, reading that version also requires `s3:GetObjectVersion`;
reading its tags requires `s3:GetObjectVersionTagging`.
Multipart recovery also needs permission to list uploaded parts and abort
obsolete uploads. Server-side copies preserve tags; multipart copies can need
additional permissions to read source tags and write them at the destination.
Permission errors fail the copy. If a service does not support reading tags
(HTTP 501), syq warns and continues without them only when it cannot determine
whether the source has tags; known tags are never silently dropped. Syq does
not change bucket policies or lifecycle rules.

## Parallelism

Syq transfers objects in parallel, splitting large uploads into parts and
large downloads into byte ranges. It chooses settings automatically and adjusts
concurrency as the copy runs. Start with the defaults; short copies may finish
before syq can measure a better setting. S3 tuning is not saved between runs.

Use the [S3 performance-tuning reference](tuning.md#s3-copies) for the complete
object, part, request, and retry controls. Explicit limits override automatic
choices; they do not cap total process memory or open sockets.

Small uploads share a 256 MiB payload-buffer budget. TLS and request bookkeeping
use additional memory. Large objects stream through bounded buffers. Discovery
and collision checks finish before copying starts, so planning memory grows
with the number of selected objects.

`--resource-limits bandwidth=RATE` limits the aggregate scheduled data rate,
with bursts up to a part on upload. It does not pace server-side copies, where
object bodies do not pass through this machine. `--no-compress` has no effect because object
bodies are transferred without compression.

## Copy between buckets or prefixes

Use two S3 endpoints to copy within the same service:

```sh
syq cp --from s3://source-bucket --srcs-in reports --to s3://destination-bucket --into archive --prune
```

The service copies object contents directly. Syq sends listing, metadata, and
copy requests; it does not download or relay object bodies. Both buckets use
the same configured endpoint, region, and credentials. Copying between different
providers is not supported, and failed server-side copies never fall back to
local downloads and uploads. Overlapping source and destination paths in the
same bucket are rejected, including a destination prefix equal to, inside,
or above a selected source prefix.

Placement, selection filters, overwrite choices, `--dry-run`, `--results`, and
`--prune` work as for local/S3 copies. Object metadata and tags are copied,
including syq metadata and stored digests. Preserving a digest does not verify
the object's contents. `--hash`, `--verify-only`, `--expected-hash`, mapping
expected digests, and transfer hashing are not supported for server-side copies.
The destination uses its bucket's default encryption
unless request headers specify otherwise; source ACLs are not copied.
Syq leaves storage class unspecified by default, letting the destination
service choose it; the source storage class is not preserved. To select a
class, pass a provider-supported value, for example
`--s3-header 'x-amz-storage-class: STANDARD_IA'` for AWS S3. The Python API
accepts `s3_header=["x-amz-storage-class: STANDARD_IA"]`. Supported classes
and defaults vary by provider. These headers apply when an object is copied;
changing them alone does not force an unchanged object to be copied.

Syq skips existing objects when their type, size, user metadata and content
headers match, along with a provider-reported whole-object checksum. Without
comparable checksums, it uses matching ETags or syq file metadata. Multipart
layout and encryption can change ETags, so objects without another basis for
comparison may be copied again even when their contents have not changed.
Tag-only changes do not trigger a copy; ACLs, storage class, and encryption
settings are also excluded from this quick check.

S3 permits a key and keys beneath its corresponding prefix to coexist. Server-side
copies do not reject an existing destination solely for that reason.

By default, server-side copies use one copy request up to the 5 GiB limit.
An explicit `s3-part-size` also sets the multipart threshold, capped at that
limit. Larger objects use concurrent multipart server-side copying, with the shared
request budget described above. Use `s3-max-concurrent-parts-per-object` to
limit one object's share of that budget. Failed or cancelled
multipart copies attempt to abort their unfinished upload; retries restart that object.
If cleanup fails, syq reports the upload ID for manual cleanup. Already completed
objects remain available.

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
with Cloudflare R2 endpoints. These provider checks stay active regardless of
syq's optional integrity settings. ETags identify objects; syq does not assume
they are content hashes.

`--integrity-checking transfer=blake3` records a whole-file digest on upload and
checks that digest, when present, before publishing a download. Choose another
[hash algorithm](reference.md#check-file-contents) in the `transfer` value, for
example `transfer=sha256`. Multipart provider checksums cover individual parts
and do not replace a whole-file check.

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

Large downloads can bypass the page cache when supported. Completion does not
guarantee durability after a machine crash.

`--hash` uses contents to decide whether an existing file needs copying.
`--verify-only` reads both sides and reports differences without copying.
These checks can download objects even when no replacement is needed.

## Overwrites and recovery

The [copy placement and overwrite options](reference.md) also apply to object
storage, including mappings, ignore rules, size filters, `--dry-run`,
`--only-new`, `--only-existing`, and `--skip-newer`. A prefix exists if it has
objects beneath it; it is not an independent directory in S3. By default,
uploads and server-side copies can replace an object created concurrently. `--only-new`, `--into-new`, and `--as-new` use conditional writes;
a concurrent creation makes the write fail rather than replacing that object.
A prefix existence check is not a transaction over the bucket.
`--into-existing photos` requires an object beneath `photos/`, including a
directory-marker object named `photos/`. An empty prefix without a marker does
not exist. For a file or symlink source, `--as-existing photos` requires the exact object
`photos`; objects beneath `photos/` do not satisfy it.

Uploads, downloads, verification reads, and S3 API responses have no fixed
duration or stall deadline. A slow or paused request can continue when the
provider resumes responding. If it never responds, cancel the copy to stop
waiting. Connection attempts still have a timeout.

Syq retries transient transport and provider errors within the `s3-retries`
budget. It can also retry a download range that is much slower than comparable
reads in the same copy, checking object identity before reusing received bytes.
Set `s3-retries=0` to disable retries.

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

Rerun an interrupted copy with the same endpoint, keys, destination and options
to reuse completed upload parts or download ranges. Recovery records live in `$XDG_CACHE_HOME/syq/s3`, or `~/.cache/syq/s3`. Download partials live beside
the destination. Syq checks their identity and rehashes saved ranges before
reuse. Single-request downloads restart and discard their temporary file on
failure or cancellation. Existing destination files remain visible until a
replacement has passed the requested checks. Recovery handles interrupted
processes and connections; it does not guarantee recovery after a machine crash.
If a crash damages a recovery record, syq names the file in its error; remove
it to restart that object.

Incomplete multipart uploads remain at the provider for recovery. If you
abandon one, abort it using your provider's tools; a bucket lifecycle rule can
also expire incomplete uploads. Removing only the local recovery record does
not remove uploaded parts. Syq does not delete unrelated objects.

S3 copies support `--results` and the Python `cp` API. Automation endpoints use
`kind: "s3"` and `host: "s3://BUCKET"`, requiring an SDK that understands S3
endpoints. SSH delegation and `--inplace` are
not supported for object storage.

## Remove objects and versions

`syq rm --on s3://BUCKET` removes selected keys or explicitly selected prefix
trees. Named paths, `--src`, and `--srcs` select only the exact object; they
refuse a prefix tree. Use `--src-dir name` to recursively remove `name/`, or
`--srcs-in name` to remove its contents while keeping its directory-marker
object. If `name` and `name/` coexist, each selector removes only its selected
object or tree. Use `--srcs-in .` for bucket contents. Removal never deletes the
bucket itself. Selectors are literal paths, not wildcard patterns; `-C` and
`--root` set a key prefix. Missing selections succeed without removing anything.
`--follow-src` is unsupported for S3 removal. `--follow` applies only to symlinks
in the local `--results` path; it does not follow links stored as S3 objects.

```sh
# Preview ordinary removal. Versioned buckets retain historical contents.
syq rm --on s3://my-bucket --src-dir old-backup --dry-run -v

# Permanently remove the tree's versions, including hidden keys and delete markers.
syq rm --on s3://my-bucket --src-dir old-backup --s3-all-versions

# Permanently remove one version of one exact key.
syq rm --on s3://my-bucket report.txt --s3-version-id VERSION_ID
```

`--s3-all-versions` and `--s3-version-id` are mutually exclusive and apply only
to S3 removal. With `--s3-all-versions`, named selectors include the exact
key's hidden history. Explicit directory selectors include only the selected
prefix's history, even when an exact key also has live or historical versions.

A version ID requires one named or non-directory selector;
a named key ending in `/` can identify a directory marker's version. Removing
a delete marker alone can reveal an older version. `--dry-run -v` previews
version IDs and identifies delete markers without sending deletion requests.
The same endpoint, region, profile, and custom-header options work as for copies.

All selectors and listings are checked before deletion begins. Overlapping
selections remove each key/version once. Removal sends concurrent batches of up
to 1,000 entries and continues after individual or batch failures, reporting
partial failure with exit 23. It cannot undo earlier removals. With
`--s3-all-versions`, all selected data versions are attempted before any delete
markers. If any data version fails, all selected markers are preserved and
reported as failed removals with zero attempts and unknown retryability. Resolve
the data-version failures before retrying the purge. Preserving markers keeps
hidden contents from being exposed after an incomplete purge. Interrupting
planning cancels it without deleting anything. Once deletion starts, interruption
stops new batches and waits for deletion requests already sent to finish.
Stop concurrent writers when clearing a prefix: versions created after listing
are not part of the removal plan. Version operations require permission to list
and delete versions; retention rules may prevent permanent deletion.

On recognized Tigris endpoints, versioned removal prints a compatibility warning:
bulk deletion has been observed to ignore version IDs and create delete markers
instead. The warning also appears in dry runs. It does not block removal or
change the API requests; provider behavior may change. Check the resulting
version history when using these options.

The Python `rm` and `AsyncClient.rm` APIs accept `s3_all_versions=True` or
`s3_version_id="..."`, along with `on="s3://BUCKET"` and the S3 connection options.
Removal results count each version or delete marker as one entry.
