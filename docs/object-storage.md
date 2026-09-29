<a id="copy-to-and-from-object-storage"></a>

<a id="s3-options-and-behavior"></a>

# Use S3 storage

Use buckets with [`cp`](commands/cp.md) and [`rm`](commands/rm.md):
`--from s3://BUCKET`, `--to s3://BUCKET`, or `--on s3://BUCKET`.
Selectors and placement options name keys within the bucket.
The bucket must already exist.

<a id="credentials-and-providers"></a>
<a id="parallelism"></a>

## S3 options

Syq uses your AWS credentials and detects AWS bucket regions automatically.

| Option | Use |
|---|---|
| `--s3-profile NAME` | Select an AWS profile |
| `--s3-endpoint URL` | Use an S3-compatible service; also accepts `AWS_ENDPOINT_URL_S3` or `AWS_ENDPOINT_URL` |
| `--s3-region REGION` | Set the signing region explicitly |
| `--s3-header 'NAME: VALUE'` | Add a provider header to every request; repeatable |
| `--s3-write-header 'NAME: VALUE'` | Add a header only to requests that create or replace objects: uploads, multipart starts, and copies; repeatable. Use it for settings such as storage class, or a server-side encryption method or KMS key, that the service rejects or ignores on other requests. Customer-provided encryption key headers (`x-amz-server-side-encryption-customer-*`) are also required on part uploads and reads, so they cannot be write-only. A write header takes precedence over an `--s3-header` of the same name |

See [S3 copies](tuning.md#s3-copies) for concurrency, part sizes, and retries.

## Upload and download

```sh
syq cp photos --to s3://backups --into laptop
syq cp --from s3://backups laptop/photos --into restored
```

The first command copies `photos` under `laptop/photos` in the bucket; the
second downloads it into `restored/photos`. Add `--dry-run` to preview either
copy. Use `--srcs-in` when you want a directory or prefix's contents instead
of its name. See [Copy files](reference.md) for placement and filtering.

To copy between buckets in the same service:

```sh
syq cp --from s3://backups --srcs-in laptop --to s3://archive --into laptop
```

For removal examples, see [Remove files](remove.md#on-another-machine).
Read [Versions and deletion](#versions-and-deletion) before deleting versioned
objects.

<a id="metadata-and-integrity"></a>
<a id="overwrites-and-recovery"></a>

## Filesystem differences

- **Buckets and prefixes:** keys must be relative UTF-8 paths. A named source selects an exact object if present, otherwise its
  `NAME/` prefix. Use `--srcs-in` for prefix contents. A prefix exists when it
  contains objects, including an empty directory marker.
- **Metadata:** syq stores timestamps, permissions, ownership, and symlinks in
  object metadata or contents. Downloads restore symlinks and set filesystem
  modification time from the stored source time, falling back to S3 Last-Modified
  when unavailable. Existing files with matching contents keep their time unless
  `--copy-metadata=mtime` requests a metadata update;
  `--copy-metadata=permissions,ownership` also restores permissions and ownership.
  New or changed uploads store these source file attributes. For matching
  contents, `--copy-metadata` selects which file attributes to reconcile. S3
  metadata updates have the object-copy effects described below. Special files
  are unsupported.
- **Updates:** `--if-exists=keep`, `--into-new`, and `--as-new` protect individual
  objects against concurrent creation. How reliably this works depends on the
  consistency guarantees of your storage service. Prefix checks are not
  transactional.
  `--if-exists=update-if-older` compares stored file timestamps, falling back
  to S3 Last-Modified when an object has no stored timestamp. S3 Last-Modified
  reflects uploads and metadata rewrites, rather than the original file's age.
  Equal timestamps use the normal content comparison.
  `--inplace` and SSH/S3 combinations are unsupported.
- **Recovery:** Retrying a copy can reuse multipart work. Recovery records are
  stored in the local user cache and removed on success. If that cache cannot be used, for example
  because it is read-only or belongs to another user, the copy continues with a
  warning, but unsaved progress cannot be reused on a later run.
  If you abandon an upload, remove its unfinished parts with provider tools or a
  lifecycle rule.

<a id="copy-between-buckets-or-prefixes"></a>

## Copies between S3 buckets

Bucket-to-bucket copies run within one service, using the same endpoint, region,
and credentials. New or changed copies retain source user metadata, content
headers, and tags. For matching contents, `--copy-metadata` can reconcile stored
modification time, permissions, ownership, and these S3 attributes:

| Selection | Source attribute to match |
|---|---|
| `content-type`, `content-encoding`, `content-language`, `content-disposition` | The corresponding content header |
| `cache-control`, `expires` | Cache response headers |
| `website-redirect` | Website redirect location |
| `user-metadata` | All application user metadata, excluding reserved `syq-*` keys |
| `tags` | The complete tag set |
| `storage-class` | Storage class, including for new or changed copies |

For example, `--copy-metadata=content-type,tags` updates those attributes even
when the contents match. A selected attribute absent on the source is cleared
at the destination, subject to service defaults. Selecting `user-metadata` or
`tags` also removes destination-only keys in that set. Unselected destination
attributes remain unchanged when contents match. These S3 selections require
named S3 sources and destinations; uploads from files, downloads, and streams
do not have corresponding source or destination attributes.

Tag-only changes use the tagging API without rewriting the object or creating a
new object version. Comparing tags requires permission to read source and
destination tags; updating them requires permission to write destination tags.
Reading tags uses a known object version when available. Tag updates using
your own credentials also use the known destination version. Your provider may
require separate permissions for reading and writing versioned tags. With
`--auth-from`, updates always target the current destination object; upload
approval does not allow changing historical versions.

New or changed copies that fit in one server-side copy request use the provider's
native tag-copy operation, without a separate tag read or support check. Providers
without tag support may accept that copy without tags. With `tags` explicitly
selected, multipart copies and tag comparisons read tags separately; if a
required tagging operation is unsupported, the copy fails.

Updating other metadata copies the destination object onto itself within
S3, preserving its contents and unselected content headers, tags, and user metadata.
It retains the destination storage class and the encryption method, KMS key,
and S3 Bucket Key setting returned by the service. Encryption settings given
with `--s3-header` or `--s3-write-header` override the selected fields:
changing a KMS key retains the compatible encryption method, while switching
away from KMS drops inherited KMS settings. Incompatible explicit encryption settings cause an error. Syq also
refuses the update if the service reports that it omitted existing metadata from
its response, because replacing that metadata could lose entries. These rules
apply to multipart metadata updates too. The update changes S3 Last-Modified and
creates a new version when bucket versioning is enabled. Object ACLs, Object Lock
settings, and custom KMS encryption contexts are not preserved by this operation.

New or changed uploads and bucket copies use the provider's storage and encryption
defaults unless overridden with `--s3-write-header` or, for bucket copies, selecting
`--copy-metadata=storage-class`. On AWS general-purpose buckets,
these are STANDARD storage and the destination bucket's default encryption.
Changes to source encryption alone do not trigger a copy. Source storage class
changes apply only when explicitly selected; copying a storage class can affect
storage costs and require restoring an archived object first.

Syq uses stored size/time, whole-file hashes, provider checksums, or ETags to
identify matching contents. Otherwise, the default policy replaces the destination.
Use `--if-exists=error-if-different` to reject copies whose contents cannot be
established as matching. Syq does not
download both bodies to compare them on this route. `--hash` and expected hashes
are unsupported.

## Authorize from your laptop

Add `--auth-from @NAME` to an S3 `cp` or `rm` command to use credentials on a
connected [receiving machine](receive.md#set-up-receiving).
`--s3-profile` selects a profile there:

```sh
syq cp results --to s3://my-bucket --into runs \
  --auth-from @laptop --s3-profile storage
```

Approve on your laptop, then wait for **storage authorization ready** before
disconnecting. Data travels directly between the server and storage.
Authorization lasts up to seven days, subject to credentials and provider
policies; restarting requires fresh approval. Both machines need the same syq
build. See [Storage authorization](security.md#storage-authorization) for the
security implications, including which credentials to use for a bucket with
Object Lock.

<a id="shell-pipelines"></a>

## Descriptor copies

With `--src-fd` or `--as-fd`, `cp` transfers one exact UTF-8 key's raw contents
instead of selecting a prefix tree. Keys are literal unless a download uses
`--cwd` or `--root`; those options resolve the source relative to a prefix using
the usual S3 path rules. Regular-file uploads store syq's file metadata. Output
descriptors receive raw bytes; use `--copy-metadata` to apply attributes to a regular
output file. Pipes carry only bytes. No local temporary file is created. See
[File descriptors](commands/cp.md#file-descriptors) for command examples.

S3 descriptor copies default to four parallel 16 MiB parts, with about one
part of payload buffering per worker plus one input/output part. Use `s3-part-size` and `s3-retries` to change the part size and retry budget.
The usual S3 request and part concurrency controls apply; object concurrency
is always one. Unknown-length uploads stop at 10,000 parts: 156.25 GiB at the
default part size. Select a larger part size before starting a larger upload.

Buffered parts can be retried, but there is no restart recovery. Uploads
replace the object only on completion. On failure, syq attempts to abort the
multipart upload; unconfirmed cleanup may need provider tools. A lost
completion response can mean an upload was published despite a reported failure.

<a id="remove-objects-and-versions"></a>

## Versions and deletion

Ordinary `rm` and `cp --prune` retain historical versions in versioned buckets.
Use `rm --s3-all-versions` to permanently remove selected versions and delete
markers, or `--s3-version-id ID` for one version. Deleting a marker can reveal
an older version. Preview version deletions with `--dry-run -v`.

Named removal selectors choose exact keys; `--src-dir` and `--srcs-in` choose
prefix trees and accept a trailing `/`. When deleting an exact directory-marker
version, keep the trailing `/` in its key. An empty S3 source prefix is rejected
by `cp`, so it cannot prune an entire local destination.
