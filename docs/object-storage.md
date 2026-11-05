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
| `--s3-write-header 'NAME: VALUE'` | Add a header only to requests that create or replace objects, for settings such as storage class or a server-side encryption method or KMS key that other requests reject; repeatable. It takes precedence over an `--s3-header` of the same name. Pass customer-provided encryption key headers (`x-amz-server-side-encryption-customer-*`) with `--s3-header` instead, because reads and part uploads need them too |
| `--s3-retries N` | Retry each request up to N times (0–100, default 10) after a dropped connection, a timeout, a server error or throttling; 0 disables retries |

See [S3 copies](tuning.md#s3-copies) for concurrency and part sizes.

### Retries

Retries wait longer each time and keep their concurrency slots, so throttling
also slows new work. With the default of 10, a single request can keep
retrying for a minute or more. If 8 requests in a row fail after all their
retries, `syq cp` and `syq rm` stop instead of trying the remaining objects;
rerun the command once the service is available.

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

- **Buckets and prefixes:** keys must be relative UTF-8 paths. A named source
  selects an exact object if present, otherwise its `NAME/` prefix. Use
  `--srcs-in` for prefix contents. A prefix exists when it contains objects,
  including an empty directory marker.
- **Metadata:** Uploads store each file's modification time, permissions,
  ownership, and symlink target with the object. Downloads restore symlinks
  and modification times, using S3 Last-Modified when an object has no stored
  time; add `--copy-metadata=permissions,ownership` to restore permissions and
  ownership too. Updating the metadata of an existing object rewrites it within
  S3, as described under [Copies between S3 buckets](#copies-between-s3-buckets).
  Special files are unsupported.
- **Updates:** `--if-exists=keep`, `--into-new`, and `--as-new` protect
  individual objects against concurrent creation, as reliably as your storage
  service's consistency guarantees allow. Prefix checks are not transactional.
  `--if-exists=update-if-older` compares stored file timestamps, falling back
  to S3 Last-Modified, which reflects the upload rather than the original
  file's age. `--in-place` is unsupported, as are copies between S3 and an SSH
  host; run syq on the machine that has the files.
- **Recovery:** Retrying a copy can reuse multipart work recorded in your local
  user cache. If that cache cannot be written, the copy continues with a
  warning but cannot resume later. A resumed download needs room for a second
  copy of its `.syq-s3-*.partial` file; without it, the file fails and keeps
  the partial for a later run. Remove the partial, or run
  [`syq clean-partials`](commands/clean-partials.md) on the destination, to
  start over instead. If you abandon an upload, remove its unfinished parts
  with provider tools or a lifecycle rule.

<a id="copy-between-buckets-or-prefixes"></a>

## Copies between S3 buckets

Bucket-to-bucket copies run within one service, using the same endpoint, region,
and credentials. New or changed copies keep the source's user metadata, content
headers, and tags. For objects whose contents already match, `--copy-metadata`
can update the stored modification time, permissions, ownership, and these S3
attributes:

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
at the destination, and selecting `user-metadata` or `tags` also removes
destination-only keys. These selections need S3 on both sides.

Updating tags alone uses the tagging API, which needs permission to read and
write tags, and does not rewrite the object. A provider without tag support may
drop tags from new copies. Updating other metadata copies the object onto
itself within S3, which changes its Last-Modified time and creates a new
version in a versioned bucket. That rewrite keeps the object's storage class
and encryption settings unless `--s3-header` or `--s3-write-header` overrides
them, but not its ACLs, Object Lock settings, or custom KMS encryption contexts.

New uploads and bucket copies use the provider's storage and encryption
defaults unless overridden with `--s3-write-header` or, for bucket copies,
`--copy-metadata=storage-class`. Copying a storage class can affect storage
costs and require restoring an archived object first.

Syq decides whether two objects match from the hashes it stores with its
uploads, from a whole-object SHA-256 or CRC64NVME checksum the provider reports
for both, or else from equal ETags or equal sizes and modification times. It
does not download objects to compare them, so `--hash`, `--hash-or-copy`, and
expected hashes are unsupported on this route. Use
`--if-exists=error-if-different` to reject copies whose contents cannot be
shown to match.

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
security implications.

<a id="shell-pipelines"></a>

## Descriptor copies

With `--src-fd` or `--as-fd`, `cp` transfers the raw contents of one exact
UTF-8 key instead of a prefix tree, without a local temporary file. See
[File descriptors](commands/cp.md#file-descriptors) for examples.

S3 descriptor copies send four 16 MiB parts in parallel by default, buffering
about one part for each. An upload of unknown length stops at 10,000 parts, 156.25 GiB at the default part size;
set a larger `--performance-tuning s3-part-size=SIZE` before starting a larger
upload. There is no restart recovery. An upload replaces the object only on
completion, and on failure syq tries to abort the multipart upload, which may
otherwise need provider tools to clean up. A lost completion response can mean
an upload was published despite a reported failure.

<a id="remove-objects-and-versions"></a>

## Versions and deletion

Ordinary `rm` and `cp --prune` retain historical versions in versioned buckets.
Use `rm --s3-all-versions` to permanently remove selected versions and delete
markers, or `--s3-version-id ID` for one version. Deleting a marker can reveal
an older version. Preview version deletions with `--dry-run -v`. When deleting
an exact directory-marker version, keep the trailing `/` in its key.

Tigris's batch delete ignores version IDs, so for endpoints at
`t3.storage.dev` or under `tigris.dev`, syq deletes versions one at a time,
which can take longer for large histories. Syq does not recognize Tigris
behind a custom proxy hostname: permanent version deletion there can leave
versions intact and add delete markers that hide current objects, and syq
reports failure. Use a Tigris endpoint for permanent version deletion. To undo
an unintended deletion, find the markers the failed attempt created in your
provider's version listing and remove them with `--s3-version-id` through a
Tigris endpoint, or rerun the original `--s3-all-versions` command there if you
meant to purge all versions.
