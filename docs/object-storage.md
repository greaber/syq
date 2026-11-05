<a id="copy-to-and-from-object-storage"></a>

<a id="s3-options-and-behavior"></a>

# Use S3 storage

[`syq cp`](commands/cp.md) copies files to, from and between S3-compatible
buckets, and [`syq rm`](commands/rm.md) removes objects. Name the bucket with
`--from s3://BUCKET`, `--to s3://BUCKET`, or `--on s3://BUCKET`; source names
and placement options then name keys within it. The bucket must already exist.

<a id="credentials-and-providers"></a>
<a id="parallelism"></a>

## S3 options

Syq uses your AWS credentials and finds an AWS bucket's region automatically.
These options change that:

| Option | Use |
|---|---|
| `--s3-profile NAME` | Select an AWS profile |
| `--s3-endpoint URL` | Use an S3-compatible service; also accepts `AWS_ENDPOINT_URL_S3` or `AWS_ENDPOINT_URL` |
| `--s3-region REGION` | Set the signing region explicitly |
| `--s3-header 'NAME: VALUE'` | Add a provider header to every request; repeatable |
| `--s3-write-header 'NAME: VALUE'` | Add a header only to requests that create or replace objects, such as storage class or server-side encryption settings; repeatable, and overrides an `--s3-header` of the same name |
| `--s3-retries N` | Retry each request up to N times (0–100, default 10) after a dropped connection, a timeout, a server error or throttling; 0 disables retries |

Pass customer-provided encryption key headers
(`x-amz-server-side-encryption-customer-*`) with `--s3-header`, since reads
need them too. See [S3 copies](tuning.md#s3-copies) for concurrency and part
sizes.

### Retries

With the default of 10, one request can keep retrying for a minute or more.
If 8 requests in a row still fail, syq stops; rerun the command once the
service is back.

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

- **Keys and prefixes:** Keys must be relative UTF-8 paths. A source name
  selects the object with that key if there is one, and otherwise everything
  under the `NAME/` prefix; use `--srcs-in` for a prefix's contents. A prefix
  exists when it contains objects, including an empty directory marker.
- **Metadata:** Uploads store each file's modification time, permissions,
  ownership, and symlink target with the object. Downloads restore symlinks
  and modification times, using the S3 Last-Modified time when an object has
  no stored time; add `--copy-metadata=permissions,ownership` to restore
  permissions and ownership too. Changing an existing object's metadata
  rewrites it; see [Copies between S3 buckets](#copies-between-s3-buckets).
  Special files are unsupported.
- **Updates:** `--if-exists=keep`, `--into-new`, and `--as-new` protect
  individual objects against concurrent creation, as far as your storage
  service's consistency allows, but not a whole prefix.
  `--if-exists=update-if-older` compares stored file times, falling back to S3
  Last-Modified, which is the upload time rather than the file's age.
  `--in-place` is unsupported, and so are copies between S3 and an SSH host;
  run syq on the machine that has the files.
- **Recovery:** A rerun can resume interrupted uploads and downloads. A resumed
  download needs room for a second copy of its `.syq-s3-*.partial` file; to
  start over instead, remove the partial or run
  [`syq clean-partials`](commands/clean-partials.md) on the destination. If
  you abandon an upload, remove its unfinished parts with provider tools or a
  lifecycle rule.

<a id="copy-between-buckets-or-prefixes"></a>

## Copies between S3 buckets

Copies between buckets run inside the service, so both buckets must use the
same endpoint, region, and credentials. New or changed copies keep the
source's user metadata, content headers, and tags. To update these on objects
whose contents already match, select them with `--copy-metadata`, along with
`mtime`, `permissions` or `ownership` if you need them:

| Selection | Source attribute to match |
|---|---|
| `content-type`, `content-encoding`, `content-language`, `content-disposition` | The corresponding content header |
| `cache-control`, `expires` | Cache response headers |
| `website-redirect` | Website redirect location |
| `user-metadata` | All application user metadata, excluding reserved `syq-*` keys |
| `tags` | The complete tag set |
| `storage-class` | Storage class, including for new or changed copies |

A selected attribute absent on the source is cleared at the destination, and
selecting `user-metadata` or `tags` also removes destination-only keys.

Updating anything but tags rewrites the object within S3: it gets a new
Last-Modified time, and a new version in a versioned bucket. It keeps its
storage class and encryption settings unless `--s3-header` or
`--s3-write-header` overrides them, but loses its ACLs, Object Lock settings,
and custom KMS encryption contexts.

New uploads and bucket copies use the provider's storage and encryption
defaults unless overridden with `--s3-write-header` or, for bucket copies,
`--copy-metadata=storage-class`. Copying a storage class can affect storage
costs and require restoring an archived object first.

Syq never downloads objects to compare them, so `--hash`, `--hash-or-copy`
and expected hashes are unsupported here. It compares objects by their
metadata, and `--if-exists=error-if-different` rejects copies whose contents
can't be shown to match that way.

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

With `--src-fd` or `--as-fd`, `cp` streams the raw contents of one object,
named by its exact UTF-8 key, without a local temporary file. See
[File descriptors](commands/cp.md#file-descriptors) for examples.

An upload of unknown length stops at 10,000 parts, which is 156.25 GiB at
the default 16 MiB part size; set a larger
`--performance-tuning s3-part-size=SIZE` before starting a larger upload.
Descriptor copies can't be resumed.

An upload replaces the object only when it completes. If it fails, syq tries
to abort the multipart upload; if that fails too, clean it up with provider
tools. A lost completion response can mean an upload was published despite a
reported failure.

<a id="remove-objects-and-versions"></a>

## Versions and deletion

In a versioned bucket, `rm` and `cp --prune` keep older versions. Use
`rm --s3-all-versions` to permanently remove the selected objects' versions and
delete markers, or `--s3-version-id ID` for one version. Deleting a marker can
reveal an older version. Preview version deletions with `--dry-run -v`. When
deleting an exact directory-marker version, keep the trailing `/` in its key.

On Tigris, permanent version deletion needs a Tigris endpoint
(`t3.storage.dev` or under `tigris.dev`). Through a custom proxy hostname it
fails and can add delete markers that hide current objects; remove them with
`--s3-version-id` through a Tigris endpoint.
