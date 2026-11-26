<a id="copy-to-and-from-object-storage"></a>

<a id="s3-options-and-behavior"></a>

# Use S3 storage

[`syq cp`](commands/cp.md) copies files to, from and between S3-compatible
buckets, [`syq rm`](commands/rm.md) removes objects, and
[`syq find`](commands/find.md) and [`syq ls`](commands/ls.md) list them. Name
the bucket with `--from s3://BUCKET`, `--to s3://BUCKET`, or
`--on s3://BUCKET`; source names and placement options then name keys within
it. The bucket must already exist.

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
| `--s3-directory-markers MODE` | Which directories get 0-byte `dir/` markers when writing to S3: `all` (default), `empty`, or `none` |
| `--s3-retries N` | Retry each request up to N times (0–100, default 10) after a dropped connection, a timeout, a server error or throttling; 0 disables retries |

Pass customer-provided encryption key headers
(`x-amz-server-side-encryption-customer-*`) with `--s3-header`, since reads
need them too. See [S3 copies](tuning.md#s3-copies) for concurrency and part
sizes.

### Retries

With the default of 10, one request can keep retrying for a minute or more.
If 8 requests in a row still fail, syq stops; rerun the command once the
service is back.

### Listing large prefixes

Before copying or removing a prefix, for `--prune`, and for recursive
`syq find`, syq lists the keys under it. When a listing spans multiple pages and
the prefix has subdirectories, syq may split it into parallel listings, trading
extra list requests (typically up to about a quarter more on large trees) for
lower latency.

In general-purpose AWS S3 buckets, keys arrive in byte order, so syq can split
by key range as well as by subdirectory. Other services (such as Cloudflare R2,
Google Cloud Storage, Backblaze B2, Tigris, and MinIO) and S3 Express directory
buckets (`--x-s3` and `--xa-s3`) do not guarantee byte order, so syq splits
there only by subdirectory and falls back to sequential listing when a prefix
is flat or has too many subdirectories to fan out safely.

When a bucket policy allows listing only the requested prefix and denies
narrower prefixes, copies and removals fall back to a sequential listing.
`syq find` does the same if nothing has printed yet; otherwise it fails and
tells you to rerun with `--performance-tuning s3-requests=1`.

## Upload and download

```sh
syq cp photos --to s3://backups --into laptop
syq cp --from s3://backups laptop/photos --into restored
```

The first command copies `photos` under `laptop/photos` in the bucket; the
second downloads it into `restored/photos`. Add `--dry-run` to preview either
copy. Use `--srcs-in` when you want a directory or prefix's contents instead
of its name. See [Copy files](copy-files.md) for placement and filtering.

To copy between buckets in the same service:

```sh
syq cp --from s3://backups --srcs-in laptop --to s3://archive --into laptop
```

For removal examples, see [Remove files](remove.md#on-another-machine).
Read [Versions and deletion](#versions-and-deletion) before deleting versioned
objects.

## List objects

[`syq find`](commands/find.md) lists keys as paths, and
[`syq ls`](commands/ls.md) lists one level:

```sh
syq ls --on s3://backups
syq find --on s3://backups laptop/photos --long
syq find --on s3://backups -C laptop --where 'path glob "photos/2026-*/**"'
```

A `PATH` that ends with `/` names a prefix. Another `PATH` names the object
with that key if there is one, and otherwise the `PATH/` prefix, as in
copies; `-C` sets the prefix that paths start from. Directories are the
prefixes that keys imply, including empty directory markers. Each prints
once, without a trailing slash, and has no size or times. An object can
share its name with a directory, as an object `a` beside keys under `a/`
does; both print as `a`, and `--long` and `--json` show their kinds.

Listing needs only permission to list the bucket (`s3:ListBucket`).
`syq ls`, and `syq find` with `--depth`, read one directory at a time, with a
request for each thousand entries. `syq find` without a depth lists every key
under the prefix, dividing the work as copies do (see
[Listing large prefixes](#listing-large-prefixes)). A `path glob` or `path =`
condition joined to the rest of `--where` with `and` limits the requests to
the prefixes that can hold a match, such as `laptop/photos/2026-*/` rather
than all of `laptop/`, unless a condition before it could fail, such as
arithmetic on a field or checking stored object metadata like `mtime`. When syq can determine that `--where` rules out every directory, recursive
`syq find` also skips building virtual directories and skips subtrees a `path`
pattern cannot match instead of listing everything under the prefix (when a
wildcard matches more than a page of subdirectories, syq still lists under
that prefix). On S3 directory buckets whose names end with `--x-s3` or
`--xa-s3`, `syq ls` and `--depth` can also show a prefix that holds only an
in-progress multipart upload.

Conditions on `path`, `name`, `extension`, `size`, `s3_last_modified`, a
directory's `kind`, and whether `kind` is `"dir"` use the listing alone. Other
fields of an object, including whether it is a file or a symlink that syq
stored, need a HEAD request for each object the listed fields haven't ruled
out, as do `--include` `kind`, `mtime`, `mode`, `uid` and `gid`; syq sends up
to 32 at a time. `--long` and the default `--json` fields never need a HEAD
request for an object, and show files and symlinks as files and directory markers
as directories. Without
`--s3-region`, syq also asks AWS where the bucket is, with one HEAD request
for the bucket itself.

<a id="metadata-and-integrity"></a>
<a id="overwrites-and-recovery"></a>

## Filesystem differences

- **Keys and prefixes:** Keys must be relative UTF-8 paths. A source name
  selects the object with that key if there is one, and otherwise everything
  under the `NAME/` prefix; use `--srcs-in` for a prefix's contents. A prefix
  exists when it contains objects, including an empty directory marker.
- **Metadata:** Uploads store each file's modification time, permissions,
  ownership, and symlink target with the object. By default
  (`--s3-directory-markers=all`), copies to S3 write a 0-byte `dir/` marker for
  every directory so empty directories and directory permissions and
  modification times survive downloads; `empty` writes markers only for copied
  leaf directories with no objects beneath them, and `none` creates no markers
  (`empty` and `none` omit directory metadata and only control marker creation
  without deleting existing destination markers). Downloads restore symlinks
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
  `--in-place` is unsupported.
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
`--copy-metadata=storage-class`. A storage-class header takes precedence over
`--copy-metadata=storage-class`. Copying a storage class can affect storage
costs and require restoring an archived object first.

Syq never downloads objects to compare them, so `--hash`, `--hash-or-copy`
and expected hashes are unsupported here. It compares objects by their
metadata, and `--if-exists=error-if-different` rejects copies whose contents
can't be shown to match that way.

## Copy between a server and a bucket

Name an SSH server as the other end to copy between its files and a bucket
without logging in to it:

```sh
syq cp --from server --srcs-in dataset --to s3://bucket --into dataset
syq cp --from s3://bucket --srcs-in dataset --to server --into dataset
```

The copy runs on the server, and file data travels directly between the
server and the storage service, never through the machine where you typed the
command. That machine supplies the credentials: `--s3-profile`,
`--s3-endpoint`, `--s3-region` and the AWS environment variables are read
there, and it signs each storage request the server needs, so the server needs
no credentials and never receives yours. Typing the command is the approval;
there is no prompt. It signs only for the bucket, paths and operations the
command implies: for a source you name, such as `project` with
`--into backups`, that is `backups/project` and what lies under it. See
[Storage authorization](security.md#storage-authorization) for the limits and
for what this trusts the server with.

When the storage credentials are on a third machine, add `--auth-from @NAME`
to have that [receiving machine](receive.md#set-up-receiving) approve the copy
and sign instead:

```sh
syq cp --from server project --to s3://bucket --into backups \
  --auth-from @laptop --s3-profile storage
```

You approve the request on NAME, as for
[any storage authorization](#authorize-from-your-laptop), and
`--s3-profile` selects a profile there. The machine where you typed the
command only passes signing requests and signed URLs between the server and
NAME; it needs no storage credentials, and it still logs in to the server
with its own SSH access. Once syq reports **storage authorization ready**,
NAME may disconnect.

The server needs:

- network access to the storage service, and for HTTPS the usual
  [CA certificates](security.md#https-certificates);
- a clock that is roughly right;
- the same syq build as your machine, which syq installs for you as for any
  copy to a server.

`--dry-run`, `--results`, `-v`, progress and exit codes work as they do for a
copy run on the server itself. Keep the command running: if it ends or loses
its connection, the copy on the server stops. Run it again to continue; the
server keeps the records of interrupted uploads and downloads, and your
machine signs again.

Requests are signed before data starts moving and stay valid for seven days,
as for any storage authorization, or until the signing credentials expire if
that is sooner, as temporary credentials often do within an hour; syq then
says when. A copy that runs longer fails its remaining files; run it again to
continue.

Headers you add with `--s3-header` and `--s3-write-header` are sent to the
server, which makes the requests. A customer-provided encryption key would be
sent with them, so these copies refuse the
`x-amz-server-side-encryption-customer-*` headers; to copy with such a key,
run syq on the server.

These copies do not support `--detach`, `--mapping`,
`--stream-mapping-fd` or the options for copies between two servers
(`--coordinate-at`, `--peer-auth` and the TCP options). `syq rm`, copies between two buckets and
copies that also name a second server or a receiving machine (`@NAME`) cannot
run through a server this way.

## Authorize from your laptop

Add `--auth-from @NAME` to an S3 `cp` or `rm` command to use credentials on a
connected [receiving machine](receive.md#set-up-receiving).
`--s3-profile` selects a profile there:

```sh
syq cp results --to s3://my-bucket --into runs \
  --auth-from @laptop --s3-profile storage
```

Approve on your laptop, then wait for **storage authorization ready** before
disconnecting. The prompt lists the paths the command covers: for a source
you name, its own name inside the destination, and otherwise the whole
destination path. Data travels directly between the server and storage.
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
