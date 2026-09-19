<a id="copy-to-and-from-object-storage"></a>

# S3 options and behavior

Use buckets with [`cp`](commands/cp.md) and [`rm`](commands/rm.md):
`--from s3://BUCKET`, `--to s3://BUCKET`, or `--on s3://BUCKET`.
Selectors and placement options name keys within the bucket.
See [copy examples](reference.md#copy-over-the-network) and [removal examples](remove.md#on-another-machine).

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

See [S3 tuning](tuning.md#s3-copies) for concurrency, part sizes, and retries.

<a id="shell-pipelines"></a>

## Descriptor copies

With [`--src-fd` or `--as-fd`](commands/cp.md#file-descriptors), `cp`
transfers one exact UTF-8 key's raw contents, without path normalization or
prefix selection. Regular-file uploads store syq's file metadata. Output
descriptors receive raw bytes; use `--preserve` to apply attributes to a regular
output file. Pipes carry only bytes. No local temporary file is created.

S3 descriptor copies default to four parallel 16 MiB parts, with about one
part of payload buffering per worker plus one input/output part. Use `s3-part-size` and `s3-retries` to change the part size and retry budget.
The usual S3 request and part concurrency controls apply; object concurrency
is always one. Unknown-length uploads stop at 10,000 parts: 156.25 GiB at the
default part size. Select a larger part size before starting a larger upload.

Buffered parts can be retried, but there is no restart recovery. Uploads
replace the object only on completion. On failure, syq attempts to abort the
multipart upload; unconfirmed cleanup may need provider tools. A lost
completion response can mean an upload was published despite a reported failure.

<a id="metadata-and-integrity"></a>
<a id="overwrites-and-recovery"></a>

## Filesystem differences

- **Buckets and prefixes:** the bucket must already exist. Keys must be relative
  UTF-8 paths. A named source selects an exact object if present, otherwise its
  `NAME/` prefix. Use `--srcs-in` for prefix contents. A prefix exists when it
  contains objects, including an empty directory marker.
- **Metadata:** syq stores timestamps, permissions, ownership, and symlinks in
  object metadata or contents. Downloads restore timestamps and symlinks;
  `--preserve` restores permissions or ownership. Special files are unsupported.
- **Updates:** `--only-new`, `--into-new`, and `--as-new` protect individual
  objects against concurrent creation. Prefix checks are not transactional.
  `--inplace` and SSH/S3 combinations are unsupported.
- **Recovery:** rerun an interrupted copy to reuse multipart work. If you abandon
  an upload, remove its unfinished parts with provider tools or a lifecycle rule.

<a id="copy-between-buckets-or-prefixes"></a>

## Copies between S3 buckets

Bucket-to-bucket copies run within one service, using the same endpoint, region,
and credentials. They preserve metadata and tags. Changes to tags, encryption,
or storage class alone do not trigger a copy. Content hashing, expected digests,
and `--verify-only` are unsupported on this route.

<a id="remove-objects-and-versions"></a>

## Versions and deletion

Ordinary `rm` and `cp --prune` retain historical versions in versioned buckets.
Use `rm --s3-all-versions` to permanently remove selected versions and delete
markers, or `--s3-version-id ID` for one version. Deleting a marker can reveal
an older version. Preview version deletions with `--dry-run -v`.

Named removal selectors choose exact keys; `--src-dir` and `--srcs-in` choose
prefix trees. An empty S3 source prefix is rejected by `cp`, so it cannot prune
an entire local destination.
