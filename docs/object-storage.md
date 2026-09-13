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
the S3-specific variable takes precedence. Custom endpoints use path-style
bucket addressing. Use HTTPS for a service outside your machine.

For example, with Tigris credentials in `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY`:

```sh
export AWS_ENDPOINT_URL_S3=https://fly.storage.tigris.dev
export AWS_REGION=auto
syq cp data --to s3://my-bucket --into backup \
  --s3-header 'X-Tigris-Consistent: true'
syq cp --from s3://my-bucket backup/data --into restored \
  --s3-header 'X-Tigris-Consistent: true'
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

Uploads use multipart requests and downloads use concurrent byte ranges.
These options control the two levels of concurrency and the request size:

| Option | Default | Meaning |
|---|---|---|
| `-j N`, `--connections N` | 256 | Objects being processed at once; 1–1024 |
| `-c N`, `--s3-concurrency N` | 5 | Concurrent parts or ranges per object; 1–1024 |
| `-p MIB`, `--s3-part-size MIB` | 50 | Part/range size in MiB; 5–5120 |
| `--s3-retries N` | 10 | Retry budget for transient failures; 0–100 |

An object no larger than the part size uses one data request. Upload part size
increases when necessary to stay within 10,000 parts. Memory use is bounded by
active workers and their buffers; syq does not buffer whole large objects.
Discovery and collision checks finish before copying starts, so planning memory
grows with the number of selected objects.

`--bwlimit` limits the aggregate scheduled data rate, with bursts up to a part
on upload. There is no automatic tuning for S3 copies. `--no-compress` has no
effect because object bodies are transferred without compression.

## Metadata and integrity

A regular file remains an ordinary object body, readable with other S3 tools.
Syq adds versioned `x-amz-meta-syq-*` fields for its type, permission bits,
numeric owner/group, modification time with nanoseconds, and BLAKE3 digest.
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

Uploads compute SHA-256 checksums for the service to validate and record a
whole-file BLAKE3 digest. Downloads check range boundaries, lengths and object
identity, then validate the stored digest when present before publishing the
file. ETags identify the object being read; syq does not assume they are content
hashes. Without syq metadata, syq cannot supply an independent whole-file digest
that the object did not contain.

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

Rerun an interrupted copy with the same endpoint, keys, destination and options
to resume completed multipart uploads or download ranges. Recovery records live
in `$XDG_CACHE_HOME/syq/s3`, or `~/.cache/syq/s3`. Download partials live beside
the destination. Syq checks their identity and rehashes saved ranges before
reuse. Single-request downloads restart and discard their temporary file on
failure or cancellation. Existing destination files remain visible until a
verified replacement is ready.

Incomplete multipart uploads remain at the provider for recovery. If you
abandon one, abort it using your provider's tools; a bucket lifecycle rule can
also expire incomplete uploads. Removing only the local recovery record does
not remove uploaded parts. Syq does not delete unrelated objects.

S3 copies support `--results` and the Python `cp` API. Automation endpoints use
`kind: "s3"` and `host: "s3://BUCKET"`, requiring an SDK that understands S3
endpoints. SSH delegation, `--prune`, `--inplace`, `rm`, and S3-to-S3 copies are
not supported for object storage.
