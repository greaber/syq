# syq stream

Transfer one S3 object's raw contents through stdin, stdout, or an inherited
file descriptor. All arguments and options follow; see
[shell pipelines](../object-storage.md#shell-pipelines) for recovery and size limits.

```sh
syq stream --from s3://backups archive.tar > archive.tar
syq stream --to s3://backups --as archive.tar < archive.tar
```

Choose exactly one direction: downloads require `--from` and a source key;
uploads require `--to` and `--as KEY`. Keys are exact object names. Descriptors
must be open in the requested direction; descriptor 2 is reserved for diagnostics.

EOF completes an upload even if its producer failed. Downloads can leave partial
output on failure. Check the pipeline's exit status, and use Bash's `set -o pipefail`
when you also need to detect producer or consumer failure. Streams have no saved
resume state, copied filesystem metadata, progress display, or `--results` channel.

`--performance-tuning` accepts only `s3-part-size`,
`s3-max-concurrent-parts-per-object`, and `s3-retries`.
[Stream defaults and limits](../tuning.md#s3-streams) differ from file copies.
`SYQ_STREAM_OPTIONS` supplies extra arguments; see
[environment variables](../reference.md#environment-variables-and-local-files).

<!-- CLI: stream -->
```text
syq stream [OPTIONS] [KEY]
```

## Arguments

| Argument / option | Meaning |
|---|---|
| `[KEY]` | Exact source object key (no wildcard expansion) |

## Options

| Argument / option | Meaning |
|---|---|
| `--from <s3://BUCKET>` | Download from this S3 bucket |
| `--to <s3://BUCKET>` | Upload to this S3 bucket |
| `--as <KEY>` | Exact destination object key |
| `--read-fd <FD>` | Read an inherited descriptor instead of stdin |
| `--write-fd <FD>` | Write an inherited descriptor instead of stdout (stderr is reserved) |
| `--performance-tuning <KEY=VALUE>` | Choose parallelism and transfer settings. See [Performance tuning](../tuning.md) for every key, default, and restriction. |

## Object storage

| Argument / option | Meaning |
|---|---|
| `--s3-endpoint <URL>` | S3 API endpoint URL (also AWS_ENDPOINT_URL_S3 or AWS_ENDPOINT_URL) |
| `--s3-region <REGION>` | S3 signing region, used as given (otherwise syq asks AWS where the bucket is) |
| `--s3-profile <NAME>` | AWS shared configuration/credentials profile |
| `--s3-header <NAME: VALUE>` | Add a header before signing every S3 request (repeatable; S3-to-S3 metadata/tag overrides are refused) |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->

