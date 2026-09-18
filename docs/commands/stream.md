# syq stream

Transfer one S3 object's contents through stdin, stdout, or an inherited
file descriptor:

```sh
syq stream --from s3://backups archive.tar > archive.tar
syq stream --to s3://backups --as archive.tar < archive.tar
```

See [shell pipelines](../object-storage.md#shell-pipelines) for failure handling
and size limits, and [environment variables](../reference.md#environment-variables-and-local-files)
for `SYQ_STREAM_OPTIONS`.

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
| `--performance-tuning <KEY=VALUE>` | [S3 stream part size, concurrency, and retries](../tuning.md#s3-streams) |

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
