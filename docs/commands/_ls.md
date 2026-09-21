# Experimental S3 listing

`syq _ls` lists S3 objects without downloading them. **This command is
experimental:** its name, arguments, pattern syntax, and output may change or
be removed between releases. It does not change how `syq cp` selects sources.

```sh
# List every object beneath logs/.
syq _ls 's3://my-bucket/logs/**'

# Select files from matching prefixes.
syq _ls 's3://my-bucket/logs/2026-*/service-a/*.json'

# List a whole bucket.
syq _ls 's3://my-bucket/**'
```

Quote patterns so your shell passes them unchanged. Patterns match the whole
object key, with these three operators:

| Pattern | Matches |
|---|---|
| `?` | One Unicode character other than `/` |
| `*` | Zero or more characters other than `/` |
| `**` | Zero or more characters, including `/` |

Every other character is literal, including backslashes, brackets, braces,
and slashes. There is no escape syntax. `logs` selects only that exact object;
`logs/` selects only an object whose key is `logs/`. A trailing slash never
turns on recursion. Use `logs/**` for the contents beneath that prefix.

Slashes around `**` are still required: `logs/**/file` matches
`logs/one/file` and `logs/one/two/file`, but not `logs/file`.
`logs**` also matches keys such as `logs-old/file` and `logstash`.
Patterns are case-sensitive. Percent sequences are literal key characters,
so `a%2Fb` selects that key, not `a/b`.

## Output and errors

Each matching object produces one JSON record on its own line:

```json
{"bucket":"my-bucket","key":"logs/run.json","size":42,"last_modified":"2026-01-01T00:00:00Z","etag":"\"opaque-value\""}
```

`size` is in bytes. `last_modified` and `etag` are `null` when the service
omits them. ETags are service-provided values, not a promise of a content hash.
Keys retain their exact spelling; JSON escapes newlines and other control
characters. Listing includes stored directory-marker objects but does not
invent directories or interpret syq's filesystem metadata.

Records arrive in unspecified order. No matches is a successful, empty
result. Check the exit status: a failed request or output write makes the
command fail, even if it has already printed some records. A listing is not
an atomic snapshot of a bucket being modified.

## Connections and concurrency

Use the usual AWS credentials or `--s3-profile NAME`. `--s3-endpoint URL`,
`--s3-region REGION`, and `--s3-header 'NAME: VALUE'` work as for S3 copies;
see [S3 options](../object-storage.md). `_ls` runs on the invoking machine
and does not support `--auth-from`, SSH endpoints, or local filesystem paths.

`--concurrency N` limits concurrent listing tasks (default 32, range 1–256).
Prefix discovery can reduce listing time while making additional LIST
requests. With `--concurrency 1`, the command skips speculative discovery and
uses paginated listing with local filtering, except where a literal prefix
or a final component can narrow the request directly.

<!-- CLI: _ls -->
```text
syq _ls [OPTIONS] <S3_PATH>
```

## Arguments

| Argument / option | Meaning |
|---|---|
| `<S3_PATH>` | Literal S3 object key or quoted pattern |

## Options

| Argument / option | Meaning |
|---|---|
| `--concurrency <CONCURRENCY>` | Maximum concurrent listing tasks; 1 skips speculative prefix discovery<br><br>[default: 32] |

## Object storage

| Argument / option | Meaning |
|---|---|
| `--s3-endpoint <URL>` | S3 API endpoint URL (also AWS_ENDPOINT_URL_S3 or AWS_ENDPOINT_URL) |
| `--s3-region <REGION>` | S3 signing region, used as given (otherwise syq asks AWS where the bucket is) |
| `--s3-profile <NAME>` | AWS shared configuration/credentials profile |
| `--s3-header <NAME: VALUE>` | Add a header before signing every S3 request (repeatable) |

## Help and version

| Argument / option | Meaning |
|---|---|
| `-h, --help` | Show common usage and options |
| `--help-all` | Show all options and details |

<!-- /CLI -->
