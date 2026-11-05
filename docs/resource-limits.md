# Resource limits

`--resource-limits` sets ceilings while syq chooses how to run the copy.
`--performance-tuning` fixes individual settings instead. Both are available
in `syq cp` and `syq rsync`; S3 copies use `syq cp`.

Supply comma-separated `KEY=VALUE` pairs:

| Key | Default | Meaning |
|---|---|---|
| `bandwidth` | `0` (unlimited) | Aggregate byte rate across the copy's workers; what is counted depends on the route |
| `workers` | Automatic | Ceiling of 1–65536 filesystem copy-worker slots |
| `s3-requests` | Automatic | Ceiling of 1–65536 simultaneous S3 data requests across objects; excludes metadata requests and idle sockets |
| `s3-objects` | Automatic | Ceiling of 1–65536 S3 objects in progress, including preparation and finalization |
| `s3-parts-per-object` | Automatic | Ceiling of 1–1024 simultaneous parts or ranges per S3 object |

Limits also apply when a server coordinates the copy, and are not saved.

<a id="where-the-limit-applies"></a>

## Bandwidth

```sh
syq cp data --to server --into backup --resource-limits bandwidth=10M
```

For ordinary SSH and TCP copies, this limits the bytes syq sends to 10 MiB/s
across all workers. It counts compressed bytes, so compressible files can copy
at a higher rate. A relay between two servers applies the rate to each leg
separately. Local, S3 and descriptor copies, and copies a receiving machine
approves, count file data before compression.

Short bursts remain possible because of buffering. Where the limit counts file
data, [`bw-pacing`](tuning.md#transfer-controls) chooses how
requests are spaced. Uploads to S3 can burst by up to one part, and copies
between buckets are not paced, since their data does not pass through this
machine. A capped local copy uses normal copying instead of filesystem
cloning.

In `syq rsync`, `--bwlimit RATE` selects the same rate limit. Do not combine it
with `--resource-limits bandwidth=RATE`.

## Bandwidth units

Rates accept decimals and case-insensitive suffixes:

| Spelling | Unit |
|---|---|
| No suffix, `K`, `KiB` | 1,024 bytes per second |
| `M`, `MiB`; `G`, `GiB`; `T`, `TiB`; `P`, `PiB` | Successive powers of 1,024 bytes per second |
| `KB`, `MB`, `GB`, `TB`, `PB` | Successive powers of 1,000 bytes per second |
| `B` | Bytes per second |

For example, `1024` and `1M` both select 1 MiB/s. Rates are rounded to the
nearest KiB/s. Zero disables the cap; nonzero values below 512 bytes/s are
rejected.

## Concurrency ceilings

```sh
syq cp data --to server --into backup --resource-limits workers=4,bandwidth=10M
```

Syq can adjust the filesystem copy-worker count up to four. By contrast,
`--performance-tuning workers=4` fixes four worker slots. Worker counts do not
include directory scanning or control connections, and do not cap total
threads, sockets, CPU use, or memory. Syq uses fewer workers, and says so,
when an endpoint's open-file limit or other resources run short; raising that
limit can allow more.

Use `workers` only for filesystem copies and the S3 keys only for S3 copies.
S3 ceilings are nested: object and per-object part counts also share the
request ceiling. Each concurrency key conflicts with the same key in
`--performance-tuning`, even when the values match, but controls for different
quantities can combine. Unknown keys, duplicate keys, zero counts, and
out-of-range values are rejected. [Restricted receiver limits](remote-reference.md#limits-and-unsupported-options)
still apply.
