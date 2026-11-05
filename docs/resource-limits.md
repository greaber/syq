# Resource limits

Use `--resource-limits` to keep syq's automatic choices under a ceiling, for
example to leave bandwidth for other work. To fix a setting instead, use
[`--performance-tuning`](tuning.md). Both work with `syq cp` and `syq rsync`;
S3 copies use `syq cp`.

Supply comma-separated `KEY=VALUE` pairs:

| Key | Default | Meaning |
|---|---|---|
| `bandwidth` | `0` (unlimited) | Aggregate byte rate across the copy's workers; what is counted depends on the route |
| `workers` | Automatic | Ceiling of 1–65536 filesystem copy-worker slots |
| `s3-requests` | Automatic | Ceiling of 1–65536 simultaneous S3 data requests across objects; excludes metadata requests and idle sockets |
| `s3-objects` | Automatic | Ceiling of 1–65536 S3 objects in progress, including preparation and finalization |
| `s3-parts-per-object` | Automatic | Ceiling of 1–1024 simultaneous parts or ranges per S3 object |

<a id="where-the-limit-applies"></a>

## Bandwidth

```sh
syq cp data --to server --into backup --resource-limits bandwidth=10M
```

Over SSH and TCP, this limits the bytes syq sends to 10 MiB/s across all
workers. It counts compressed bytes, so compressible files can copy faster. A
relay between two servers applies the rate to each leg separately. Local, S3
and descriptor copies, and copies a receiving machine approves, count file data
before compression.

Buffering allows short bursts. For local, descriptor, and receiver-approved
copies, [`bw-pacing`](tuning.md#transfer-controls) chooses how requests are
spaced. S3 uploads can burst by up to one part, and copies between buckets
aren't limited, since their data doesn't pass through this machine. A capped
local copy uses normal copying instead of filesystem cloning.

In `syq rsync`, `--bwlimit RATE` sets the same limit.

## Bandwidth units

Rates accept decimals and case-insensitive suffixes:

| Spelling | Unit |
|---|---|
| No suffix, `K`, `KiB` | 1,024 bytes per second |
| `M`, `MiB`; `G`, `GiB`; `T`, `TiB`; `P`, `PiB` | Successive powers of 1,024 bytes per second |
| `KB`, `MB`, `GB`, `TB`, `PB` | Successive powers of 1,000 bytes per second |
| `B` | Bytes per second |

For example, `1024` and `1M` both select 1 MiB/s. Rates are rounded to the
nearest KiB/s, and zero turns the limit off.

## Concurrency ceilings

```sh
syq cp data --to server --into backup --resource-limits workers=4,bandwidth=10M
```

Here syq adjusts the number of filesystem copy workers up to four, whereas
`--performance-tuning workers=4` fixes it at four. Workers don't include
directory scanning or control connections, and the ceiling doesn't cap total
threads, sockets, CPU, or memory. Syq uses fewer workers, and says so, when an
endpoint's open-file limit or other resources run short; raising that limit
can allow more.

Use `workers` for filesystem copies and the S3 keys for S3 copies. S3 ceilings
are nested: object and per-object part counts also share the request ceiling.
[Restricted receiver limits](remote-reference.md#limits-and-unsupported-options)
still apply.
