# Resource limits

`--resource-limits` sets ceilings while syq chooses how to run the copy.
`--performance-tuning` fixes individual settings instead. Both are available
in `syq cp` and `syq rsync`; S3 copies use `syq cp`.

Supply comma-separated `KEY=VALUE` pairs:

| Key | Default | Meaning |
|---|---|---|
| `bandwidth` | `0` (unlimited) | Aggregate logical file-data bytes per second across the copy's workers |
| `workers` | Automatic | Ceiling of 1–65536 filesystem copy-worker slots |
| `s3-max-concurrent-requests` | Automatic | Ceiling of 1–65536 simultaneous S3 data requests across objects; excludes metadata requests and idle sockets |
| `s3-max-concurrent-objects` | Automatic | Ceiling of 1–65536 S3 objects in progress, including preparation and finalization |
| `s3-max-concurrent-parts-per-object` | Automatic | Ceiling of 1–1024 simultaneous parts or ranges per S3 object |

```sh
syq cp data --to server --into backup --resource-limits bandwidth=10M
```

This limits the average copy rate to 10 MiB/s. It counts bytes before compression,
encryption, and protocol overhead; it does not cap every network burst.

## Concurrency ceilings

```sh
syq cp data --to server --into backup --resource-limits workers=4,bandwidth=10M
```

Syq can adjust the filesystem copy-worker count up to four. By contrast,
`--performance-tuning workers=4` fixes four worker slots. Unused slots can
remain idle in either case. Worker counts do not include directory scanning,
metadata processing, or control connections, and do not cap total threads,
sockets, CPU use, or memory.

Each concurrency key conflicts with the same key in `--performance-tuning`,
even when the values match. Controls for different quantities can combine:
for example, a fixed request size with a worker ceiling. Unknown keys,
duplicate keys, zero counts, and out-of-range values are rejected.

A ceiling only constrains automatic choices; it does not raise their normal
upper bounds or force syq to use that many slots. Filesystem copies currently
auto-tune up to 64 workers. S3 choices depend on the route and workload. The
S3 ceilings are nested: object and per-object part counts also share the
aggregate request ceiling. A fixed setting for one count still operates within
ceilings on the other counts.

Use `workers` only for filesystem copies and the S3 keys only for S3 copies.
Limits apply to the remote coordinator too and are not saved.

## Bandwidth units

Rates accept decimals and case-insensitive suffixes:

| Spelling | Unit |
|---|---|
| No suffix, `K`, `KiB` | 1,024 bytes per second |
| `M`, `MiB`; `G`, `GiB`; `T`, `TiB`; `P`, `PiB` | Successive powers of 1,024 bytes per second |
| `KB`, `MB`, `GB`, `TB`, `PB` | Successive powers of 1,000 bytes per second |
| `B` | Bytes per second |

A final `+1` or `-1` adjusts the scaled value by one byte before rounding.
Rates are rounded to the nearest KiB/s. Zero disables the cap; nonzero values
below 512 bytes/s are rejected. For example, `1024` and `1M` both select 1 MiB/s.

## Where the limit applies

For filesystem copies, workers share one aggregate limit. Buffering, streaming,
and SSH/TCP overhead can produce bursts.
[`bw-pacing`](tuning.md#average-rate-and-burst-patterns) controls pacing.
A capped copy uses normal copying instead of local filesystem cloning.

For local/S3 copies, the limit applies to scheduled data, with upload bursts
up to a part. Server-side S3 copies do not pass object bodies through this
machine and are not paced by this setting.

With a worker ceiling, syq uses the remembered connection count up to that
ceiling and leaves the cache unchanged. A bandwidth limit alone still reads
and updates it. Live tuning runs unless you fix `workers` through
`--performance-tuning`; see
[remembered connection counts](tuning.md#remembered-connection-counts).

In `syq rsync`, `--bwlimit RATE` selects the same rate limit. Do not combine it
with `--resource-limits bandwidth=RATE`.
