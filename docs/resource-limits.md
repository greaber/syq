# Resource limits

`--resource-limits` caps bandwidth in `syq cp` and `syq rsync`:

| Key | Default | Meaning |
|---|---|---|
| `bandwidth` | `0` (unlimited) | Aggregate logical file-data bytes per second across the copy's workers |

```sh
syq cp data --to server --into backup --resource-limits bandwidth=10M
```

This limits the average copy rate to 10 MiB/s. It counts bytes before compression,
encryption, and protocol overhead; it does not cap every network burst.

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

Supplying `--resource-limits` bypasses the remembered connection-count cache.
Live tuning still runs unless you also fix `workers`; see
[remembered connection counts](tuning.md#remembered-connection-counts).

In `syq rsync`, `--bwlimit RATE` selects the same rate limit. Do not combine it
with `--resource-limits bandwidth=RATE`.
