# Resource limits

`--resource-limits` sets ceilings while syq chooses how to run the copy.
`--performance-tuning` fixes individual settings instead. Both are available
in `syq cp` and `syq rsync`; S3 copies use `syq cp`.

Supply comma-separated `KEY=VALUE` pairs:

| Key | Default | Meaning |
|---|---|---|
| `bandwidth` | `0` (unlimited) | Aggregate byte rate across the copy's workers; accounting depends on the transport |
| `workers` | Automatic | Ceiling of 1–65536 filesystem copy-worker slots |
| `s3-requests` | Automatic | Ceiling of 1–65536 simultaneous S3 data requests across objects; excludes metadata requests and idle sockets |
| `s3-objects` | Automatic | Ceiling of 1–65536 S3 objects in progress, including preparation and finalization |
| `s3-parts-per-object` | Automatic | Ceiling of 1–1024 simultaneous parts or ranges per S3 object |

```sh
syq cp data --to server --into backup --resource-limits bandwidth=10M
```

For ordinary SSH and TCP copies, this limits outgoing bytes to 10 MiB/s
across all workers, including when workers use both transports. It counts
compressed bytes and syq framing. TCP also counts its encryption records;
SSH counts bytes passed to OpenSSH, excluding OpenSSH encryption overhead.
Connection setup, separate control traffic, and IP/TCP headers are excluded.
The small-copy shortcut also paces file data sent on its control connection.
Compressible files can therefore copy at a higher logical rate. Small bursts
remain possible because the operating system buffers network writes.

Remote-to-remote relays apply the rate to each network leg separately: a
10 MiB/s cap permits up to 10 MiB/s inbound and 10 MiB/s outbound at the relay. Local,
S3, named receiving, descriptor, and signed-receiver copies count logical
file-data bytes before compression.

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

A ceiling does not force syq to use that many slots. Filesystem copies have no
fixed default tuning ceiling; syq adjusts the count from measured throughput.
Automatic filesystem copies also limit workers using the endpoints' available
open-file budgets and reduce concurrency when worker setup exhausts local
resources. Syq reports these reductions; raising an endpoint's operating-system
limit can allow more concurrency. Fixed worker settings still report failures
when their requested resources are unavailable.

Metadata processing falls back to sequential work if its thread pool cannot
start. Small-file staging reduces its open-file burst after an open failure
that may indicate descriptor exhaustion, then retries once after existing
bursts finish. Persistent failures remain errors. These measures do not reserve
memory or disk space, or guarantee success under every resource limit.

[Restricted receiver limits](remote-reference.md#limits-and-unsupported-options)
still apply. S3 ceilings constrain the route's normal automatic range without
raising it. They are nested: object and per-object part counts also share the
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

A worker ceiling also limits the starting connection count and leaves the
[remembered count](tuning.md#remembered-connection-counts) unchanged.
A bandwidth limit alone still allows syq to update it.

In `syq rsync`, `--bwlimit RATE` selects the same rate limit. Do not combine it
with `--resource-limits bandwidth=RATE`.
