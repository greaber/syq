# Mac streaming comparison at 34cadda

2026-09-06. The requested implementation is
`34cadda23adfddaba587acb45e859d121f5556dd`, identified by the
[Mac handoff at ee17a93](https://github.com/greaber/syq/blob/ee17a938f81ae076e880c961c3a122535a31711b/experiments/streaming.md#macos-handoff).
Native release-profile builds on the Mac and Linux endpoint both report
`v0.4.0+dev.34cadda23adf`. All comparisons below use that same binary, with
**persistence off and all connection startup timed**.

The [separate tiny-copy persistence-on probe](ssh-persistent-data-probe.md)
answers a different question. Its saving is not included in these results.

## Main comparison

Streaming did not show a reliable speedup on this Mac-to-Linux SSH route.
The ordinary pipeline and streaming take similar time for the generated large
file. Rsync's mean push time is lower for both workloads, even after retaining
its unusually slow second large-file run.

Mean whole-command seconds over three rotated repeats, with a fresh empty
destination every time:

| Push mode | Workers | 16 MiB file | 1,024 × 8 KiB |
| --- | ---: | ---: | ---: |
| Ordinary, pipeline 4 | 1 | 15.291 | 12.194 |
| Streaming | 1 | incomplete: 1 cap | 12.022 |
| Ordinary, pipeline 16 | 1 | 17.890 | 11.765 |
| Ordinary, pipeline 4 | 8 | 15.155 | 11.504 |
| Streaming | 8 | 15.562 | 10.200 |
| Ordinary, pipeline 16 | 8 | 16.218 | 12.943 |
| Rsync | — | 13.302 | 7.725 |

The one-worker streaming large-file times are 15.803 s, a timeout at 25.099 s,
and 14.777 s. Reporting only the two successful times would hide the timeout.
All other main push trials completed and verified. Rsync's large-file trials
are 10.078, 19.842, and 9.985 seconds; the slow middle sample remains included.
Streaming's eight-worker push throughput, including setup, is 1.028 MiB/s for
the large file and 0.784 MiB/s for the small tree. Rsync reaches 1.203 and
1.036 MiB/s respectively on that same whole-command measure.

| Pull mode | Workers | 16 MiB file | 1,024 × 8 KiB |
| --- | ---: | ---: | ---: |
| Ordinary, pipeline 4 | 8 | 12.094 | 8.726 |
| Streaming | 8 | 12.211 | 9.469 |
| Ordinary, pipeline 16 | 8 | 12.028 | 8.747 |

All 18 pull copies verified. These pulls compare syq modes; rsync was measured
only for the user's original push scenario.

## What the traces establish

In the main matrix, completed remote large-file streaming copies each report
one streaming range. The ordinary path reports four range requests. No completed small-file
copy uses streaming: both modes retain the batch path. The lower small-file
push mean in streaming mode therefore does not establish a gain from the
streaming transfer algorithm; the pull result also reverses that ordering.

A representative ordinary push finishes control setup at 3.73 s, planning at
5.10 s, and data-worker setup at about 8.43 s. The worker then reports 5.19 s
blocked sending to SSH and essentially no time awaiting write acknowledgments.
This supports investigating setup and SSH send throughput before increasing
pipeline depth. It does not identify encryption, network loss, or a particular
remote disk as the cause of waiting.

At a 4 MiB request size, the 16 MiB file fits in four requests. Pipeline depth
16 has little opportunity to help this fixture. These results do not rule out
a deeper pipeline helping larger transfers on another path.

The default split minimum is 32 MiB, and a range needs at least twice that
remaining size to split. Neither the 16 MiB main fixture nor the 32 MiB initial
screening fixture can exercise range stealing with that default. Starting
eight workers does not make eight workers carry this file. The follow-up below
uses equal explicit splitting settings to exercise the new early-shrink path.

## Smaller split threshold

The follow-up uses a 32 MiB file, eight workers, and
`split-min-size=8M` for both ordinary pipeline 4 and streaming. Request size
remains 4 MiB. Three push rounds rotate ordinary/streaming/rsync order; three
pull rounds alternate the two syq modes.

| Push mode | Completed / attempted | Trial seconds, in round order |
| --- | ---: | --- |
| Ordinary, pipeline 4 | 2 / 3 | 24.954, 22.381, cap at 25.067 |
| Streaming | 1 / 3 | cap at 25.040, cap at 25.047, 19.502 |
| Rsync | 2 / 3 | 15.304, 16.301, cap at 25.053 |

The 19.502-second streaming success cannot establish a win while two of its
three attempts time out. Ordinary mode and rsync also have capped attempts.
This setting did not produce a reliable push improvement. Every completed
copy verified, including the one streaming success, which used two ranges.
No early-shrink notification was reported in that successful push. The
capped copies have no final tuning counters; they are unknown, not zeros.

| Pull mode | Completed / attempted | Mean seconds | Whole-command MiB/s |
| --- | ---: | ---: | ---: |
| Ordinary, pipeline 4 | 3 / 3 | 13.904 | 2.302 |
| Streaming | 3 / 3 | 13.825 | 2.315 |

All three streaming pulls report three streaming ranges, eight streamed
blocks, one shrink notification, and zero discarded payload bytes. This
confirms that the new notification mechanism ran successfully from the remote
Linux source to the Mac. The mean elapsed difference is only 0.079 seconds
(0.6%), with overlapping trial times; it does not establish a useful speedup.
The paired ordinary times are 13.292, 14.813, and 13.606 seconds, versus
13.997, 13.992, and 13.485 for streaming. An older streaming binary was not
measured here, so zero discarded bytes cannot be credited quantitatively to
this commit versus its parent.

The smaller split minimum also does not guarantee that all eight workers do
useful work. In the first ordinary push, two connected around 3.68 seconds
after launch, while the other six took 6.12–6.64 seconds. Only two reported
nonzero data-send waiting; the rest spent the transfer idle. This remains a
concrete reason to investigate worker startup and scheduling on this route.

Across the initial screen, main matrix, local checks, and split follow-up,
there are 120 recorded attempts: 113 verified copies and seven caps. All
attempts are preserved in the CSV. Neither a default tuning change nor a
syq-over-rsync performance claim is supported by these measurements.

## Procedure and limits

The Mac has an Apple M4 Pro and macOS 26.5.2, with OpenSSH 10.2p1 and rsync
3.4.1. The Linux endpoint uses rsync 3.2.7. Neither installed syq binary was
replaced. The Linux development build uses the repository-pinned Rust 1.94.1
Docker image. Both native build identities are checked before copying.

The three main tuning values are:

```text
copy-path=auto,request-size=4M,pipeline-depth=4
copy-path=auto-streaming,request-size=4M
copy-path=auto,request-size=4M,pipeline-depth=16
```

Syq uses `--no-tcp --no-compress`, fixed `-j 1` or `-j 8`,
`--preserve=permissions`, `-v --stats`, and `SYQ_DEBUG=1`. Push commands use
`--srcs-in SOURCE --to HOST --into-existing DEST`; pull commands use
`--srcs-in SOURCE --from HOST --into-existing DEST`. The exact matching Linux
helper is selected with `--syq-path`. Rsync uses `-rpt` without compression.

Private configuration and runtime directories isolate `persist off` from the
user's normal settings and sessions; the resulting disabled policy is checked
as JSON. There is no `--pscope`. Rsync explicitly disables SSH multiplexing.
Syq may reuse SSH channels within one copy. Both tools use the same temporary
SSH keepalive override, interval 15 seconds and count 3. An owned administrative
SSH socket handles only untimed setup, checksums, and cleanup. It never carries
timed payload. No global SSH or network configuration changes are made. The route uses the
same interface and gateway at the start and end of each measurement run.

A monotonic timer encloses the full copy command. Generated dense random
sources are identical across modes within each run. Preparation, destination
creation, helper identity checks, and full SHA-256 verification are outside the
timer. Every completed destination is checked for exactly the expected files
and hashes. No global cache purge or final disk flush is performed; filesystem
caches are warm. These measure copying to the filesystem, not durability after
a power loss. Builds and test suites do not run concurrently with timed copies.

A task-private helper wrapper places each Linux helper in its own process
group and records its PID, enabling bounded cancellation of every owned remote
worker. The same wrapper is used for all syq modes; its startup cost is included.
It adds a Python process startup, so these numbers are not an exact reproduction
of the standalone script's helper launch. Syq's observed advantage or deficit
is not adjusted to subtract that overhead.

Each copy has a 25-second cap. On a cap the harness terminates the entire local
process group, checks for survivors, and terminates/checks any recorded remote
helper groups. Capped destinations are not counted as verified copies. Cleanup
never targets other sessions or real user data.

The initial 32 MiB screen had two capped eight-worker pushes, streaming and
pipeline 16. Its other seven recorded remote copies verified. The run was
stopped between copies during the next destination's untimed setup, and its
scratch and workers were removed. The large fixture was then reduced to
16 MiB and the main three-repeat matrix restarted. All initial records remain
in the [trial CSV](mac-streaming-34cadda-results.csv); they are not pooled with
the main results. The main matrix contains 59 verified copies and one cap.

Before remote timing, 36 local copies passed SHA-256 verification. The 32 MiB
local file completes in 0.058–0.097 s and the small tree in 0.125–0.274 s.
These local large-file copies report eight range requests in ordinary mode
and one streaming range in hybrid mode, with zero whole-file shortcut calls.
No global cache flush was used, and no cloning benefit is assumed. The short
local times do not establish a streaming gain for the WAN route.

The pinned streaming revision predates master's newer copying-interval field.
These diagnostics use its phase timestamps and tuning counters; they do not
invent or backport `copying_elapsed_ms`. This comparison isolates the streaming
mode within 34cadda, not the incremental difference between that commit and
its parent, nor a release-to-release performance change.

## Verification

At clean `34cadda`, native release builds pass on Mac and Linux. On the Mac,
`cargo fmt --all -- --check`, clippy for all targets/features with warnings as
errors, and `cargo test --bin syq` pass: 472 unit tests and one pre-existing
ignored test. All five focused `cargo test --test local streaming` tests pass,
covering errors, reconnection, resume, hybrid shortcuts, and local/remote range
copies. The release build retains the pre-existing `unused_mut` warning in
`session_pool.rs`; clippy passes.

The full three-container real-SSH suite was not repeated for this measurement
of existing code. The real Mac/Linux copies above exercise the matching build
over SSH in both directions. No runtime code or defaults are changed by this
report. The earlier benchmark-fix branch's Rust and real-SSH validation remains
documented in the [primary investigation](ssh-push-benchmark-cold.md).

All generated remote destinations, source trees, private scopes, helper
wrappers, build sources, and the build container were removed. The matching
Linux helper is retained in its versioned cache for a future explicit test.
Local raw logs and host-specific harness settings remain ignored artifacts;
the committed CSV contains portable timings and counters.
