# Mac to j5 comparison with persistence off

2026-09-06. This is the primary comparison for the SSH startup investigation.
The earlier persist-mode comparisons are [historical results](ssh-push-benchmark.md),
with a different startup policy. They do not establish a cold-connection speedup.

## Result and decision

The proposed runtime changes did not demonstrate an improvement with persistence
off. Rsync was faster than both syq builds in every trial of both workloads.
All 18 copies passed full SHA-256 content verification; there were no failures.

| Workload / build | Mean seconds | Min | Max | Trials |
| --- | ---: | ---: | ---: | ---: |
| 64 MiB file, released syq `f4aee996` | 30.461 | 28.577 | 34.083 | 3 |
| 64 MiB file, proposed syq `1f6a12c` | 42.612 | 29.436 | 53.720 | 3 |
| 64 MiB file, rsync 3.4.1 | 24.448 | 23.802 | 25.591 | 3 |
| 1,024 × 8 KiB, released syq `f4aee996` | 10.287 | 9.549 | 11.733 | 3 |
| 1,024 × 8 KiB, proposed syq `1f6a12c` | 13.373 | 9.510 | 19.529 | 3 |
| 1,024 × 8 KiB, rsync 3.4.1 | 7.790 | 7.185 | 8.788 | 3 |

The proposed build took longer than the release in two of three rounds for
both workloads. The large-file timings varied considerably, and the proposed
edits target small-file startup; these samples do not isolate the cause of the
large-file difference. Every sample, including the slow ones, remains in the
[trial CSV](ssh-push-benchmark-cold-results.csv).

Commit `4a9372e` withdraws the one-worker startup and persistent data-channel
reuse changes. The branch's Rust source and Rust/real-SSH tests then match
`master` at `5fbb158`. The remaining change makes the standalone benchmark
explicitly disable persistence. No syq-over-rsync performance improvement is
claimed from this investigation.

## Controlled procedure

The Mac is the same Apple M4 Pro sender, with OpenSSH 10.2p1 and rsync 3.4.1;
j5 uses rsync 3.2.7. The before build is the installed syq v0.4.0 at `f4aee996`.
The proposed Mac and Linux helpers identify as `v0.4.0+dev.1f6a12cdb7c1`.
This tests the narrowed proposal, with the original 32 MiB range split minimum,
not the earlier 8 MiB prototype. Both are release-profile builds.

Both syq builds run `persist off` in the same private configuration and runtime
directories before testing. The generated policy is checked as JSON and no
global persistence scope exists in that runtime. No `--pscope` is passed.
The user's normal setting and existing connections are untouched. Rsync gets
`ControlMaster=no`, `ControlPath=none`, and `ControlPersist=no`, so it cannot
reuse an existing SSH master. Both tools therefore establish their connections
inside each measured copy. Syq may share channels within that one copy.

Both syq builds use `--no-tcp` to hold the payload on the SSH transport seen in
the original report. Both tools get the same temporary SSH keepalive override:
15-second interval, count 3. No SSH or network configuration is changed globally.
The SSH route was `en0` through `10.0.0.1` at both the start and the end of the
run. This is a fixed-transport comparison; the standalone script still uses
syq's normal automatic transport selection.

The dense random 64 MiB file and 1,024 random 8 KiB files are identical for all
copies. Each destination is a new empty directory. Source generation, helper
preflight, destination creation, and SHA-256 verification are untimed. Each
helper preflight connection closes before the scored copies; the preflight
does not provide a warm connection to the timed copy. Binary installation and
filesystem caches are not cold. A separate SSH connection handles untimed
administration and is never used by either timed tool.

The scored commands are:

```sh
syq cp --preserve=permissions --syq-path MATCHING_HELPER \
  --srcs-in SOURCE --to j5 --into-existing DEST --stats --no-tcp
rsync -rpt -- SOURCE/ j5:DEST/
```

The syq binary and matching helper are the only build-specific arguments.
`SYQ_DEBUG=1` captures the same phase diagnostics for both syq builds. The
harness measures the complete command with a monotonic clock, verifies every
completed destination, records errors, and bounds each copy to 180 seconds.
Order rotates over three rounds: release/candidate/rsync, candidate/rsync/release,
then rsync/release/candidate. The tools never run timed copies concurrently.
Compilation and large downloads start only after the comparison finishes.

## Where time goes

The phase traces already show why the proposed small-file change did not remove
cold setup cost. Released syq establishes its control connection in 3.40–3.54
seconds for the small workload, and finishes planning at 4.64–4.79 seconds.
Its eight data workers then open shared SSH channels in about 0.64 seconds each,
in parallel. They already reuse the login created for that copy when persistence
is off. Starting one worker does not eliminate eight independent authentications
in this mode, because those authentications were not happening.

The proposed build's one active worker connects in 0.62–0.66 seconds, nearly the
same delay. In its slow small-file trial, the worker spends 10.35 seconds writing
data to SSH and 2.61 seconds awaiting replies. That delay is inside the transfer,
not an initial login delay. The precise cause of this stall is not established.

For the large file, planning finishes at 4.38–4.90 seconds, then the data workers
need about 3.2–6.6 seconds to connect. Usually only one or two workers carry file
data; the others spend most of their time idle. Extra data-login work and time
blocked writing to SSH remain concrete investigation targets. Neither this
experiment nor the earlier pipeline/streaming experiments establish a safe
change to the defaults that makes syq consistently faster than rsync here.

## Copying-interval diagnostic after the comparison

After the scored comparison, a matching Mac/Linux build at `4a9372e` ran the
corrected mini script against j5 with `--size quick --rounds 1 --workload both`.
A temporary wrapper adds `--no-tcp`, `--stats`, and `--results` to syq and applies
the same SSH keepalive settings used above. Persistence remains off. Every copy,
including rsync, passes POSIX cksum verification. This smoke test uses normal
helper discovery and the normal tuning cache (six workers), separate from the
primary comparison's isolated tuning cache (eight workers).

The new timing fields give these [diagnostic records](ssh-push-benchmark-timing.csv):

| Workload | syq elapsed | Copying interval | Outside that interval |
| --- | ---: | ---: | ---: |
| large | 30.245 s | 21.970 s | 8.275 s |
| small | 9.261 s | 3.346 s | 5.915 s |

These values use syq's `elapsed_ms`, not the shell's complete process timer.
The copying interval spans first to last file work, including per-file checks,
finalization and gaps. Planning and connections may overlap it. The difference
is time outside that interval, including setup and completion; it is not a
measurement of SSH authentication alone. The small workload spends most of
its elapsed time outside file work, making cold setup a useful next target.
The large workload also spends substantial time outside file work, while its
copying interval remains much longer. These single-trial diagnostics explain
where to look; they do not establish an optimization or replace total elapsed
time as the comparison metric.

## Standalone benchmark correction

The standalone script runs `syq persist off` with private `XDG_CONFIG_HOME` and
`XDG_RUNTIME_DIR`. Isolating both matters: isolating only configuration would
still let `persist off` close the user's usual runtime scope. Helper caches
remain available for untimed installation/preparation. Disabling persistence
must succeed before any copies start. Preparation, automatic sizing, and all
scored copies use the same persistence-off environment.

Rsync and administrative SSH commands explicitly disable connection reuse.
The transcript and result table both identify syq persistence as OFF and say
that connection startup is timed. There is no persist-on benchmark option in
this correction. The previous local convenience wrapper now also runs with
persistence off.

The correction is integrated with `5fbb158`, including automatic sizing and the
new copying-interval report. Older v0.4.0 binaries can still use the fixed-size
`--size quick` comparison. Regression tests exercise inherited persist-on
settings in push and pull modes, preserve the user's configuration/runtime,
check cleanup of private settings, and stop before copying if persistence
cannot be disabled.

## Verification

At `4a9372e`, formatting, clippy with all targets/features and warnings as errors,
and all Rust targets pass: 466 unit tests, one pre-existing ignored probe,
401 local integration tests, and 16 other integration tests. The default
three-container real-SSH suite passes, including fixed-size push/pull,
automatic-size push/pull, and cancellation cleanup. The 21 standalone script
tests pass. Documentation and investigation links, shell syntax, and all CSV
summary calculations are checked. Rust code and Rust/real-SSH tests match
`master` at `5fbb158`; the proposal introduces no runtime or wire changes.

The unchanged installed v0.4.0 binary also runs the corrected fixed-size script
locally with small test fixtures, verifies every copy, and leaves the user's
persistence policy unchanged. The real Mac-to-j5 smoke test above passes with
normal cached helper discovery. An initial diagnostic wrapper failed on an
empty Bash 3.2 array before copying; cleanup completed and the fixed wrapper's
rerun passed. Neither attempt changes the 18-trial primary comparison.

Mac and Linux release-profile builds match `v0.4.0+dev.4a9372e4e11e`. They retain
the pre-existing `unused_mut` release-profile warning in `session_pool.rs`.
The temporary remote build and benchmark scratch are removed; versioned helper
caches remain. No PR workflows were dispatched and no merge was performed.
