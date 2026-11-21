---
name: syq-benchmark
description: How to measure syq performance and support a performance claim - benchmark duration, which resources to record, exact peak-memory measurement, and what to check when new code replaces an existing path. Use when benchmarking, comparing performance, writing a performance claim, or replacing or bypassing an existing copy or I/O path.
---

# Performance evidence

Choose benchmark duration to suit the behavior being measured; there is no
fixed minimum. Short tests can measure startup or small operations, but do not
infer sustained performance from subsecond runs unless there is evidence that
they reach a representative steady state quickly. Consider startup, autotuning
and variability, and lengthen or repeat the test as needed to support the claim.

Record resource use with every benchmark, not only elapsed time. At minimum,
report CPU time (user and system) and peak memory for each process, the
coordinator and every helper, and compare both with the baseline. Also record
the other resources the change could affect, such as bytes sent or written,
threads and open files, filesystem or network requests, and disk space. A
change can be faster while using several times the memory or CPU, and timing
alone hides that.

Measure peak memory exactly. `ru_maxrss` (what `wait4` and `/usr/bin/time`
report) reads the kernel's per-CPU RSS counters without their pending deltas.
Each CPU can hold back up to twice the CPU count in pages, so on a 96-CPU
Linux host a reading can be about 768 KiB low for each CPU the process ran on,
and few-run medians jump between values that far apart with no real change.
Read `VmHWM` and `VmRSS` from `/proc/PID/status`, or `/proc/PID/smaps_rollup`,
before the process exits, or compare enough samples to see the clusters.

When new code replaces or bypasses an existing path, first list what the
existing path does for performance and resource use: preallocation, cloning
or in-kernel copies, read-ahead and access hints, request sizes, memory bounds
and batching. Either carry each one over, or measure the cases it was meant to
help and show that the new path does not regress them. Measure on the kinds of
system those choices target, such as filesystems with and without cloning
(XFS or btrfs against ext4), network filesystems, and slow and fast links. A
choice that only matters elsewhere is invisible on the development machine's
own filesystem.
