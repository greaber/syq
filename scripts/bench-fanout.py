#!/usr/bin/env python3
"""Measure coordinator scaling with real helper protocols and local fake SSH.

Linux only (RSS from /proc). No external hosts or third-party Python packages.
Build first with cargo build --release --locked. Run from a task worktree:
  python3 scripts/bench-fanout.py --files 50000 --targets 2 4 8 --repetitions 3

Each sample copies a fresh tree. Independent copies have the same aggregate
worker budget. RSS is sampled for client processes only, excluding helpers;
first mutation is the first destination root creation (20 ms resolution).
Helper sessions counts remote-shell invocations, including control sessions.
This isolates local coordination cost; it does not measure SSH/network latency.
"""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def rss(pid):
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except FileNotFoundError:
        pass
    return 0


def sample(binary, source, hosts, root, mode, workers, deadline_seconds):
    homes = root / "homes"
    homes.mkdir()
    for host in hosts:
        (homes / host).mkdir()
    shell = root / "rsh"
    shell.write_text('''#!/bin/sh
host=$1
shift
HOME="$BENCH_REMOTE_ROOT/$host"
export HOME
cd "$HOME" || exit 97
printf '%s\\n' "$host" >> "$BENCH_SESSION_LOG"
exec /bin/sh -c "$1"
''')
    shell.chmod(0o755)
    session_log = root / "sessions"
    env = os.environ.copy()
    env.update(SYQ_INTERNAL_NATIVE_RSH=str(shell), BENCH_REMOTE_ROOT=str(homes),
               BENCH_SESSION_LOG=str(session_log))
    common = [str(binary), "cp", "--syq-path", str(binary), "--no-tcp", "-q",
              "--srcs-in", str(source)]
    commands = ([common + ["--tos", *hosts, "--into", "dst", "-j", str(workers * len(hosts))]]
                if mode == "coordinated" else
                [common + ["--to", host, "--into", "dst", "-j", str(workers)] for host in hosts])
    if workers == 0:
        commands = [command[:-2] for command in commands]
    children = []
    first_mutation = None
    peak_rss = 0
    started = time.monotonic()
    report = started + 10
    log = root / "output"
    with log.open("wb") as output:
        try:
            children = [subprocess.Popen(command, env=env, stdout=output, stderr=output)
                        for command in commands]
            while any(child.poll() is None for child in children):
                now = time.monotonic()
                if now - started > deadline_seconds:
                    raise TimeoutError(f"{mode}: deadline exceeded; log: {log.read_text()}")
                peak_rss = max(peak_rss, sum(rss(child.pid) for child in children))
                if first_mutation is None and any((homes / host / "dst").exists() for host in hosts):
                    first_mutation = now - started
                if now >= report:
                    print(f"{mode}/{len(hosts)}: {now - started:.1f}s, RSS {peak_rss / 1024:.1f} MiB",
                          file=sys.stderr, flush=True)
                    report += 10
                time.sleep(0.02)
            elapsed = time.monotonic() - started
            assert all(child.returncode == 0 for child in children), log.read_text()
        finally:
            for child in children:
                if child.poll() is None:
                    child.send_signal(signal.SIGTERM)
            for child in children:
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
    # Verify every output, outside the timed section.
    expected = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    for host in hosts:
        destination = homes / host / "dst"
        actual = {p.relative_to(destination): p.read_bytes() for p in destination.rglob("*") if p.is_file()}
        assert actual == expected, host
    return dict(mode=mode, targets=len(hosts), files=len(expected), workers=workers * len(hosts) if workers else "auto",
                elapsed_s=round(elapsed, 3), first_mutation_s=round(first_mutation or elapsed, 3),
                client_peak_rss_mib=round(peak_rss / 1024, 2),
                helper_sessions=len(session_log.read_text().splitlines()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/syq"))
    parser.add_argument("--files", type=int, default=10000)
    parser.add_argument("--targets", type=int, nargs="+", default=[2, 4, 8])
    parser.add_argument("--workers-per-target", type=int, default=2,
                        help="fixed workers per target; 0 exercises default tuning")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--deadline", type=int, default=180)
    args = parser.parse_args()
    if not Path("/proc/self/status").exists():
        parser.error("this benchmark needs Linux /proc for client RSS")
    binary = args.binary.resolve(strict=True)
    identity = subprocess.check_output([str(binary), "--build-identity"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="syq-fanout-bench-") as directory:
        base = Path(directory)
        source = base / "source"
        source.mkdir()
        for i in range(args.files):
            parent = source / f"d{i // 100:05d}"
            parent.mkdir(exist_ok=True)
            (parent / f"f{i:06d}").write_bytes(f"file {i}\n".encode().ljust(1024, b"x"))
        for count in args.targets:
            hosts = [f"target{i}" for i in range(count)]
            for repetition in range(args.repetitions):
                # Alternate ordering to expose warm-cache and ordering effects.
                modes = ["coordinated", "independent"]
                if repetition % 2:
                    modes.reverse()
                for mode in modes:
                    with tempfile.TemporaryDirectory(dir=base) as run:
                        result = sample(binary, source, hosts, Path(run), mode,
                                        args.workers_per_target, args.deadline)
                        result.update(identity=identity, repetition=repetition + 1)
                        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
