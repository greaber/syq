#!/usr/bin/env python3
"""Compare local rm, copy and pruning across binaries, workers and CPU allowances.

  python3 scripts/benchmark-concurrency.py --example > target/concurrency-plan.json
  # Edit scratch roots, binary paths, cases and variants in that plan.
  python3 scripts/benchmark-concurrency.py --plan target/concurrency-plan.json \
      --output target/concurrency-results --rounds 4

Manual only; no global cache drops or machine configuration changes. Each trial
gets a fresh, fully written and fsynced fixture, with warm caches. Setup and exact
result verification are outside the timer. Larger files contain random bytes,
not holes. Increase case sizes to observe sustained tuning; short runs also
matter but cannot establish steady-state behavior. Run without other benchmarks.

The reference is another measured variant, normally the old automatic tuner.
Fixed counts are controls, not substitutes for testing the automatic candidate.
Results retain paired rounds, individual cases and worst slowdowns; there is no
aggregate pass threshold. Reversing variant order balances linear order effects,
but does not remove workload drift or prove safety on unmeasured systems.

Requires Linux (GNU /usr/bin/time) or macOS (/usr/bin/time). CPU affinity is
Linux-only and applies to the WHOLE process, independently of worker count;
it does not reproduce worker-only pinning. CPU/RSS are the local product's
wait4 accounting from native time, avoiding the Python fixture builder's RSS.
Wall time includes that small native launcher; CPU time has 10 ms precision.
Linux thread/FD/I/O samples are
lower bounds at 20 ms intervals; macOS reports these as unavailable. No remote
helpers are launched. Logs and raw host/mount metadata stay in --output.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time

from tooling import sha256_file

INTERRUPTED = None


def example():
    cases = [
        ("rm-flat", "rm", 262144, 1, [0]),
        ("rm-spread", "rm", 1048576, 64, [0]),
        ("rm-allocated", "rm", 1024, 64, [1048576]),
        ("rm-mixed", "rm", 16384, 64, [0, 4096, 1048576]),
        ("cp-small", "cp", 262144, 64, [4096]),
        ("cp-large", "cp", 1024, 64, [1048576]),
        ("prune-spread", "prune", 262144, 64, [0]),
    ]
    return {"reference": "baseline-auto", "cases": [
        dict(name=name, operation=op, root="/path/to/scratch", files=count,
             directories=dirs, sizes=sizes) for name, op, count, dirs, sizes in cases
    ], "variants": [
        dict(name=f"{binary}-{workers or 'auto'}", binary=f"/path/to/{binary}/syq",
             workers=workers, cpus=None)
        for binary in ("baseline", "candidate") for workers in (None, 8, 32)
    ]}


def positive(value):
    return type(value) is int and value > 0


def validate(plan):
    if set(plan) != {"reference", "cases", "variants"}:
        raise ValueError("plan needs reference, cases and variants only")
    for field in ("cases", "variants"):
        if not plan[field] or not isinstance(plan[field], list):
            raise ValueError(f"{field} must be a nonempty list")
        names = [item["name"] for item in plan[field]]
        if len(set(names)) != len(names) or any(not re.fullmatch(r"[a-zA-Z0-9_-]+", n) for n in names):
            raise ValueError(f"{field} names must be unique letters, numbers, hyphens or underscores")
    if plan["reference"] not in [v["name"] for v in plan["variants"]]:
        raise ValueError("reference must name a variant")
    for case in plan["cases"]:
        if set(case) != {"name", "operation", "root", "files", "directories", "sizes"}:
            raise ValueError("case needs name, operation, root, files, directories and sizes only")
        if case["operation"] not in ("rm", "cp", "prune"):
            raise ValueError("operation must be rm, cp or prune")
        if not positive(case["files"]) or not positive(case["directories"]) or case["directories"] > case["files"]:
            raise ValueError("files and directories must be positive, with directories <= files")
        if not isinstance(case["sizes"], list) or not case["sizes"] or any(type(n) is not int or n < 0 for n in case["sizes"]):
            raise ValueError("sizes must be a nonempty list of nonnegative byte counts")
        case["root"] = str(Path(case["root"]).resolve(strict=True))
        if not Path(case["root"]).is_dir():
            raise ValueError("scratch root must be an existing directory")
    for variant in plan["variants"]:
        if set(variant) != {"name", "binary", "workers", "cpus"}:
            raise ValueError("variant needs name, binary, workers and cpus only")
        if variant["workers"] is not None and not positive(variant["workers"]):
            raise ValueError("workers must be null (automatic) or a positive integer")
        cpus = variant["cpus"]
        if cpus is not None:
            if not hasattr(os, "sched_getaffinity"):
                raise ValueError("CPU affinity requires Linux; use cpus: null on macOS")
            if not isinstance(cpus, list) or not cpus or any(type(n) is not int or n < 0 for n in cpus):
                raise ValueError("cpus must be null or a nonempty list of CPU IDs")
            if not set(cpus) <= os.sched_getaffinity(0):
                raise ValueError("requested CPUs are outside this process's allowed set")
        variant["binary"] = str(Path(variant["binary"]).resolve(strict=True))
        if not os.access(variant["binary"], os.X_OK):
            raise ValueError("binary must be executable")


class Deadline:
    def __init__(self, seconds, label, interruptible=True):
        self.end = time.monotonic() + seconds
        self.next_message = 0
        self.label = label
        self.interruptible = interruptible

    def check(self, state):
        if self.interruptible and INTERRUPTED is not None:
            raise KeyboardInterrupt(f"received signal {INTERRUPTED}; {self.label}: {state}")
        now = time.monotonic()
        if now >= self.end:
            raise TimeoutError(f"{self.label}: timed out; last state: {state}")
        if now >= self.next_message:
            print(f"{self.label}: {state}", flush=True)
            self.next_message = now + 10


def filename(case, index):
    return Path(f"d{index % case['directories']:04d}") / f"f{index:09d}"


def fixture(root, case, deadline):
    source, destination = root / "source", root / "destination"
    source.mkdir()
    destination.mkdir()
    tree = destination if case["operation"] == "prune" else source
    for index in range(case["directories"]):
        (tree / f"d{index:04d}").mkdir()
    rng = random.Random(0)
    hashes = {}
    allocated = logical = 0
    for index in range(case["files"]):
        if index % 256 == 0:
            deadline.check(f"creating file {index}/{case['files']}")
        path = tree / filename(case, index)
        size = case["sizes"][index % len(case["sizes"])]
        digest = hashlib.sha256()
        with path.open("wb") as stream:
            remaining = size
            while remaining:
                data = rng.randbytes(min(remaining, 1 << 20))
                stream.write(data)
                digest.update(data)
                remaining -= len(data)
                deadline.check(f"creating file {index}/{case['files']}")
            if size:
                stream.flush()
                os.fsync(stream.fileno())
        # Store hashes only when copying bytes; large empty rm trees should
        # not leave a million-entry Python manifest hot during measurement.
        if case["operation"] == "cp":
            hashes[str(filename(case, index))] = digest.hexdigest()
        allocated += path.stat().st_blocks * 512
        logical += size
    # Persist directory entries too, outside the timed operation. This does
    # not drop caches or turn the timed operation into a durability benchmark.
    for directory in [tree / f"d{i:04d}" for i in range(case["directories"])] + [source, destination, root]:
        deadline.check("syncing fixture directories")
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return hashes, dict(logical_bytes=logical, allocated_bytes=allocated)


def verify(root, case, hashes, deadline):
    source, destination = root / "source", root / "destination"
    if case["operation"] in ("rm", "prune"):
        tree = source if case["operation"] == "rm" else destination
        if not tree.is_dir() or next(tree.iterdir(), None) is not None:
            raise RuntimeError("removal left paths behind or removed the selection root")
        if case["operation"] == "prune" and (not source.is_dir() or next(source.iterdir(), None) is not None):
            raise RuntimeError("pruning changed the empty source")
        return
    expected_dirs = {f"d{i:04d}" for i in range(case["directories"])}
    # Both source preservation and destination contents are checked, including
    # unexpected directories/files and symlinks, without following any links.
    for tree in (source, destination):
        if tree.is_symlink() or not tree.is_dir():
            raise RuntimeError(f"expected directory: {tree}")
        seen = set()
        dirs = set()
        for current, directories, files in os.walk(tree):
            for name in directories:
                path = Path(current) / name
                if path.is_symlink():
                    raise RuntimeError(f"unexpected symlink: {path}")
                dirs.add(str(path.relative_to(tree)))
            for name in files:
                deadline.check(f"verifying {tree.name}, {len(seen)} files")
                path = Path(current) / name
                relative = str(path.relative_to(tree))
                if path.is_symlink() or not path.is_file() or relative not in hashes or sha256_file(path) != hashes[relative]:
                    raise RuntimeError(f"unexpected or changed file: {path}")
                seen.add(relative)
        if dirs != expected_dirs or seen != hashes.keys():
            raise RuntimeError(f"tree differs: {tree}")


GNU_FORMAT = json.dumps(dict(user_seconds="%U", system_seconds="%S", peak_rss_bytes="%M",
                            voluntary_switches="%w", involuntary_switches="%c",
                            input_blocks="%I", output_blocks="%O"))


def time_usage(log, system):
    if system == "Linux":
        row = json.loads(log.splitlines()[-1])
        row = {k: float(v) if k.endswith("seconds") else int(v) for k, v in row.items()}
        row["peak_rss_bytes"] *= 1024
        return row
    timings = re.search(r"^\s*[\d.]+ real\s+([\d.]+) user\s+([\d.]+) sys\s*$", log, re.M)
    if not timings:
        raise ValueError("missing macOS time CPU results")
    row = dict(user_seconds=float(timings[1]), system_seconds=float(timings[2]))
    for key, label in (("peak_rss_bytes", "maximum resident set size"),
                       ("voluntary_switches", "voluntary context switches"),
                       ("involuntary_switches", "involuntary context switches"),
                       ("input_blocks", "block input operations"), ("output_blocks", "block output operations")):
        match = re.search(r"^\s*(\d+)\s+" + label + r"\s*$", log, re.M)
        if not match:
            raise ValueError(f"missing macOS time field: {label}")
        row[key] = int(match[1])
    return row


def sample_linux(launcher):
    """Find time's direct child, the local syq process, not the Python parent."""
    samples = []
    try:
        children = Path(f"/proc/{launcher}/task/{launcher}/children").read_text().split()
        for pid in children:
            proc = Path("/proc") / pid
            status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines())
            io = dict(line.split(":", 1) for line in (proc / "io").read_text().splitlines())
            samples.append(dict(pid=int(pid), threads=int(status["Threads"]),
                                allowed_cpus=status["Cpus_allowed_list"].strip(),
                                fds=len(list((proc / "fd").iterdir())),
                                read_bytes=int(io["read_bytes"]), write_bytes=int(io["write_bytes"])))
    except (FileNotFoundError, ProcessLookupError):
        pass  # A short process can finish between reads; never report a zero peak.
    return samples


def group_alive(pgid):
    if platform.system() == "Linux":
        for proc in Path("/proc").glob("[0-9]*/stat"):
            try:
                fields = proc.read_text().rsplit(")", 1)[1].split()
                if int(fields[2]) == pgid and fields[0] != "Z":
                    return True
            except (FileNotFoundError, ProcessLookupError):
                pass
        return False
    # On macOS killpg(pgid, 0) can return EPERM for an exiting group after
    # orphan adoption. Inspect states, as on Linux, rather than treating a
    # zombie as a live worker or interpreting EPERM as proof of termination.
    states = subprocess.run(["/bin/ps", "-axo", "pgid=,stat="], capture_output=True,
                            text=True, check=True, timeout=5).stdout
    return any(int(group) == pgid and not state.startswith("Z")
               for group, state in (line.split() for line in states.splitlines()))


def cpu_constraints():
    """Keep available cgroup v2 limits/counters and topology as raw evidence."""
    paths = [Path("/proc/self/cgroup"), Path("/proc/cpuinfo")]
    root = Path("/sys/fs/cgroup")
    paths.extend(root / name for name in ("cpu.max", "cpu.stat", "cpuset.cpus.effective"))
    membership = paths[0]
    if membership.exists():
        for line in membership.read_text().splitlines():
            if line.startswith("0::"):
                current = (root / line[3:].lstrip("/")).resolve()
                while current != root and current.is_relative_to(root):
                    paths.extend(current / name for name in ("cpu.max", "cpu.stat", "cpuset.cpus.effective"))
                    current = current.parent
    return {str(path): path.read_text() for path in paths if path.is_file()}


def measure(command, env, cpus, stem, timeout):
    system = platform.system()
    usage_path = stem.with_suffix(".usage")
    timed = (["/usr/bin/time", "-f", GNU_FORMAT, "-o", str(usage_path)] if system == "Linux"
             else ["/usr/bin/time", "-l"]) + command
    ended = []
    samples = []
    with stem.with_suffix(".stdout").open("wb") as stdout, stem.with_suffix(".stderr").open("wb") as stderr:
        affinity = os.sched_getaffinity(0) if cpus is not None else None
        try:
            if cpus is not None:
                os.sched_setaffinity(0, cpus)
            started = time.monotonic()
            child = subprocess.Popen(timed, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        finally:
            if affinity is not None:
                os.sched_setaffinity(0, affinity)

        def wait():
            child.wait()
            ended.append(time.monotonic())

        waiter = threading.Thread(target=wait)
        waiter.start()
        deadline = Deadline(timeout, stem.name)
        try:
            while waiter.is_alive():
                deadline.check(f"running {time.monotonic() - started:.1f}s")
                if system == "Linux":
                    samples.extend(sample_linux(child.pid))
                waiter.join(0.02)
        finally:
            # Also catch descendants if a faulty executable leaves them behind
            # after time exits. Reap the launcher and verify the entire group.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            waiter.join(10)
            cleanup = Deadline(10, stem.name + " cleanup", interruptible=False)
            while group_alive(child.pid):
                cleanup.check("waiting for process group to exit")
                time.sleep(0.02)
        log = (usage_path if system == "Linux" else stem.with_suffix(".stderr")).read_text()
    resources = time_usage(log, system)
    resources["cpu_seconds"] = resources["user_seconds"] + resources["system_seconds"]
    peaks = {key: max((s[key] for s in samples), default=None)
             for key in ("threads", "fds", "read_bytes", "write_bytes")}
    return dict(seconds=ended[0] - started, exit_code=child.returncode, resources=resources,
                sampled=peaks, sample_count=len(samples), command=command,
                observed_cpu_sets=sorted({s["allowed_cpus"] for s in samples}),
                process_ids=sorted({s["pid"] for s in samples}), log_prefix=str(stem))


def comparisons(rows, reference):
    results = []
    for case in sorted({r["case"] for r in rows}):
        refs = {r["round"]: r for r in rows if r["case"] == case and r["variant"] == reference and r["verified"]}
        for variant in sorted({r["variant"] for r in rows if r["case"] == case} - {reference}):
            pairs = [(refs[r["round"]], r) for r in rows if r["case"] == case and r["variant"] == variant and r["verified"] and r["round"] in refs]
            if not pairs:
                continue
            result = dict(case=case, variant=variant, paired_rounds=len(pairs))
            for key in ("seconds", "cpu_seconds", "peak_rss_bytes"):
                values = [(a[key], b[key]) if key == "seconds" else (a["resources"][key], b["resources"][key]) for a, b in pairs]
                ratios = [b / a for a, b in values if a > 0]
                result[key] = dict(reference_median=statistics.median(a for a, _ in values),
                                   variant_median=statistics.median(b for _, b in values),
                                   paired_ratios=ratios,
                                   median_ratio=statistics.median(ratios) if ratios else None,
                                   worst_ratio=max(ratios) if ratios else None)
            results.append(result)
    return sorted(results, key=lambda r: r["seconds"]["worst_ratio"], reverse=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--example", action="store_true")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=180, help="seconds per measured operation")
    parser.add_argument("--fixture-timeout", type=float, default=1800, help="seconds for each setup or verification")
    args = parser.parse_args()
    if args.example:
        print(json.dumps(example(), indent=2))
        return 0
    if not args.plan or not args.output or args.rounds < 1 or any(
            not math.isfinite(n) or n <= 0 for n in (args.timeout, args.fixture_timeout)):
        parser.error("need --plan, --output and positive rounds/timeouts")
    if platform.system() not in ("Linux", "Darwin") or not Path("/usr/bin/time").is_file():
        parser.error("requires Linux GNU /usr/bin/time or macOS /usr/bin/time")
    plan = json.loads(args.plan.read_text())
    validate(plan)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, LC_ALL="C", SYQ_TUNING_CACHE="", SYQ_TUNING_HISTORY="")
    # A caller's diagnostic settings must not silently change the measured run.
    for key in list(env):
        if key.startswith("SYQ_") and key not in ("SYQ_TUNING_CACHE", "SYQ_TUNING_HISTORY"):
            del env[key]
    report = dict(plan=plan, rounds=args.rounds, complete=False, cleaned=False, trials=[],
                  platform=platform.platform(), cpu_count=os.cpu_count(),
                  allowed_cpus=sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
                  binary_sha256={v["name"]: sha256_file(v["binary"]) for v in plan["variants"]},
                  harness_sha256=sha256_file(__file__), sample_interval_seconds=0.02,
                  cpu_time_resolution_seconds=0.01,
                  wall_clock="includes native time launcher", cache="fresh fsynced fixtures, warm caches")
    mounts = Path("/proc/self/mountinfo")
    (args.output / "mounts.txt").write_text(mounts.read_text() if mounts.exists() else
        subprocess.run(["/sbin/mount"], capture_output=True, text=True, check=True, timeout=10).stdout)
    (args.output / "cpu-constraints.json").write_text(json.dumps(cpu_constraints(), indent=2))

    def save():
        report["comparisons"] = comparisons(report["trials"], plan["reference"])
        (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")

    def interrupted(signum, _frame):
        # Defer interruption to a checkpoint so Popen cannot launch a process
        # just before an exception prevents us from owning and cleaning it.
        global INTERRUPTED
        INTERRUPTED = signum

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    save()
    try:
        for case in plan["cases"]:
            for iteration in range(args.rounds):
                variants = plan["variants"] if iteration % 2 == 0 else list(reversed(plan["variants"]))
                for variant in variants:
                    stem = args.output / f"{case['name']}-{iteration + 1}-{variant['name']}"
                    row = dict(case=case["name"], variant=variant["name"], round=iteration + 1, verified=False)
                    report["trials"].append(row)
                    save()
                    with tempfile.TemporaryDirectory(prefix="syq-concurrency-", dir=case["root"]) as temporary:
                        root = Path(temporary).resolve()
                        row["fixture"] = str(root)
                        row["load_before"] = os.getloadavg()
                        row["device"] = root.stat().st_dev
                        hashes, row["fixture_bytes"] = fixture(root, case, Deadline(args.fixture_timeout, stem.name + " setup"))
                        operation = "rm" if case["operation"] == "rm" else "cp"
                        command = [variant["binary"], operation, "--no-progress", "--srcs-in", str(root / "source")]
                        if operation == "cp":
                            command += ["--into", str(root / "destination")]
                        if case["operation"] == "prune":
                            command += ["--prune"]
                        if variant["workers"] is not None:
                            command += ["--performance-tuning", f"workers={variant['workers']}"]
                        row.update(measure(command, env, variant["cpus"], stem, args.timeout))
                        save()
                        if row["exit_code"]:
                            raise RuntimeError(f"{stem.name}: exit {row['exit_code']}; see {stem}.stderr")
                        verify(root, case, hashes, Deadline(args.fixture_timeout, stem.name + " verify"))
                        row["verified"] = True
                    row["cleaned"] = not root.exists()
                    save()
                    print(json.dumps(row), flush=True)
        report["complete"] = True
    except BaseException as error:
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        report["cleaned"] = all(not Path(r["fixture"]).exists() for r in report["trials"] if "fixture" in r)
        save()
    print(json.dumps(report["comparisons"], indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
