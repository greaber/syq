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
Pruning has its own automatic deletion pool: fixed-worker variants are skipped
for prune cases. Tuning cache/history are disabled, so automatic copies always
start without remembered worker counts. This does not measure learned starts.
Results retain paired rounds, individual cases and worst slowdowns; there is no
aggregate pass threshold. Reversing variant order balances linear order effects,
but does not remove workload drift or prove safety on unmeasured systems.

Requires Linux (GNU /usr/bin/time) or macOS (/usr/bin/time). CPU affinity is
Linux-only and applies to the WHOLE process, independently of worker count;
it does not reproduce worker-only pinning. Wall time ends when the coordinator
exits, including the small native time launcher. The harness then lets helpers
exit within the same timeout. Linux CPU includes exit accounting for all local
processes, using a subreaper for helpers the coordinator did not wait for.
macOS copy/prune CPU is an estimate from cumulative per-process libproc samples;
it can miss final work or entire short-lived processes. Missing either expected
process makes that estimate unavailable. Native time CPU has 10 ms precision.
Both platforms sample each process's CPU, RSS, threads, FDs and disk I/O every
20 ms plus sampling cost. Group memory is a sampled sum of current RSS, not a
sum of individual peaks. Single-process rm uses native time's maximum RSS.
Samples are lower bounds; check sample gaps and observer CPU, and use longer
runs for CPU comparisons. Linux per-process I/O includes waited children: do
not sum those historical counters. Process CPU excludes background kernel
threads (journal commits, inode cleanup, transaction sync); these are not
system-wide filesystem cost measurements. No remote helpers are launched.
Logs and raw host/mount metadata stay in --output.
"""

import argparse
import contextlib
import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import resource
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
    reference = next(v for v in plan["variants"] if v["name"] == plan["reference"])
    if any(c["operation"] == "prune" for c in plan["cases"]) and reference["workers"] is not None:
        raise ValueError("prune cases require an automatic-worker reference")


def case_variants(case, variants):
    return [v for v in variants if case["operation"] != "prune" or v["workers"] is None]


def save_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def check_binaries(report):
    report["binary_sha256_after"] = {v["name"]: sha256_file(v["binary"]) for v in report["plan"]["variants"]}
    if report["binary_sha256_after"] != report["binary_sha256"]:
        raise RuntimeError("a benchmark binary changed during the run; comparisons are invalid")


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
        digest = hashlib.sha256() if case["operation"] == "cp" else None
        with path.open("wb") as stream:
            remaining = size
            while remaining:
                data = rng.randbytes(min(remaining, 1 << 20))
                stream.write(data)
                if digest is not None:
                    digest.update(data)
                remaining -= len(data)
                deadline.check(f"creating file {index}/{case['files']}")
            if size:
                stream.flush()
                os.fsync(stream.fileno())
        # Store hashes only when copying bytes; large empty rm trees should
        # not leave a million-entry Python manifest hot during measurement.
        if digest is not None:
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


def linux_group(pgid):
    # Discover children through /proc's task lists, including helpers adopted
    # by our subreaper. Scanning every host PID at 50 Hz is costly on busy
    # machines. Inspect all threads because any thread can launch a child.
    def children(pid):
        found = []
        for path in (Path("/proc") / str(pid) / "task").glob("*/children"):
            try:
                found.extend(map(int, path.read_text().split()))
            except (FileNotFoundError, ProcessLookupError):
                pass
        return found

    members = {}
    pending = [pgid] + children(os.getpid())
    seen = set()
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        try:
            fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == pgid:
                members[pid] = fields
                pending.extend(children(pid))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return members


def sample_linux(launcher):
    """Sample every process in the group, including the local receiver."""
    samples = []
    ticks = os.sysconf("SC_CLK_TCK")
    for pid, fields in linux_group(launcher).items():
        if pid == launcher:
            continue
        if fields[0] == "Z":
            continue
        proc = Path("/proc") / str(pid)
        try:
            status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines())
            io = dict(line.split(":", 1) for line in (proc / "io").read_text().splitlines())
            command = (proc / "cmdline").read_bytes().decode(errors="replace").split("\0")[:-1]
            samples.append(dict(pid=pid, parent_pid=int(fields[1]), command=command,
                                user_seconds=int(fields[11]) / ticks,
                                system_seconds=int(fields[12]) / ticks,
                                rss_bytes=int(status.get("VmRSS", "0 kB").split()[0]) * 1024,
                                peak_rss_bytes=int(status.get("VmHWM", "0 kB").split()[0]) * 1024,
                                threads=int(status["Threads"]),
                                allowed_cpus=status["Cpus_allowed_list"].strip(),
                                fds=len(list((proc / "fd").iterdir())),
                                read_bytes=int(io["read_bytes"]), write_bytes=int(io["write_bytes"])))
        except (FileNotFoundError, ProcessLookupError):
            pass  # A process can exit between reads; wait accounting still captures its CPU.
    return samples


class DarwinSampler:
    """Read-only libproc counters; no task suspension, tracing or product hooks.

    ABI: apple-oss-distributions/xnu, bsd/sys/{proc_info,resource}.h.
    rusage CPU counters use Mach time units (fill_task_rusage in bsd_kern.c).
    """
    class BsdInfo(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint32) for n in (
            "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid",
            "svuid", "svgid", "reserved")] + [
            ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)] + [
            (n, ctypes.c_uint32) for n in ("nfiles", "pgid", "pjobc", "tdev", "tpgid", "nice")] + [
            ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]

    class TaskInfo(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in (
            "virtual", "resident", "user", "system", "threads_user", "threads_system")] + [
            (n, ctypes.c_int32) for n in ("policy", "faults", "pageins", "cow_faults", "messages_sent",
                "messages_received", "syscalls_mach", "syscalls_unix", "csw", "threadnum", "numrunning", "priority")]

    class Usage(ctypes.Structure):
        _fields_ = [("uuid", ctypes.c_ubyte * 16)] + [(n, ctypes.c_uint64) for n in (
            "user", "system", "idle_wakeups", "interrupt_wakeups", "pageins", "wired", "resident",
            "footprint", "start", "exit", "child_user", "child_system", "child_idle", "child_interrupt",
            "child_pageins", "child_elapsed", "read_bytes", "write_bytes")]

    def __init__(self):
        self.lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.lib.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        timebase = (ctypes.c_uint32 * 2)()
        libsystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        if libsystem.mach_timebase_info(ctypes.byref(timebase)) != 0:
            raise RuntimeError("mach_timebase_info failed")
        self.seconds_per_tick = timebase[0] / timebase[1] / 1e9

    def pids(self, pgid):
        pids = (ctypes.c_int * 4096)()
        ctypes.set_errno(0)
        size = self.lib.proc_listpids(2, pgid, pids, ctypes.sizeof(pids))
        if size == ctypes.sizeof(pids):
            raise RuntimeError("process group exceeds sampler capacity")
        if size < 0 or (size == 0 and ctypes.get_errno() not in (0, errno.ESRCH, errno.ENOENT)):
            raise OSError(ctypes.get_errno(), "cannot list benchmark process group")
        return [pid for pid in pids[:size // ctypes.sizeof(ctypes.c_int)] if pid]

    def info(self, pid, flavor, value):
        ctypes.set_errno(0)
        size = self.lib.proc_pidinfo(pid, flavor, 0, ctypes.byref(value), ctypes.sizeof(value))
        if size == ctypes.sizeof(value):
            return value
        if size == 0 and ctypes.get_errno() in (0, errno.ESRCH, errno.ENOENT):
            return None
        raise OSError(ctypes.get_errno(), f"cannot read process {pid}, flavor {flavor} (size {size})")

    def alive(self, pgid):
        for pid in self.pids(pgid):
            info = self.info(pid, 3, self.BsdInfo())
            if info is not None and info.status != 5:  # SZOMB
                return True
        return False

    def sample(self, launcher):
        samples = []
        for pid in self.pids(launcher):
            if pid == launcher:
                continue
            bsd = self.info(pid, 3, self.BsdInfo())
            if bsd is None or bsd.status == 5:
                continue
            task = self.info(pid, 4, self.TaskInfo())
            usage = self.Usage()
            if bsd is None or task is None:
                continue
            if self.lib.proc_pid_rusage(pid, 2, ctypes.byref(usage)):
                if ctypes.get_errno() in (errno.ESRCH, errno.ENOENT):
                    continue
                raise OSError(ctypes.get_errno(), f"cannot read process {pid} usage")
            # PROC_PIDLISTFDS returns packed (fd, type) pairs, eight bytes each.
            ctypes.set_errno(0)
            size = self.lib.proc_pidinfo(pid, 1, 0, None, 0)
            if size <= 0 and ctypes.get_errno():
                if ctypes.get_errno() in (errno.ESRCH, errno.ENOENT):
                    continue
                raise OSError(ctypes.get_errno(), f"cannot count process {pid} descriptors")
            fds = ctypes.create_string_buffer(max(size + 4096, 4096))
            ctypes.set_errno(0)
            size = self.lib.proc_pidinfo(pid, 1, 0, fds, len(fds))
            if size <= 0 and ctypes.get_errno():
                if ctypes.get_errno() in (errno.ESRCH, errno.ENOENT):
                    continue
                raise OSError(ctypes.get_errno(), f"cannot read process {pid} descriptors")
            if size == len(fds):
                raise RuntimeError("file descriptor list grew beyond sampler buffer")
            samples.append(dict(pid=pid, parent_pid=bsd.ppid,
                command=[(bsd.name or bsd.comm).decode(errors="replace")], allowed_cpus=None,
                user_seconds=usage.user * self.seconds_per_tick,
                system_seconds=usage.system * self.seconds_per_tick,
                rss_bytes=usage.resident, peak_rss_bytes=usage.resident,
                threads=task.threadnum, fds=size // 8,
                read_bytes=usage.read_bytes, write_bytes=usage.write_bytes))
        return samples


def group_alive(pgid):
    if platform.system() == "Linux":
        return any(fields[0] != "Z" for fields in linux_group(pgid).values())
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


@contextlib.contextmanager
def subreaper():
    """Adopt un-waited local helpers; restore the caller's original setting."""
    if platform.system() != "Linux":
        yield
        return
    # https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) or libc.prctl(36, 1, 0, 0, 0):
        raise OSError(ctypes.get_errno(), "cannot enable child subreaper accounting")
    try:
        yield
    finally:
        if libc.prctl(36, previous.value, 0, 0, 0):
            raise OSError(ctypes.get_errno(), "cannot restore child subreaper setting")


def reap_group(pgid, accounting):
    """Only call after the launcher waiter has finished, to avoid a wait race."""
    while True:
        try:
            pid, status, usage = os.wait4(-pgid, os.WNOHANG)
        except ChildProcessError:
            return True
        if pid == 0:
            return False
        accounting.append(dict(pid=pid, exit_code=os.waitstatus_to_exitcode(status),
            scope="adopted process and descendants it waited for", resources=dict(
                user_seconds=usage.ru_utime, system_seconds=usage.ru_stime,
                peak_rss_bytes=usage.ru_maxrss * 1024,
                voluntary_switches=usage.ru_nvcsw, involuntary_switches=usage.ru_nivcsw,
                input_blocks=usage.ru_inblock, output_blocks=usage.ru_oublock)))


def measure(command, env, cpus, stem, timeout, operation=None):
    with subreaper():
        return measure_group(command, env, cpus, stem, timeout, operation)


def measure_group(command, env, cpus, stem, timeout, operation):
    system = platform.system()
    darwin = DarwinSampler() if system == "Darwin" else None
    usage_path = stem.with_suffix(".usage")
    timed = (["/usr/bin/time", "-f", GNU_FORMAT, "-o", str(usage_path)] if system == "Linux"
             else ["/usr/bin/time", "-l"]) + command
    ended = []
    processes = {}
    accounting = []
    peaks = dict(threads=None, fds=None, rss_bytes=None)
    sample_count = 0
    sample_times = []
    observer_before = resource.getrusage(resource.RUSAGE_SELF)

    def sample():
        nonlocal sample_count
        snapshot = sample_linux(child.pid) if darwin is None else darwin.sample(child.pid)
        timestamp = time.monotonic() - started
        sample_times.append(timestamp)
        present = {entry["pid"] for entry in snapshot}
        for pid, record in processes.items():
            if pid not in present:
                record.setdefault("first_missing_seconds", timestamp)
        if not snapshot:
            return
        sample_count += 1
        for key in peaks:
            peaks[key] = max(peaks[key] or 0, sum(s[key] for s in snapshot))
        for entry in snapshot:
            pid = entry["pid"]
            record = processes.setdefault(pid, dict(pid=pid, command=[], sampled={}))
            record.setdefault("first_seen_seconds", timestamp)
            record["last_seen_seconds"] = timestamp
            record.pop("first_missing_seconds", None)
            if entry["command"]:
                record["command"] = entry["command"]
            if entry["parent_pid"] == child.pid:
                record["role"] = "coordinator"
            elif "--local-receiver" in record["command"]:
                record["role"] = "local_receiver"
            else:
                record.setdefault("role", "descendant")
            record["allowed_cpus"] = entry["allowed_cpus"]
            for key in ("threads", "fds", "peak_rss_bytes", "user_seconds", "system_seconds", "read_bytes", "write_bytes"):
                record["sampled"][key] = max(record["sampled"].get(key, 0), entry[key])
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
        finished = False
        try:
            while waiter.is_alive():
                deadline.check(f"running {time.monotonic() - started:.1f}s")
                sample()
                waiter.join(0.02)
            # The coordinator can exit before its receiver. Allow orderly
            # shutdown, account for adopted descendants, and keep the original
            # deadline. Successful trials must never kill unfinished helpers.
            while True:
                sample()
                reaped = reap_group(child.pid, accounting) if system == "Linux" else True
                if reaped and not (darwin.alive(child.pid) if darwin else group_alive(child.pid)):
                    break
                deadline.check("waiting for receiver/process group to finish")
                time.sleep(0.02)
            group_ended = time.monotonic()
            finished = True
        finally:
            # On timeout/interruption, terminate and reap the entire group.
            if not finished:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                waiter.join(10)
                cleanup = Deadline(10, stem.name + " cleanup", interruptible=False)
                while True:
                    reaped = reap_group(child.pid, accounting) if system == "Linux" and not waiter.is_alive() else True
                    if not waiter.is_alive() and reaped and not (darwin.alive(child.pid) if darwin else group_alive(child.pid)):
                        break
                    cleanup.check("waiting for process group to exit")
                    time.sleep(0.02)
        log = (usage_path if system == "Linux" else stem.with_suffix(".stderr")).read_text()
    coordinator = time_usage(log, system)
    coordinator_pid = next((p for p, r in processes.items() if r.get("role") == "coordinator"), None)
    accounting.insert(0, dict(pid=coordinator_pid, scope="coordinator and descendants it waited for",
                              resources=coordinator))
    complete = system == "Linux" or operation == "rm"
    resources = {key: sum(a["resources"][key] for a in accounting) if complete else None
                 for key in coordinator if key != "peak_rss_bytes"}
    resources["cpu_seconds"] = resources["user_seconds"] + resources["system_seconds"] if complete else None
    expected_observed = coordinator_pid is not None and (operation not in ("cp", "prune") or len(processes) >= 2)
    if not complete and expected_observed:
        for key in ("user_seconds", "system_seconds"):
            resources[key] = sum(p["sampled"][key] for p in processes.values())
        resources["cpu_seconds"] = resources["user_seconds"] + resources["system_seconds"]
    # Wait accounting's maxrss is the largest process, not a group memory
    # peak. Keep it per accounting record. Never sum per-process peak values.
    resources["peak_rss_bytes"] = peaks["rss_bytes"] if expected_observed else None
    if operation == "rm":
        resources["peak_rss_bytes"] = coordinator["peak_rss_bytes"]
    observer_after = resource.getrusage(resource.RUSAGE_SELF)
    return dict(seconds=ended[0] - started, process_group_seconds=group_ended - started,
                drain_seconds=group_ended - ended[0], exit_code=child.returncode,
                resources=resources, accounting=accounting, cpu_accounting_complete=complete,
                cpu_accounting="exit accounting" if complete else "sampled cumulative process CPU",
                expected_processes_observed=expected_observed,
                memory_accounting="single-process maximum RSS" if operation == "rm" else "sampled sum of process RSS",
                processes=list(processes.values()), sampled=peaks, sample_count=sample_count,
                max_sample_gap_seconds=max(b - a for a, b in zip([0] + sample_times, sample_times + [group_ended - started])),
                observer_cpu_seconds=(observer_after.ru_utime + observer_after.ru_stime
                                      - observer_before.ru_utime - observer_before.ru_stime),
                command=command, observed_cpu_sets=sorted({s["allowed_cpus"] for s in processes.values() if s["allowed_cpus"] is not None}),
                log_prefix=str(stem))


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
                values = [(a, b) for a, b in values if a is not None and b is not None]
                # Native time rounds short CPU measurements to zero. Neither
                # a zero denominator nor a zero numerator establishes a ratio.
                ratios = [b / a for a, b in values if a > 0 and b > 0]
                result[key] = dict(available_pairs=len(values),
                                   reference_median=statistics.median(a for a, _ in values) if values else None,
                                   variant_median=statistics.median(b for _, b in values) if values else None,
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
                  tuning_history="disabled; automatic variants start without remembered counts",
                  kernel_background_cpu="not counted",
                  skipped_variants=[dict(case=c["name"], variant=v["name"], reason="pruning tunes its own deletion workers")
                      for c in plan["cases"] for v in plan["variants"] if v not in case_variants(c, plan["variants"])],
                  wall_clock="includes native time launcher", cache="fresh fsynced fixtures, warm caches")
    mounts = Path("/proc/self/mountinfo")
    (args.output / "mounts.txt").write_text(mounts.read_text() if mounts.exists() else
        subprocess.run(["/sbin/mount"], capture_output=True, text=True, check=True, timeout=10).stdout)
    (args.output / "cpu-constraints.json").write_text(json.dumps(cpu_constraints(), indent=2))

    def save():
        report["comparisons"] = comparisons(report["trials"], plan["reference"])
        save_json(args.output / "results.json", report)

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
                eligible = case_variants(case, plan["variants"])
                variants = eligible if iteration % 2 == 0 else list(reversed(eligible))
                for variant in variants:
                    trial = len(report["trials"]) + 1
                    stem = args.output / f"trial-{trial:06d}"
                    row = dict(trial=trial, case=case["name"], variant=variant["name"], round=iteration + 1, verified=False,
                               worker_control="automatic pruning" if case["operation"] == "prune" else variant["workers"] or "automatic")
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
                        row.update(measure(command, env, variant["cpus"], stem, args.timeout, case["operation"]))
                        save()
                        if row["exit_code"]:
                            raise RuntimeError(f"{stem.name}: exit {row['exit_code']}; see {stem}.stderr")
                        verify(root, case, hashes, Deadline(args.fixture_timeout, stem.name + " verify"))
                        row["verified"] = True
                    row["cleaned"] = not root.exists()
                    save()
                    print(json.dumps(row), flush=True)
        check_binaries(report)
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
