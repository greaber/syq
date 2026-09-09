#!/usr/bin/env python3
"""Compare fresh APFS copies; report timings and verify bytes outside the timer.

Run: cargo build --release --locked
     python3 scripts/benchmark-macos-clone.py target/release/syq

Uses disposable directories under TMPDIR. Needs about 2 GiB free. Timings include
process startup and use warm filesystem caches; they do not measure durable
writes or predict another disk's speed. Forced ranges isolate the clone benefit
in the same binary, rather than comparing unrelated changes between versions.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile
import time


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("syq", type=Path)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("this benchmark requires macOS and a clone-capable APFS TMPDIR")
    if args.rounds < 1:
        parser.error("--rounds must be positive")
    binary = args.syq.resolve(strict=True)
    env = os.environ.copy()
    env["SYQ_DEBUG"] = "1"
    print(json.dumps({"platform": platform.platform(), "binary": str(binary),
                      "rounds": args.rounds, "cache": "warm", "destination": "fresh"}), flush=True)
    with tempfile.TemporaryDirectory(prefix="syq-clone-benchmark-") as temporary:
        root = Path(temporary)
        for case, count, mib in [("large", 1, 512), ("tree", 64, 8), ("medium", 64, 1)]:
            source = root / "source"
            source.mkdir()
            # Real writes, not sparse files or filesystem-compressed fixtures.
            block = os.urandom(1 << 20)
            expected = {}
            for index in range(count):
                path = source / f"file-{index:04d}"
                with path.open("wb") as stream:
                    for _ in range(mib):
                        stream.write(block)
                expected[path.name] = digest(path)
            times = {name: [] for name in ("auto", "ranges", "cp")}
            for iteration in range(args.rounds):
                order = list(times)
                order = order[iteration % 3:] + order[:iteration % 3]
                for name in order:
                    destination = root / "destination"
                    destination.mkdir()
                    command = (["/bin/cp", "-R", str(source) + "/.", str(destination)]
                               if name == "cp" else
                               [str(binary), "cp", "--srcs-in", str(source), "--into",
                                str(destination), "--no-progress"])
                    if name == "ranges":
                        command += ["--tuning-options=copy-path=ranges"]
                    started = time.perf_counter()
                    result = subprocess.run(command, env=env, capture_output=True,
                                            text=True, timeout=180)
                    elapsed = time.perf_counter() - started
                    if result.returncode:
                        raise RuntimeError(f"{command}: {result.stderr}")
                    actual = {path.name: digest(path) for path in destination.iterdir()}
                    if actual != expected:
                        raise RuntimeError(f"{case}/{name}: copied bytes differ")
                    observed = None
                    if name != "cp":
                        prefix = "syq: tuning observed: "
                        observed = next(json.loads(line[len(prefix):])
                                        for line in result.stderr.splitlines()
                                        if line.startswith(prefix))
                        if case != "medium":
                            if name == "auto":
                                assert observed["local_whole_files"] == count, observed
                                assert observed["range_requests"] == 0, observed
                            else:
                                assert observed["local_whole_files"] == 0, observed
                                assert observed["range_requests"] > 0, observed
                        else:
                            assert observed["local_whole_files"] == 0, observed
                    times[name].append(elapsed)
                    print(json.dumps({"case": case, "method": name, "round": iteration + 1,
                                      "seconds": elapsed, "observed": observed}), flush=True)
                    shutil.rmtree(destination)
            medians = {name: statistics.median(values) for name, values in times.items()}
            print(json.dumps({"case": case, "files": count, "MiB": count * mib,
                              "median_seconds": medians,
                              "ranges_over_auto": medians["ranges"] / medians["auto"],
                              "auto_over_cp": medians["auto"] / medians["cp"]}), flush=True)
            shutil.rmtree(source)


if __name__ == "__main__":
    main()
