"""Multi-destination contracts inside the disposable three-container SSH lab."""

import contextlib
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time

HOSTS = ("source", "destination")
REMOTE = "/tmp/syq-real-ssh/fanout"


def ssh(host, command, *, check=True, input=None):
    return subprocess.run(
        ["ssh", host, command], input=input, capture_output=True,
        check=check, timeout=15,
    )


def records(path):
    if not path.exists():
        return []
    # A writer may still be appending the last record.
    return [json.loads(line) for line in path.read_bytes().splitlines(keepends=True)
            if line.endswith(b"\n")]


def wait_for(predicate, label, timeout=15):
    deadline = time.monotonic() + timeout
    report = time.monotonic() + 3
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return
        if time.monotonic() >= report:
            print(f"waiting: {label}; last state {last!r}", flush=True)
            report += 3
        time.sleep(0.05)
    raise AssertionError(f"timed out: {label}; last state {last!r}")


def settled(path, expected):
    events = records(path)
    assert events[-1]["type"] == "result", events
    assert events[-1]["exit_code"] == expected, events[-1]
    members = [r for r in events if r["type"] == "destination_result"]
    assert sorted(r["destination_index"] for r in members) == [0, 1], members
    return members


@contextlib.contextmanager
def copying(local, name, source, destination, *, options=(), placements=None, tcp=False, helper="/usr/local/bin/syq"):
    result = local / f"{name}.jsonl"
    log = local / f"{name}.log"
    command = ["syq", "cp", "--syq-path", helper, "--no-progress",
               "--results", str(result), "-j", "4", *options, "--srcs-in", str(source)]
    if not tcp:
        command += ["--no-tcp"]
    command += placements or ["--tos", *HOSTS, "--into", destination]
    env = os.environ.copy()
    if tcp:
        env["SYQ_TEST_REQUIRE_TCP"] = "1"
    with log.open("wb") as output:
        child = subprocess.Popen(command, stdout=output, stderr=output, env=env)
        try:
            yield child, result
        except BaseException:
            print(log.read_text(errors="replace"), flush=True)
            raise
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()


def no_helpers():
    # Persistence is off in the surrounding suite. All attached helpers must exit.
    wait_for(lambda: all(ssh(h, "pgrep -x syq", check=False).returncode == 1
                         for h in HOSTS), "remote helper cleanup")


def verify_tree(source, destination):
    expected = hashlib.sha256((source / "payload").read_bytes()).hexdigest()
    for host in HOSTS:
        actual = ssh(host, f"sha256sum {shlex.quote(destination + '/payload')}")
        assert actual.stdout.decode().split()[0] == expected, (host, actual.stdout)
        ssh(host, f"test -d {destination}/empty && test -L {destination}/link "
                  f"&& test \"$(readlink {destination}/link)\" = payload")


def main():
    with tempfile.TemporaryDirectory(prefix="syq-fanout-") as directory:
        local = Path(directory)
        source = local / "source"
        source.mkdir()
        (source / "empty").mkdir()
        (source / "link").symlink_to("payload")
        (source / "payload").write_bytes(os.urandom(2 * 1024 * 1024))
        for host in HOSTS:
            ssh(host, f"mkdir -p {REMOTE}")

        for tcp in (False, True):
            name = "tcp" if tcp else "ssh"
            print(f"case: multi-destination success over {name}", flush=True)
            destination = f"{REMOTE}/{name}"
            with copying(local, name, source, destination, tcp=tcp) as (child, result):
                assert child.wait(timeout=30) == 0
                settled(result, 0)
            verify_tree(source, destination)
            no_helpers()

        print("case: multi-destination copies preserve persistent SSH masters", flush=True)
        trace = Path("/tmp/syq-real-ssh-ssh.trace")
        trace_start = len(trace.read_text().splitlines())
        subprocess.run(["syq", "persist", "on"], check=True, capture_output=True, timeout=10)
        try:
            for attempt in range(2):
                with copying(local, f"persistent-{attempt}", source, f"{REMOTE}/persistent",
                             options=["--hash"]) as (child, result):
                    assert child.wait(timeout=30) == 0
                    settled(result, 0)
                controls = {}
                for line in trace.read_text().splitlines()[trace_start:]:
                    fields = dict(field.split("=", 1) for field in line.split("\t"))
                    if fields.get("control_master") == "auto" and fields.get("host") in HOSTS:
                        controls[fields["host"]] = fields["control_path"]
                assert set(controls) == set(HOSTS), controls
                for host, control in controls.items():
                    subprocess.run(["/usr/bin/ssh", "-S", control, "-O", "check", host],
                                   check=True, capture_output=True, timeout=10)
            verify_tree(source, f"{REMOTE}/persistent")
        finally:
            subprocess.run(["syq", "persist", "off"], check=True, capture_output=True, timeout=15)
        no_helpers()

        print("case: multi-destination refusal before any target mutation", flush=True)
        with copying(local, "refusal", source, "unused", placements=[
            "--to", "source", "--into", f"{REMOTE}/refused",
            "--to", "destination", "--into-existing", f"{REMOTE}/missing",
        ]) as (child, result):
            assert child.wait(timeout=15) == 1
            settled(result, 1)
        ssh("source", f"test ! -e {REMOTE}/refused")
        no_helpers()

        # Enough noncompressible data to interrupt an active copy deterministically.
        block = os.urandom(1024 * 1024)
        with (source / "payload").open("wb") as output:
            for _ in range(64):
                output.write(block)

        for tcp in (False, True):
            name = "interrupt-tcp" if tcp else "interrupt-ssh"
            print(f"case: multi-destination {name}, cleanup, and verified retry", flush=True)
            destination = f"{REMOTE}/{name}"
            with copying(local, name, source, destination, options=["--bwlimit", "2M"],
                         tcp=tcp) as (child, result):
                wait_for(lambda: len({r.get("destination_index") for r in records(result)
                                      if r["type"] == "progress" and r["bytes_done"] > 0}) == 2,
                         "both targets transferring")
                child.send_signal(signal.SIGINT)
                assert child.wait(timeout=5) == -signal.SIGINT
            no_helpers()
            with copying(local, name + "-retry", source, destination,
                         options=["--hash"], tcp=tcp) as (child, result):
                assert child.wait(timeout=30) == 0
                settled(result, 0)
            verify_tree(source, destination)
            no_helpers()

        print("case: fatal peer cancels a live transfer and settles both targets", flush=True)
        destination = f"{REMOTE}/fatal"
        # Beta has the complete data. Its final directory metadata operation
        # waits for alpha to transfer bytes, then reports a fatal capacity error.
        ssh("destination", f"cp -a {REMOTE}/interrupt-ssh {destination}")
        ready, continuation = f"{REMOTE}/ready", f"{REMOTE}/continue"
        helper = f"{REMOTE}/helper"
        wrapper = ("#!/bin/sh\n"
                   f"export SYQ_TEST_FAIL_APPLY_ENOSPC={destination}\n"
                   f"export SYQ_TEST_CAPACITY_FAILURE_READY_FILE={ready}\n"
                   f"export SYQ_TEST_CAPACITY_FAILURE_CONTINUE_FILE={continuation}\n"
                   "exec /usr/local/bin/syq \"$@\"\n")
        ssh("destination", f"cat > {helper} && chmod 755 {helper}", input=wrapper.encode())
        ssh("source", f"ln -s /usr/local/bin/syq {helper}")
        with copying(local, "fatal", source, destination,
                     options=["--bwlimit", "2M", "--hash"], helper=helper
                     ) as (child, result):
            wait_for(lambda: any(r["type"] == "progress" and r.get("destination_index") == 0
                                 and r["bytes_done"] > 0 for r in records(result)),
                     "alpha transferring before beta fails")
            wait_for(lambda: ssh("destination", f"test -f {ready}", check=False).returncode == 0,
                     "beta ready to report capacity failure", timeout=5)
            ssh("destination", f"touch {continuation}")
            assert child.wait(timeout=5) == 1
            members = settled(result, 1)
            alpha = next(r for r in members if r["destination_index"] == 0)
            assert alpha["exit_code"] == 1 and alpha["files_transferred"] == 0, alpha
        no_helpers()
        with copying(local, "fatal-retry", source, destination,
                     options=["--hash"]) as (child, result):
            assert child.wait(timeout=30) == 0
            settled(result, 0)
        verify_tree(source, destination)
        no_helpers()
        print("multi-destination real-SSH scenarios passed", flush=True)


if __name__ == "__main__":
    main()
