"""Helpers shared by the real-SSH test scripts.

The lab image installs this module as `syq_real_ssh_lab`, so every python3 in
the lab can import it. Everything here runs inside the Debian test containers
with that image's python3.
"""
import contextlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time

PROGRESS_SECONDS = 3
POLL_SECONDS = 0.05


def run(*args, stdin=None, success=True, env=None, timeout=60, text=True):
    """Run a command, check whether it succeeded, and return its stdout."""
    result = subprocess.run(args, input=stdin, capture_output=True, text=text, timeout=timeout,
                            env=env)
    assert (result.returncode == 0) == success, (args, result)
    return result.stdout


def remote(host, command, **kwargs):
    """Run a shell command on a lab host as the lab account."""
    return run("ssh", host, command, **kwargs)


def wait_for(description, observe, timeout, *, done=bool, details=None):
    """Call `observe` until `done` accepts what it returned, and return that.

    While waiting it prints the last observed state every few seconds. At the
    deadline it fails with that state, followed by `details()` if given."""
    deadline = time.monotonic() + timeout
    progress = time.monotonic() + PROGRESS_SECONDS
    while True:
        state = observe()
        if done(state):
            return state
        now = time.monotonic()
        if now >= deadline:
            break
        if now >= progress:
            print(f"Waiting for {description}; last state: {state!r}", flush=True)
            progress = now + PROGRESS_SECONDS
        time.sleep(POLL_SECONDS)
    message = f"timed out after {timeout}s waiting for {description}; last state: {state!r}"
    if details is not None:
        message += f"; {details()}"
    raise AssertionError(message)


def stop(process):
    """End a process started in its own session, and its process group."""
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


@contextlib.contextmanager
def running(host, command):
    """Run a command on a host in the background, with its output in a file."""
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(["ssh", host, command], stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=output, start_new_session=True)
        try:
            yield process, output
        except BaseException:
            print(os.pread(output.fileno(), 1024 * 1024, 0).decode(errors="replace"), flush=True)
            raise
        finally:
            stop(process)


def finish(process, output, label, success=True):
    """Wait up to 90 seconds for a `running` command, printing its output."""
    deadline, offset = time.monotonic() + 90, 0
    while True:
        try:
            status = process.wait(timeout=5)
            break
        except subprocess.TimeoutExpired:
            data = os.pread(output.fileno(), 1024 * 1024, offset)
            offset += len(data)
            print(data.decode(errors="replace"), end="", flush=True)
            print(f"Waiting for the {label}", flush=True)
            assert time.monotonic() < deadline, f"{label} exceeded its deadline"
    text = os.pread(output.fileno(), 1024 * 1024, 0).decode(errors="replace")
    print(text, end="", flush=True)
    assert status != 124, f"{label} reached its safety timeout"
    assert (status == 0) == success, (status, text)
    return text


def enrollments():
    """The runner's active enrollments, as (identifier, account) pairs."""
    rows = []
    for line in run("syq", "receiver", "list").splitlines():
        fields = line.split("\t")
        if len(fields) >= 3 and fields[1] == "active":
            rows.append((fields[0], fields[2]))
    return rows


def successful_results(path):
    """The records of a --results file, whose last must be a successful result."""
    records = [json.loads(line) for line in Path(path).read_text().splitlines()]
    assert records and records[-1]["type"] == "result" and records[-1]["status"] == "success", records
    return records


def tuning_observed(path):
    """The counts of each `syq: tuning observed:` line in SYQ_DEBUG output."""
    marker = "syq: tuning observed: "
    return [json.loads(line.split(marker, 1)[1]) for line in Path(path).read_text().splitlines()
            if marker in line]


def digest(host, path):
    return remote(host, "sha256sum " + shlex.quote(path)).split()[0]


# Programs that inspect a lab host. `probe` runs one as the account whose
# processes it inspects; its inputs arrive as the JSON object `v` on stdin, and
# it prints its answer as JSON. A test adds its own with `PROBES.update`.
PROBES = {
    # Whether every [pid, start time] in `processes` has exited.
    "exited": r'''
active = []
for pid, started in v["processes"]:
    try:
        stat = Path("/proc", str(pid), "stat").read_text().rsplit(") ", 1)[1].split()
        if stat[19] == started and stat[0] != "Z":
            active.append(pid)
    except FileNotFoundError:
        pass
print(json.dumps(not active))
''',
    # Whether an established TCP connection reaches `port` on destination.
    "tcp": r'''
import socket, struct
address = socket.gethostbyname("destination")
connected = False
for row in open("/proc/net/tcp").read().splitlines()[1:]:
    fields = row.split()
    host, port = fields[2].split(":")
    peer = socket.inet_ntoa(struct.pack("<I", int(host, 16)))
    connected |= fields[3] == "01" and peer == address and int(port, 16) == v["port"]
print(json.dumps(connected))
''',
    # Whether a partial of `name` in `root` starts with the `size` bytes whose
    # SHA-256 is `digest`.
    "partial": r'''
import hashlib
root = Path(v["root"])
matches = list(root.glob("." + v["name"] + ".syq-tmp.*"))
print(json.dumps(any(hashlib.sha256(p.open("rb").read(v["size"])).hexdigest() == v["digest"]
                     for p in matches)))
''',
}


def probe(host, name, timeout=60, **values):
    script = "import json, sys\nfrom pathlib import Path\nv = json.load(sys.stdin)\n" + PROBES[name]
    return json.loads(remote(host, "python3 -c " + shlex.quote(script), stdin=json.dumps(values),
                             timeout=timeout))
