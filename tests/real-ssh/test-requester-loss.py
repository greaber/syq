#!/usr/bin/env python3
"""Ending the syq that requested a server-to-server copy stops that copy.

The runner starts a slow copy from source into a command-restricted receiver
on destination, then ends the requesting syq: once with SIGINT to its process
group, as Ctrl-C does, and once with SIGKILL to that syq alone, which leaves
its SSH client running. The source coordinator, its processes, and the
destination receiver must exit within seconds without publishing either file.
The receiver then sees an interrupted copy: it removes the partial shorter
than 1 MiB and keeps the longer one, and a rerun completes.
"""
import hashlib
import json
import os
import shlex
import signal
import subprocess
import tempfile
import time

SOURCE = "/tmp/syq-real-ssh/requester-loss-source"
FILES = {"short": 921600, "long": 6291456}
STOP_SECONDS = 5

# Each probe runs on the host it inspects and reads its input from stdin.
PROBES = {
    # The copy's coordinator, found by its encoded destination operand, and
    # every process below it.
    "coordinator": r'''
import base64
operand = base64.b64encode(v["destination"].encode()).decode().rstrip("=")
processes = {}
for p in Path("/proc").iterdir():
    if not p.name.isdigit():
        continue
    try:
        args = p.joinpath("cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
        stat = p.joinpath("stat").read_text().rsplit(") ", 1)[1].split()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    if stat[0] != "Z":
        processes[int(p.name)] = (args, int(stat[1]), stat[19])
tree = [pid for pid, (args, _, _) in processes.items()
        if "--delegated-operands-b64" in args and operand in args]
for pid in tree:
    tree.extend(child for child, (_, parent, _) in processes.items() if parent == pid)
print(json.dumps([[pid, processes[pid][2], " ".join(processes[pid][0])[:120]] for pid in tree]))
''',
    "receivers": r'''
import os
found = []
for p in Path("/proc").iterdir():
    if not p.name.isdigit():
        continue
    try:
        args = p.joinpath("cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
        stat = p.joinpath("stat").read_text().rsplit(") ", 1)[1].split()
        owner = p.stat().st_uid
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    if owner == os.getuid() and stat[0] != "Z" and "--restricted-receiver" in args:
        found.append([int(p.name), stat[19], " ".join(args)[:120]])
print(json.dumps(found))
''',
    "alive": r'''
alive = []
for pid, started, description in v["processes"]:
    try:
        stat = Path("/proc", str(pid), "stat").read_text().rsplit(") ", 1)[1].split()
    except FileNotFoundError:
        continue
    if stat[19] == started and stat[0] != "Z":
        alive.append(description)
print(json.dumps(alive))
''',
    "partials": r'''
root = Path(v["root"])
found = sorted([p.name, p.stat().st_size] for p in root.glob(".*.syq-tmp.*")) if root.is_dir() else []
print(json.dumps(found))
''',
    "published": r'''
root = Path(v["root"])
print(json.dumps(sorted(name for name in v["names"] if root.joinpath(name).exists())))
''',
    "digests": r'''
import hashlib
root = Path(v["root"])
print(json.dumps({name: hashlib.sha256(root.joinpath(name).read_bytes()).hexdigest()
                  for name in v["names"]}))
''',
}


def probe(host, name, **values):
    script = "import json, sys\nfrom pathlib import Path\nv = json.load(sys.stdin)\n" + PROBES[name]
    result = subprocess.run(["ssh", host, "python3 -c " + shlex.quote(script)],
                            input=json.dumps(values), capture_output=True, text=True,
                            timeout=30, check=True)
    return json.loads(result.stdout)


def wait_for(description, predicate, timeout):
    deadline = time.monotonic() + timeout
    progress = time.monotonic() + 2
    state = None
    while time.monotonic() < deadline:
        done, state = predicate()
        if done:
            return state
        if time.monotonic() >= progress:
            print(f"waiting for {description}; last state: {state}", flush=True)
            progress += 2
        time.sleep(0.1)
    raise AssertionError(f"timed out after {timeout}s waiting for {description}; last state: {state}")


def copy(destination, *options):
    return ["syq", "cp", "--no-progress", *options, "--from", "source", "--srcs-in", SOURCE,
            "--to", "destination", "--into", destination]


def interrupt_copy(name, end_requester):
    destination = f"/tmp/syq-real-ssh/requester-loss-{name}"
    # Two workers write each file in ranges at 32 KiB/s: the copy needs
    # minutes, so it is still running when its requester ends.
    command = copy(destination, "--resource-limits", "bandwidth=32",
                   "--performance-tuning", "workers=2,copy-path=ranges")
    with tempfile.TemporaryFile() as output:
        requester = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                     stderr=output, start_new_session=True)
        try:
            wait_for("partials of both files", lambda: (
                len(partials := probe("destination", "partials", root=destination)) == len(FILES),
                partials), timeout=45)
            coordinator = probe("source", "coordinator", destination=destination)
            assert coordinator, "no coordinator for the copy on source"
            receivers = probe("destination", "receivers")
            assert receivers, "no restricted receiver on destination"
            ended = time.monotonic()
            end_requester(requester.pid)
            status = requester.wait(timeout=10)
            assert status != 0, status
            for host, processes in (("source", coordinator), ("destination", receivers)):
                wait_for(f"the copy's processes on {host} to exit", lambda: (
                    not (alive := probe(host, "alive", processes=processes)), alive),
                    timeout=STOP_SECONDS)
            print(f"{name}: the copy stopped {time.monotonic() - ended:.1f}s after its "
                  "requester ended", flush=True)
        except BaseException:
            output.seek(0)
            print(output.read().decode(errors="replace"), flush=True)
            if requester.poll() is None:
                os.killpg(requester.pid, signal.SIGKILL)
                requester.wait(timeout=10)
            raise
    published = probe("destination", "published", root=destination, names=list(FILES))
    assert not published, f"an interrupted copy published {published}"
    partials = probe("destination", "partials", root=destination)
    assert [(name.split(".syq-tmp.")[0], size) for name, size in partials] == [
        (".long", FILES["long"])], f"the receiver did not keep only the resumable partial: {partials}"
    subprocess.run(copy(destination), check=True, timeout=120)
    expected = probe("source", "digests", root=SOURCE, names=list(FILES))
    assert probe("destination", "digests", root=destination, names=list(FILES)) == expected


def main():
    subprocess.run(["ssh", "source", "mkdir -p " + shlex.quote(SOURCE) + " && " + " && ".join(
        f"head -c {size} /dev/urandom > {shlex.quote(SOURCE + '/' + name)}"
        for name, size in FILES.items())], check=True, timeout=30)
    # Ctrl-C reaches the requester and its SSH client together.
    interrupt_copy("interrupted", lambda pid: os.killpg(pid, signal.SIGINT))
    # Only the requester ends; its SSH client sees the end of its input.
    interrupt_copy("killed", lambda pid: os.kill(pid, signal.SIGKILL))


if __name__ == "__main__":
    main()
