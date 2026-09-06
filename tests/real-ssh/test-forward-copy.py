"""Source-shell copies authorized by the runner; all paths are disposable."""
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time


def run(*args, success=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=40)
    assert (result.returncode == 0) == success, (args, result)
    return result.stdout


def remote(command, *, success=True):
    return run("ssh", "destination", command, success=success)


def copy(path, *, allow=True, success=True, extra=(), cancel=False,
         source="/tmp/syq-real-ssh/return-source/subdir/chunks.bin", prefix=None, after_approval=None):
    argv = ["syq", "cp", "-vv", source, "--to", "destination",
            "--via", "@laptop", "--as", path, "--connections", "2", *extra]
    command = "test -z \"${SSH_AUTH_SOCK:-}\" && test ! -e ~/.ssh/id_ed25519 && exec timeout 75 " + shlex.join(argv)
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(["ssh", "source", command], stdout=output, stderr=output, start_new_session=True)
        try:
            pending = json.loads(run("syq", "recv", "pending", "--json", "--wait", "--timeout", "15"))
            assert len(pending) == 1, pending
            request = pending[0]
            assert 'SSH "destination"' in request["destination"], request
            assert "SSH access" in request["permission"], request
            run("syq", "recv", "approve" if allow else "deny", request["id"])
            run("syq", "recv", "approve", request["id"], success=False)
            if after_approval is not None:
                after_approval()
            if cancel:
                deadline = time.monotonic() + 25
                progress = time.monotonic() + 5
                state = ""
                while time.monotonic() < deadline:
                    partials = remote("find /tmp/syq-real-ssh/forward -type f -name '.cancelled.syq-part.*'").splitlines()
                    state = repr(partials)
                    if len(partials) == 1:
                        state = remote("dd if=" + shlex.quote(partials[0]) + " bs=1M count=4 status=none | sha256sum")
                        if state == prefix:
                            break
                    assert process.poll() is None, "copy exited before cancellation"
                    if time.monotonic() >= progress:
                        print("Waiting for remote copy partial:", repr(state), flush=True)
                        progress += 5
                    time.sleep(.1)
                assert state == prefix, ("no complete resumable prefix before deadline", state)
                run("syq", "recv", "on", "--notify", "off")
            deadline = time.monotonic() + 65
            last_output = 0
            while True:
                try:
                    status = process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    data = os.pread(output.fileno(), 1024 * 1024, last_output)
                    last_output += len(data)
                    print(data.decode(errors="replace"), end="", flush=True)
                    print("Waiting for remote copy:", path, flush=True)
                    assert time.monotonic() < deadline, "remote copy exceeded its deadline"
            output.seek(0)
            text = output.read().decode(errors="replace")
            print(text, end="", flush=True)
            assert "one-time SSH grant" not in text and "signed receiver" not in text, text
            assert "(restricted grant)" not in text, text
            assert status != 124, ("copy timed out", text)
            assert (status == 0) == success, (status, text)
            if success:
                assert "receipt:" not in text.lower(), text
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)


print("case: source-shell remote copy requires approval even with automatic local receiving", flush=True)
run("syq", "recv", "on", "--approve", "always", "--notify", "off")
run("syq", "recv", "wait", "source", "--timeout", "30")
remote("mkdir -p /tmp/syq-real-ssh/forward")
copy("/tmp/syq-real-ssh/forward/denied", allow=False, success=False)
remote("test ! -e /tmp/syq-real-ssh/forward/denied")

print("case: approved copy uses direct encrypted TCP without source SSH credentials", flush=True)
trace = Path("/tmp/syq-real-ssh-ssh.trace")
def destination_connections():
    events = [dict(field.split("=", 1) for field in line.split("\t"))
              for line in trace.read_text().splitlines()]
    return sum(event["phase"] == "start" and event["host"] == "destination" for event in events)

before = destination_connections()
copy("/tmp/syq-real-ssh/forward/approved", extra=("--stats",))
assert destination_connections() - before == 1, "a cached helper must need only the copy's SSH connection"
expected = run("ssh", "source", "sha256sum /tmp/syq-real-ssh/return-source/subdir/chunks.bin").split()[0]
assert remote("sha256sum /tmp/syq-real-ssh/forward/approved").split()[0] == expected

print("case: a missing helper is installed once after its launcher reports the cache miss", flush=True)
helpers = remote('find "$HOME/.cache/syq/helpers" -type f -name syq').splitlines()
assert len(helpers) == 1, helpers
helper = shlex.quote(helpers[0])
remote("rm " + helper)
copy("/tmp/syq-real-ssh/forward/installed")
assert remote("sha256sum /tmp/syq-real-ssh/forward/installed").split()[0] == expected

print("case: an unexecutable cached helper gets one bootstrap retry", flush=True)
# A malformed ELF passes the launcher's executable-bit check but exec fails
# with 126. This is an actual exec failure, not a helper returning that code.
remote("python3 -c " + shlex.quote(
    "from pathlib import Path; p = Path(" + repr(helpers[0] + ".fixture") + "); "
    "p.write_bytes(b'\\x7fELF' + b'\\x00' * 64); p.chmod(0o700); p.replace(" + repr(helpers[0]) + ")"))
remote("sh -c " + shlex.quote("exec " + helper) + " 2>/dev/null; test \"$?\" -eq 126")
try:
    copy("/tmp/syq-real-ssh/forward/reinstalled")
    assert remote("sha256sum /tmp/syq-real-ssh/forward/reinstalled").split()[0] == expected
finally:
    remote("cp /usr/local/bin/syq " + helper + ".fixture && mv " + helper + ".fixture " + helper)

print("case: tilde paths use the destination home and ./~ stays literal", flush=True)
remote("mkdir -p ~/syq-real-ssh-forward-home './~/syq-real-ssh-forward-home'")
copy("~/syq-real-ssh-forward-home/expanded")
assert remote("sha256sum ~/syq-real-ssh-forward-home/expanded").split()[0] == expected
remote("test ! -e './~/syq-real-ssh-forward-home/expanded'")
copy("./~/syq-real-ssh-forward-home/literal")
assert remote("sha256sum './~/syq-real-ssh-forward-home/literal'").split()[0] == expected
remote("test ! -e ~/syq-real-ssh-forward-home/literal")

print("case: a delayed approval relay leaves time for the source to begin Hello", flush=True)
# Start the real helper, then hold its Approved reply for longer than the old
# 10-second deadline. Stream every subsequent control chunk without buffering.
delayed_helper = r'''#!/usr/bin/python3
import json
import os
import subprocess
import sys
import threading
import time

child = subprocess.Popen(['/usr/local/bin/syq', *sys.argv[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
def pump(reader, writer):
    while True:
        # Preserve any preamble bytes buffered while reading Approved, while
        # returning available control bytes without waiting for a full chunk.
        data = reader.read1(16384)
        if not data:
            break
        while data:
            count = os.write(writer, data)
            data = data[count:]
def send_input():
    try:
        pump(sys.stdin.buffer, child.stdin.fileno())
    except BrokenPipeError:
        pass
    finally:
        child.stdin.close()
threading.Thread(target=send_input, daemon=True).start()
header = child.stdout.read(4)
assert len(header) == 4
length = int.from_bytes(header, 'big')
assert 0 < length <= 256 * 1024
reply = child.stdout.read(length)
assert 'Approved' in json.loads(reply)
time.sleep(12)
sys.stdout.buffer.write(header + reply)
sys.stdout.buffer.flush()
pump(child.stdout, 1)
sys.exit(child.wait())
'''
remote("printf %s " + shlex.quote(delayed_helper) + " > " + helper + ".fixture && chmod 700 " + helper + ".fixture && mv " + helper + ".fixture " + helper)
try:
    copy("/tmp/syq-real-ssh/forward/delayed-hello")
    assert remote("sha256sum /tmp/syq-real-ssh/forward/delayed-hello").split()[0] == expected
finally:
    remote("cp /usr/local/bin/syq " + helper + ".fixture && mv " + helper + ".fixture " + helper)

print("case: an approved copy's slow SSH setup does not block the next approval", flush=True)
def deny_during_setup():
    command = "exec timeout 15 syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as during-forward-setup"
    process = subprocess.Popen(["ssh", "source", command], start_new_session=True)
    try:
        pending = json.loads(run("syq", "recv", "pending", "--json", "--wait", "--timeout", "3"))
        assert len(pending) == 1 and "during-forward-setup" in pending[0]["destination"], pending
        run("syq", "recv", "deny", pending[0]["id"])
        assert process.wait(timeout=5) not in (0, 124)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)

# The approval happens before the destination helper starts; keep that window
# open long enough to exercise another request on the same return connection.
remote("printf '%s\\n' '#!/bin/sh' 'sleep 10' 'exec /usr/local/bin/syq \"$@\"' > " + helper + ".fixture && chmod 700 " + helper + ".fixture && mv " + helper + ".fixture " + helper)
try:
    run("syq", "recv", "on", "--approve", "ask", "--notify", "off")
    run("syq", "recv", "wait", "source", "--timeout", "30")
    copy("/tmp/syq-real-ssh/forward/slow-setup", after_approval=deny_during_setup)
finally:
    remote("cp /usr/local/bin/syq " + helper + ".fixture && mv " + helper + ".fixture " + helper)

print("case: preview, verification, and protected paths remain restricted", flush=True)
copy("/tmp/syq-real-ssh/forward/preview", extra=("--dry-run",))
remote("test ! -e /tmp/syq-real-ssh/forward/preview")
copy("/tmp/syq-real-ssh/forward/approved", extra=("--verify-only",))
remote("printf '%s\\n' '# protected syq test fixture' > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys")
authorized = remote("sha256sum ~/.ssh/authorized_keys")
copy(".ssh/authorized_keys", success=False)
assert remote("sha256sum ~/.ssh/authorized_keys") == authorized

print("case: unreachable TCP fails without an SSH data fallback", flush=True)
port = os.environ["SYQ_REAL_SSH_BLOCKED_TCP_PORT"]
copy("/tmp/syq-real-ssh/forward/blocked", extra=("--tcp-ports", f"{port}-{port}"), success=False)
remote("test ! -e /tmp/syq-real-ssh/forward/blocked")

print("case: receiver restart revokes an active remote copy; a new approval can resume", flush=True)
source = "/tmp/syq-real-ssh/return-source/forward-resume.bin"
run("ssh", "source", f"dd if=/dev/urandom of={source} bs=1M count=16 status=none")
prefix = run("ssh", "source", f"dd if={source} bs=1M count=4 status=none | sha256sum")
expected = run("ssh", "source", f"sha256sum {source}").split()[0]
# Wait for a complete hash block, so the retry must actually reuse copied data.
copy("/tmp/syq-real-ssh/forward/cancelled", source=source, prefix=prefix,
     extra=("--bwlimit", "512"), cancel=True, success=False)
remote("test ! -e /tmp/syq-real-ssh/forward/cancelled")
run("syq", "recv", "wait", "source", "--timeout", "30")
results = "/tmp/syq-real-ssh/forward-resume.ndjson"
copy("/tmp/syq-real-ssh/forward/cancelled", source=source, extra=("--results", results))
records = [json.loads(line) for line in run("ssh", "source", f"cat {results}").splitlines()]
assert records[-1]["type"] == "result", records
assert records[-1]["bytes_unchanged"] >= 4 * 1024 * 1024, records[-1]
assert remote("sha256sum /tmp/syq-real-ssh/forward/cancelled").split()[0] == expected
assert not remote("find /tmp/syq-real-ssh/forward -type f -name '.cancelled.syq-part.*'")
print("source-shell remote copy checks passed", flush=True)
