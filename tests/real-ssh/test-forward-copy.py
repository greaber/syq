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


def copy(path, *, allow=True, success=True, extra=(), cancel=False):
    argv = ["syq", "cp", "-vv", "/tmp/syq-real-ssh/return-source/subdir/chunks.bin", "--to", "destination",
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
            if cancel:
                deadline = time.monotonic() + 25
                progress = time.monotonic() + 5
                state = ""
                while time.monotonic() < deadline:
                    state = remote("find /tmp/syq-real-ssh/forward -type f -name '*.part'")
                    if state:
                        break
                    assert process.poll() is None, "copy exited before cancellation"
                    if time.monotonic() >= progress:
                        print("Waiting for remote copy partial:", repr(state), flush=True)
                        progress += 5
                    time.sleep(.1)
                assert state, ("no copy partial before deadline", state)
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
copy("/tmp/syq-real-ssh/forward/approved", extra=("--stats",))
expected = run("ssh", "source", "sha256sum /tmp/syq-real-ssh/return-source/subdir/chunks.bin").split()[0]
assert remote("sha256sum /tmp/syq-real-ssh/forward/approved").split()[0] == expected

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
copy("/tmp/syq-real-ssh/forward/cancelled", extra=("--bwlimit", "128"), cancel=True, success=False)
run("syq", "recv", "wait", "source", "--timeout", "30")
copy("/tmp/syq-real-ssh/forward/cancelled")
assert remote("sha256sum /tmp/syq-real-ssh/forward/cancelled").split()[0] == expected
print("source-shell remote copy checks passed", flush=True)
