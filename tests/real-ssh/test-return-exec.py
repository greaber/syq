"""Approved commands over the laptop-initiated connection, in disposable paths."""
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time


def run(*args):
    return subprocess.check_output(args, text=True, timeout=40)


def ready():
    run("syq", "persist", "receive", "wait", "source", "--timeout", "30")


def wait_for(description, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.05)
    raise AssertionError(f"Timed out: {description}")


root = Path("/tmp/syq-real-ssh-receive/exec-fixture")
root.mkdir()
client_pid = "/tmp/syq-real-ssh/exec-client-pid"


def execute(argv, *, cwd="exec-fixture", allow=True, status=0, cancel=None, binary="syq"):
    command = ('test -z "${SSH_AUTH_SOCK:-}" && test ! -e ~/.ssh/id_ed25519 && '
               'echo $$ > ' + client_pid + ' && exec ' + shlex.join([
                   binary, "exec", "--on", "@laptop", "--cwd", cwd, "--", *argv]))
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(["ssh", "source", command], stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            pending = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
            assert len(pending) == 1, pending
            summary = pending[0]
            assert summary["kind"] == "command" and "destination" not in summary, summary
            assert "source" in summary["from"] and "local user" in summary["permission"], summary
            assert argv[0] in summary["argv"][0], summary
            assert process.poll() is None
            run("syq", "persist", "receive", "approve" if allow else "deny", summary["id"])
            if cancel:
                wait_for("running command", lambda: (root / "ready").exists())
                if cancel == "interrupt":
                    run("ssh", "source", "kill -INT $(cat " + client_pid + ")")
                else:
                    run("syq", "persist", "receive", "off")
            deadline = time.monotonic() + 30
            while True:
                try:
                    actual = process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    print("Waiting for approved command:", argv[0], flush=True)
                    assert time.monotonic() < deadline, "command exceeded fixture deadline"
            stdout.seek(0)
            stderr.seek(0)
            out, err = stdout.read(), stderr.read()
            assert actual == status, (actual, status, out, err)
            assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
            return out, err
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


print("case: exec always needs command approval, even with automatic copies", flush=True)
run("syq", "persist", "receive", "on", "--approve", "always", "--notify", "off")
ready()
execute(["sh", "-c", "touch denied"], allow=False, status=1)
assert not (root / "denied").exists()

print("case: literal argv, cwd, binary stdout/stderr and nonzero status cross real SSH", flush=True)
script = "import os,sys; assert sys.stdin.buffer.read() == b''; sys.stdout.buffer.write(os.getcwdb()+b'\\n'+os.fsencode(sys.argv[1])+b'\\x00\\xff'); sys.stderr.buffer.write(b'error\\x00\\xff'); sys.exit(17)"
argument = '$(touch injected) <b>&\n--help'
out, err = execute(["python3", "-c", script, argument], status=17)
assert out == os.fsencode(root) + b"\n" + argument.encode() + b"\x00\xff", out
assert err.endswith(b"error\x00\xff"), err
assert not (root / "injected").exists()

print("case: command from another source build preserves arguments, output and status", flush=True)
other_out, other_err = execute(["python3", "-c", script, argument], status=17, binary="syq-other-build")
assert other_out == out and other_err.endswith(b"error\x00\xff"), (other_out, other_err)
execute(["sh", "-c", "touch skew-denied"], allow=False, status=1, binary="syq-other-build")
assert not (root / "skew-denied").exists()

print("case: approved commands may run beyond the copy root", flush=True)
out, _ = execute(["pwd"], cwd="/tmp")
assert out == b"/tmp\n", out

print("case: execute the installed native syq binary", flush=True)
assert execute(["/usr/local/bin/syq", "--version"])[0] == run("syq", "--version").encode()

print("case: missing programs and signalled commands fail visibly", flush=True)
_, err = execute(["/no/such/syq-test-program"], status=1)
assert b"start approved command" in err, err
execute(["sh", "-c", "kill -TERM $$"], status=143)

print("case: both command output streams exceed pipe capacity without truncation", flush=True)
out, err = execute(["python3", "-c", "import sys; sys.stdout.buffer.write(b'o'*262144); sys.stderr.buffer.write(b'e'*262145)"])
assert out == b"o" * 262144
assert err.endswith(b"e" * 262145)

for cancellation in ["interrupt", "stop"]:
    print("case: command group cleanup after", cancellation, flush=True)
    script = "echo $$ > leader; (sleep 1; touch survived) & touch ready; wait"
    # OpenSSH reports the killed requesting client as exit-signal (255),
    # distinct from an executed program whose exit status syq returns normally.
    execute(["sh", "-c", script], status=255 if cancellation == "interrupt" else 1, cancel=cancellation)
    leader = int((root / "leader").read_text())
    def gone():
        try:
            os.kill(leader, 0)
            return False
        except ProcessLookupError:
            return True
    wait_for("command leader reaped", gone)
    time.sleep(1.1)
    assert not (root / "survived").exists()
    (root / "ready").unlink()
    if cancellation == "stop":
        run("syq", "persist", "receive", "on", "--notify", "off")
        ready()

print("case: exec works again after receiving restarts", flush=True)
assert execute(["printf", "reconnected"])[0] == b"reconnected"
print("Return command execution passed", flush=True)
