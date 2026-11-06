"""Receiving switches to a new build without cutting an approved account connection in use.

The laptop receives with another build installed at a path of its own, and
the server opens an approved account connection through it. A shell runs
through that connection while the path is updated to this build: receiving
keeps the old build until the shell ends, then switches by itself and ends
the account connection, which nothing uses any more.
"""
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import time

NATIVE_PATH = "PATH=/usr/bin:/bin:/usr/local/bin"
BIN = Path("/tmp/syq-account-switch-bin")
OLD = BIN / "syq"
# Its own name: the suite's shared receiver is `laptop`.
NAME = "switching-laptop"
FAST = {"SYQ_TEST_SWITCH_CHECK_MS": "200", "SYQ_TEST_SWITCH_QUIET_MS": "1000"}


def run(*args, data=None, success=True, env=None):
    result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=60,
                            env=None if env is None else {**os.environ, **env})
    assert (result.returncode == 0) == success, (args, result)
    return result.stdout


def source(*args, success=True):
    return run("ssh", "source", shlex.join(["env", NATIVE_PATH, *args]), success=success)


def wait_for(description, predicate, timeout=60):
    deadline, progress = time.monotonic() + timeout, time.monotonic() + 5
    state = None
    while time.monotonic() < deadline:
        state = predicate()
        if state:
            return state
        if time.monotonic() >= progress:
            print("Waiting for", description, "last state:", state, flush=True)
            progress += 5
        time.sleep(.2)
    raise AssertionError(("Timed out", description, "last state", state))


def receiving(scope):
    state = json.loads(run("syq", "persist", "receive", "status", "--json", "--pscope", scope))
    (connection,) = state["connections"]
    return connection


def accounts_on_source():
    state = json.loads(source("syq", "persist", "status", "--json"))
    return [row for row in state.get("authorized_ssh", []) if row.get("connected")]


scope = run("syq", "persist", "on", "--ephemeral").strip()
other_build = run("syq-other-build", "--build-identity").strip()
this_build = run("syq", "--build-identity").strip()
root = Path("/tmp/syq-account-switch-receive")
shell = None
try:
    BIN.mkdir(mode=0o755, exist_ok=True)
    root.mkdir(exist_ok=True)
    shutil.copy2("/usr/local/bin/syq-other-build", OLD)
    run(str(OLD), "persist", "receive", "on", "--pscope", scope, "--name", NAME, "--notify", "off",
        "--root", str(root), "--all-connections", env=FAST)
    run(str(OLD), "persist", "connect", "source", "--pscope", scope, env=FAST)
    assert receiving(scope)["identity"] == other_build

    # The server opens an approved account connection through the laptop.
    args = ["env", NATIVE_PATH, "syq", "persist", "connect", "destination", "--auth-from", "@" + NAME]
    connecting = subprocess.Popen(["ssh", "source", shlex.join(args)], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, start_new_session=True)
    (request,) = json.loads(run(str(OLD), "persist", "receive", "pending", "--json", "--pscope", scope,
                                "--wait", "--timeout", "15"))
    assert request["kind"] == "ssh" and request["reusable"], request
    run(str(OLD), "persist", "receive", "approve", "--pscope", scope, request["id"])
    stdout, stderr = connecting.communicate(timeout=30)
    assert connecting.returncode == 0, (stdout, stderr)
    assert len(accounts_on_source()) == 1

    # A shell runs through it while syq is updated at the followed path.
    command = ["env", NATIVE_PATH, "syq", "ssh", "--auth-from", "@" + NAME, "destination", "--",
               "sleep 8; echo done"]
    shell = subprocess.Popen(["ssh", "source", shlex.join(command)], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, start_new_session=True)
    time.sleep(2)
    shutil.copy2("/usr/local/bin/syq", BIN / "syq.new")
    os.replace(BIN / "syq.new", OLD)

    # It keeps the old build while the shell runs, and says why.
    def waits_for_shell():
        connection = receiving(scope)
        busy = connection.get("busy") or {}
        return connection if busy.get("accounts_in_use") == 1 else None

    connection = wait_for("receiving to report the account connection in use", waits_for_shell, 20)
    assert connection["identity"] == other_build, connection
    stdout, stderr = shell.communicate(timeout=30)
    assert shell.returncode == 0 and stdout.strip() == "done", (stdout, stderr)
    shell = None

    # Once nothing uses it, receiving switches and the account connection ends.
    def switched():
        connection = receiving(scope)
        if connection["identity"] == this_build and connection["connection"]["phase"] == "online":
            return connection
        return None

    wait_for("receiving to switch to " + this_build, switched, 90)
    wait_for("the idle account connection to end", lambda: not accounts_on_source(), 20)
finally:
    if shell is not None and shell.poll() is None:
        os.killpg(shell.pid, signal.SIGTERM)
        shell.wait(timeout=5)
    subprocess.run(["ssh", "source", shlex.join(["env", NATIVE_PATH, "syq", "persist", "off"])],
                   timeout=60)
    subprocess.run(["syq", "persist", "off", "--pscope", scope], timeout=60)
    shutil.rmtree(BIN, ignore_errors=True)
    shutil.rmtree(root, ignore_errors=True)
