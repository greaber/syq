"""Independent profiles, live requests, and two clients sharing a server account."""
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time


def run(*args, env=None, ok=True):
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=45)
    if ok:
        assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result


def receive(*args, **kwargs):
    return run("syq", "persist", "receive", *args, **kwargs)


def state(env=None):
    return json.loads(receive("status", "--json", env=env).stdout)


def profile(name, env=None):
    return next(p for c in state(env)["connections"] if c["endpoint"] == "source"
                for p in c["profiles"] if p["settings"]["name"] == name)


def wait_for(description, predicate, timeout=15):
    deadline = time.monotonic() + timeout
    last = None
    progress = time.monotonic()
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        if time.monotonic() - progress >= 5:
            print(f"Waiting for {description}: {last!r}", flush=True)
            progress = time.monotonic()
        time.sleep(.1)
    raise AssertionError(f"Timed out waiting for {description}: {last!r}; {state()}")


def start_copy(name, target):
    return subprocess.Popen(["ssh", "source", shlex.join([
        "syq", "cp", "/tmp/syq-real-ssh/return-source/message.txt", "--to", "@" + name,
        "--as", target])], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)


def pending(count):
    def matching():
        requests = json.loads(receive("pending", "--json").stdout)
        return requests if len(requests) == count else None
    return wait_for(f"{count} pending requests", matching)


def finish(process, success=True):
    out, err = process.communicate(timeout=30)
    assert (process.returncode == 0) == success, (process.returncode, out, err)


print("case: independent profiles preserve live requests and isolated roots", flush=True)
processes = []
with tempfile.TemporaryDirectory(prefix="syq-profiles-") as directory:
    root = Path(directory)
    project = root / "project"
    project.mkdir()
    receive("on", "--name", "laptop", "--no-auto-approve-root", "--notify", "off")
    receive("wait", "source", "--name", "laptop", "--timeout", "30")
    original = profile("laptop")["connection"]["ssh_pid"]
    first = start_copy("laptop", "profiles-kept-pending")
    processes.append(first)
    request = pending(1)[0]
    receive("on", "--name", "project", "--root", str(project), "--notify", "off")
    receive("wait", "source", "--timeout", "30")
    assert profile("laptop")["connection"]["ssh_pid"] == original
    assert pending(1)[0]["id"] == request["id"]
    second = start_copy("project", "project-copy")
    processes.append(second)
    requests = pending(2)
    project_request = next(r for r in requests if "@project" in r["from"])
    assert "@laptop" in next(r for r in requests if r["id"] == request["id"])["from"]
    receive("approve", project_request["id"])
    finish(second)
    assert (project / "project-copy").read_bytes() == b"return\n"
    # Explicitly configuring the same profile still revokes that profile only.
    receive("on", "--name", "project", "--notify", "off")
    receive("wait", "source", "--name", "project", "--timeout", "30")
    assert profile("laptop")["connection"]["ssh_pid"] == original
    assert pending(1)[0]["id"] == request["id"]
    receive("approve", request["id"])
    finish(first)
    escaped = start_copy("project", "../escape")
    processes.append(escaped)
    finish(escaped, success=False)
    assert not (root / "escape").exists()

    print("case: scoped automatic downloads and server restrictions", flush=True)
    inbox = root / "inbox"
    inbox.mkdir()
    receive("on", "--name", "inbox", "--auto-approve-root", str(inbox),
            "--server", "source", "--notify", "off")
    receive("wait", "source", "--name", "inbox", "--timeout", "30")
    automatic = start_copy("inbox", "automatic")
    processes.append(automatic)
    finish(automatic)
    assert (inbox / "automatic").read_bytes() == b"return\n"
    assert json.loads(receive("pending", "--json").stdout) == []
    outside = start_copy("inbox", str(root / "approved-outside"))
    processes.append(outside)
    request = pending(1)[0]
    assert not (root / "approved-outside").exists()
    receive("approve", request["id"])
    finish(outside)
    assert (root / "approved-outside").read_bytes() == b"return\n"
    (inbox / "escape").symlink_to(root, target_is_directory=True)
    escaped = start_copy("inbox", "escape/must-ask")
    processes.append(escaped)
    receive("deny", pending(1)[0]["id"])
    finish(escaped, success=False)
    assert not (root / "must-ask").exists()
    # A hard root still rejects an outside destination before any prompt.
    receive("on", "--name", "inbox", "--root", str(root))
    receive("wait", "source", "--name", "inbox", "--timeout", "30")
    refused = start_copy("inbox", "../outside-hard-root")
    processes.append(refused)
    finish(refused, success=False)
    assert json.loads(receive("pending", "--json").stdout) == []
    # Withdrawing a server cancels its pending request and stops advertising.
    waiting = start_copy("inbox", "requires-approval")
    processes.append(waiting)
    pending(1)
    receive("on", "--name", "inbox", "--server", "another-server")
    finish(waiting, success=False)
    assert not any(p["settings"]["name"] == "inbox"
                   for c in state()["connections"] for p in c["profiles"])
    assert receive("wait", "source", "--name", "inbox", "--timeout", "1", ok=False).returncode != 0
    unavailable = start_copy("inbox", "unavailable")
    processes.append(unavailable)
    finish(unavailable, success=False)
    receive("on", "--name", "inbox", "--all-servers")
    receive("wait", "source", "--name", "inbox", "--timeout", "30")
    restored = start_copy("inbox", "inbox/restored")
    processes.append(restored)
    finish(restored)
    assert (inbox / "restored").read_bytes() == b"return\n"
    receive("remove", "inbox")

    print("case: live command survives changes to another profile", flush=True)
    script = "from pathlib import Path; import time; p=Path(" + repr(str(root)) + "); (p/'ready').touch(); deadline=time.monotonic()+30\nwhile not (p/'release').exists():\n assert time.monotonic()<deadline\n time.sleep(.1)\nprint('survived')"
    command = subprocess.Popen(["ssh", "source", shlex.join(["syq", "exec", "--on", "@laptop", "--", "python3", "-c", script])], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    processes.append(command)
    receive("approve", pending(1)[0]["id"])
    wait_for("running command", lambda: (root / "ready").exists())
    receive("off", "--name", "project")
    assert profile("laptop")["connection"]["ssh_pid"] == original
    assert command.poll() is None
    (root / "release").touch()
    finish(command)

    print("case: two clients can receive; duplicate name fails only that profile", flush=True)
    (root / "runtime").mkdir(mode=0o700)
    other_home = root / "other-home"
    other_home.mkdir(mode=0o700)
    other_env = dict(os.environ, HOME=str(other_home), XDG_CONFIG_HOME=str(root / "config"), XDG_RUNTIME_DIR=str(root / "runtime"))
    other_root = root / "other"
    other_root.mkdir()
    try:
        # First-ever connection while every profile excludes the server. Later
        # permission changes must activate receiving without another connect.
        for allow in [("--server", "source"), ("--all-servers",)]:
            print(f"case: first-time receiving activation with {allow[0]}", flush=True)
            receive("on", "--name", "other-client", "--root", str(other_root),
                    "--server", "another-server", "--notify", "off", env=other_env)
            run("syq", "persist", "connect", "source", "--timeout", "30", env=other_env)
            connection = next(c for c in json.loads(run("syq", "persist", "status", "--json", env=other_env).stdout)["connections"]
                              if c["endpoint"] == "source")
            assert connection["receiving_enabled"] is False, connection
            assert connection["state"] == "ready", connection
            assert not any(c["profiles"] for c in state(other_env)["connections"])
            receive("on", "--name", "other-client", *allow, env=other_env)
            receive("wait", "source", "--name", "other-client", "--timeout", "10", env=other_env)
            # Remove the connection and its service record before the next case.
            run("syq", "persist", "off", env=other_env)
        receive("on", "--name", "other-client", "--all-servers", env=other_env)
        receive("on", "--name", "laptop", "--root", str(other_root), "--notify", "off", env=other_env)
        receive("on", "--name", "other-client", "--root", str(other_root), "--notify", "off", "--auto-approve-root", str(other_root), env=other_env)
        conflict = run("syq", "persist", "connect", "source", "--timeout", "30", env=other_env, ok=False)
        assert conflict.returncode != 0 and "already connected" in conflict.stderr, conflict
        receive("wait", "source", "--name", "other-client", "--timeout", "30", env=other_env)
        assert profile("laptop", other_env)["connection"]["phase"] == "failed"
        assert profile("laptop")["connection"]["ssh_pid"] == original
        other_copy = start_copy("other-client", "received")
        processes.append(other_copy)
        finish(other_copy)
        assert (other_root / "received").read_bytes() == b"return\n"
        other_pid = profile("other-client", other_env)["connection"]["ssh_pid"]
        # Recovery retries the failed profile without restarting the healthy one.
        run("syq", "persist", "connect", "source", "--timeout", "30", env=other_env, ok=False)
        assert profile("other-client", other_env)["connection"]["ssh_pid"] == other_pid
        receive("remove", "laptop", env=other_env)
        run("syq", "persist", "connect", "source", env=other_env)
        # An SSH connection with no allowed receiving profiles is still usable.
        receive("on", "--name", "other-client", "--server", "another-server", env=other_env)
        run("syq", "persist", "connect", "source", "--timeout", "2", env=other_env)
        connection = next(c for c in json.loads(run("syq", "persist", "status", "--json", env=other_env).stdout)["connections"]
                          if c["endpoint"] == "source")
        assert connection["receiving_enabled"] is False, connection
        assert connection["state"] == "ready", connection
        receive("on", "--name", "other-client", "--server", "source", env=other_env)
        receive("wait", "source", "--name", "other-client", "--timeout", "30", env=other_env)
    finally:
        run("syq", "persist", "off", env=other_env)
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
    receive("remove", "project")
    receive("on", "--name", "laptop", "--auto-approve-root", "/tmp/syq-real-ssh-receive", "--notify", "off")
    receive("wait", "source", "--timeout", "30")
print("Multiple receiving profiles passed", flush=True)
