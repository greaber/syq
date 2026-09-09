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
    receive("on", "--name", "laptop", "--approve", "ask", "--notify", "off")
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
        receive("on", "--name", "laptop", "--root", str(other_root), "--notify", "off", env=other_env)
        receive("on", "--name", "other-client", "--root", str(other_root), "--notify", "off", "--approve", "always", env=other_env)
        conflict = run("syq", "persist", "connect", "source", "--timeout", "30", env=other_env, ok=False)
        assert conflict.returncode != 0 and "different receiver" in conflict.stderr, conflict
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
    finally:
        run("syq", "persist", "off", env=other_env)
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
    receive("remove", "project")
    receive("on", "--name", "laptop", "--approve", "always", "--notify", "off")
    receive("wait", "source", "--timeout", "30")
print("Multiple receiving profiles passed", flush=True)
