"""Source-shell copies the runner approves for the destination's enrolled
receiver; all paths are disposable."""
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import tempfile
import time


def run(*args, success=True, stdin=None):
    result = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=40)
    assert (result.returncode == 0) == success, (args, result)
    return result.stdout


def remote(command, *, success=True):
    return run("ssh", "destination", command, success=success)


def copy(path, *, allow=True, success=True, extra=(), drop_laptop=False, interrupt=False,
         source="/tmp/syq-real-ssh/return-source/subdir/chunks.bin", prefix=None, after_approval=None, auth=(), binary="syq", stdin=None, ssh_trace=None,
         to="destination"):

    argv = [binary, "cp", "-vv", source, "--to", to,
            *auth, "--as", path, "--performance-tuning", "workers=2", *extra]
    if ssh_trace is not None:
        argv = ["env", "SYQ_REAL_SSH_TRACE_FILE=" + ssh_trace, *argv]
    command = "test -z \"${SSH_AUTH_SOCK:-}\" && test ! -e ~/.ssh/id_ed25519 && exec timeout 75 " + shlex.join(argv)
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(["ssh", "source", command], stdout=output, stderr=output,
                                   stdin=subprocess.PIPE if stdin is not None else None, start_new_session=True)
        try:
            if stdin is not None:
                process.stdin.write(stdin)
                process.stdin.close()
            pending = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
            assert len(pending) == 1, pending
            request = pending[0]
            assert f' on "{to}" using your SSH access' in request["destination"], request
            assert "syq's receiver" in request["permission"], request
            run("syq", "persist", "receive", "approve" if allow else "deny", request["id"])
            run("syq", "persist", "receive", "approve", request["id"], success=False)
            if after_approval is not None:
                after_approval()
            if drop_laptop or interrupt:
                deadline = time.monotonic() + 25
                progress = time.monotonic() + 5
                state = ""
                while time.monotonic() < deadline:
                    partials = remote("find /tmp/syq-real-ssh/forward -type f -name "
                                      + shlex.quote("." + path.rsplit("/", 1)[-1] + ".syq-tmp.*")).splitlines()
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
                if drop_laptop:
                    # The copy no longer needs this machine.
                    run("syq", "persist", "receive", "off", "--name", "laptop")
                else:
                    # Interrupting the command on the source stops its copy.
                    # Only this copy runs on the source; the pattern cannot
                    # match the shell that runs pkill.
                    run("ssh", "source", "pkill -TERM -f '^timeout 75 syq cp '")
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


print("case: automatic authorization falls back after source SSH fails and requires approval", flush=True)
run("syq", "persist", "receive", "on", "--auto-approve-root", "/tmp/syq-real-ssh-receive", "--notify", "off")
run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
remote("mkdir -p /tmp/syq-real-ssh/forward")
print("case: automatic authorization uses working source SSH without requesting approval", flush=True)
# Forwarding a credential does not also transfer host trust. Reuse the
# destination key already trusted by the runner in this isolated lab.
trusted_destination = run("ssh-keygen", "-F", "destination", "-f", str(Path.home() / ".ssh/known_hosts"))
run("ssh", "source", "umask 077; cat >> ~/.ssh/known_hosts", stdin=trusted_destination)
run("ssh", "-A", "source", "timeout 20 syq cp /tmp/syq-real-ssh/return-source/subdir/chunks.bin "
    "--to destination --as /tmp/syq-real-ssh/forward/source-ssh")
assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
assert remote("sha256sum /tmp/syq-real-ssh/forward/source-ssh").split()[0] == run(
    "ssh", "source", "sha256sum /tmp/syq-real-ssh/return-source/subdir/chunks.bin").split()[0]

print("case: a configured SSH handshake timeout never requests laptop approval", flush=True)
run("ssh", "source", "python3 -", stdin="""
from pathlib import Path
import subprocess
import time

config = Path.home() / ".ssh/config"
original = config.read_bytes() if config.exists() else None
try:
    config.write_bytes(b"Host syq-timeout-fixture\\n  HostName destination\\n  ProxyCommand sleep 10\\n  ConnectTimeout 1\\nHost *\\n" + (original or b""))
    started = time.monotonic()
    result = subprocess.run([
        "syq", "cp", "/tmp/syq-real-ssh/return-source/subdir/chunks.bin",
        "--to", "syq-timeout-fixture", "--as", "/tmp/syq-real-ssh/forward/timed-out",
    ], capture_output=True, text=True, timeout=8)
    print(result.stderr, end="", flush=True)
    assert result.returncode != 0, result
    assert "timed out" in result.stderr.lower(), result
    assert "requesting permission" not in result.stderr, result
    print("SSH timeout returned after", round(time.monotonic() - started, 2), "seconds", flush=True)
finally:
    if original is None:
        config.unlink()
    else:
        config.write_bytes(original)
""")
assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
remote("test ! -e /tmp/syq-real-ssh/forward/timed-out")

print("case: explicit SSH fails without source credentials and never requests approval", flush=True)
run("ssh", "source", "timeout 15 syq cp /tmp/syq-real-ssh/return-source/subdir/chunks.bin "
    "--to destination --as /tmp/syq-real-ssh/forward/direct-ssh --auth-from ssh", success=False)
assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
remote("test ! -e /tmp/syq-real-ssh/forward/direct-ssh")
copy("/tmp/syq-real-ssh/forward/denied", allow=False, success=False)
remote("test ! -e /tmp/syq-real-ssh/forward/denied")

print("case: approved copy uses direct encrypted TCP without source SSH credentials", flush=True)
trace = Path("/tmp/syq-real-ssh-ssh.trace")


def trace_events(text):
    return [dict(field.split("=", 1) for field in line.split("\t"))
            for line in text.splitlines()]


def trace_length():
    return len(trace.read_text().splitlines())


def runner_sessions_to_destination(start):
    # This machine's SSH connections to the destination since `start`,
    # other than reading its SSH configuration with -G.
    return [event for event in trace_events(trace.read_text())[start:]
            if event["phase"] == "start" and event["host"].rsplit("@", 1)[-1] == "destination"
            and event.get("query") != "yes"]


def alive(pid):
    # A process that ended but that nobody reaped yet counts as ended.
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
    except (OSError, IndexError):
        return False
    return state != "Z"


def setup_processes():
    found = []
    for entry in Path("/proc").iterdir():
        try:
            if entry.name.isdigit() and b"--return-prepare" in (entry / "cmdline").read_bytes():
                if alive(int(entry.name)):
                    found.append(int(entry.name))
        except OSError:
            pass
    return found


def wait_until(label, probe, seconds=20):
    deadline = time.monotonic() + seconds
    progress = time.monotonic() + 5
    last = None
    while time.monotonic() < deadline:
        done, last = probe()
        if done:
            return
        if time.monotonic() >= progress:
            print(f"Waiting for {label}: {last}", flush=True)
            progress += 5
        time.sleep(.1)
    raise AssertionError(f"{label} timed out; last state: {last}")


def destination_enrollments():
    return [line.split("\t")[0] for line in run("syq", "receiver", "list").splitlines()
            if "\tsyq@destination" in line]


def source_copy(*extra):
    argv = ["syq", "cp", "/tmp/syq-real-ssh/return-source/subdir/chunks.bin", "--to", "destination",
            "--as", "/tmp/syq-real-ssh/forward/first-use", "--no-progress", *extra]
    command = "test -z \"${SSH_AUTH_SOCK:-}\" && test ! -e ~/.ssh/id_ed25519 && exec timeout 75 " + shlex.join(argv)
    return subprocess.Popen(["ssh", "source", command], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, start_new_session=True)


print("case: a dry run is refused before approval while the destination is not enrolled", flush=True)
for enrollment in destination_enrollments():
    run("syq", "receiver", "revoke", enrollment)
preview = source_copy("--dry-run")
_, stderr = preview.communicate(timeout=90)
assert preview.returncode not in (0, 124), stderr
assert "a dry run does not set up restricted copying on syq@destination" in stderr, stderr
assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
assert destination_enrollments() == []

print("case: a first copy to a destination this machine has not seen follows its host-key setting", flush=True)
known_hosts = Path.home() / ".ssh/known_hosts"
trusted = known_hosts.read_bytes()
config = Path.home() / ".ssh/config"
original_config = config.read_bytes() if config.exists() else None
run("ssh-keygen", "-R", "destination", "-f", str(known_hosts))
try:
    # With StrictHostKeyChecking yes, this machine refuses a host it has not
    # seen, and nothing is enrolled.
    config.write_bytes(b"Host destination\n  StrictHostKeyChecking yes\n\n" + (original_config or b""))
    config.chmod(0o600)
    untrusted = source_copy()
    pending = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
    assert len(pending) == 1 and "Also sets up restricted copying" in pending[0]["permission"], pending
    run("syq", "persist", "receive", "approve", pending[0]["id"])
    _, stderr = untrusted.communicate(timeout=90)
    assert untrusted.returncode not in (0, 124), stderr
    assert "Host key verification failed" in stderr, stderr
    assert destination_enrollments() == []
    # With `ask`, the default (the lab's configuration says `yes`), nobody can
    # answer in the background: the key is accepted the first time and
    # recorded, as accept-new does, and the copy sets restricted copying up.
    config.write_bytes(b"Host destination\n  StrictHostKeyChecking ask\n\n" + (original_config or b""))
    config.chmod(0o600)
    first = source_copy()
    pending = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
    assert len(pending) == 1 and "Also sets up restricted copying" in pending[0]["permission"], pending
    run("syq", "persist", "receive", "approve", pending[0]["id"])
    _, stderr = first.communicate(timeout=90)
    assert first.returncode == 0, stderr
    assert subprocess.run(["ssh-keygen", "-F", "destination", "-f", str(known_hosts)],
                          capture_output=True).returncode == 0
    assert len(destination_enrollments()) == 1
finally:
    known_hosts.write_bytes(trusted)
    if original_config is None:
        config.unlink(missing_ok=True)
    else:
        config.write_bytes(original_config)
assert remote("sha256sum /tmp/syq-real-ssh/forward/first-use").split()[0] == run(
    "ssh", "source", "sha256sum /tmp/syq-real-ssh/return-source/subdir/chunks.bin").split()[0]

# The source has its own trace filesystem. Give this copy a separate file so
# an older source session's background activity cannot enter the assertion.
source_trace = run("ssh", "source", "mktemp /tmp/syq-real-ssh/forward-ssh.XXXXXX").strip()
try:
    copy("/tmp/syq-real-ssh/forward/approved", extra=("--stats",), ssh_trace=source_trace)
    events = trace_events(run("ssh", "source", "cat " + shlex.quote(source_trace)))
    # RemoteSpec sets ControlMaster on every transport connection. The same
    # process also runs ssh -G to read config, for the receiver too; those
    # queries never connect.
    attempts = [event for event in events
                if event["phase"] == "start" and event["host"] == "destination"
                and event["control_master"] != "unset" and event["entry_key"] == "no"
                and event.get("query") != "yes"]
    assert len(attempts) == 1, ("expected one source SSH attempt", events)
    exits = [event for event in events
             if event["phase"] == "end" and event["pid"] == attempts[0]["pid"]]
    assert len(exits) == 1 and exits[0]["status"] == "255", events
    # The source then connects to the destination's receiver itself, with
    # the entry key the runner handed it.
    receiver = [event for event in events
                if event["phase"] == "end" and event["entry_key"] == "yes"]
    assert receiver and all(event["status"] == "0" for event in receiver), events
finally:
    run("ssh", "source", "rm -f " + shlex.quote(source_trace))
expected = run("ssh", "source", "sha256sum /tmp/syq-real-ssh/return-source/subdir/chunks.bin").split()[0]
assert remote("sha256sum /tmp/syq-real-ssh/forward/approved").split()[0] == expected

assert "syq-enrollment:" in remote("cat ~/.ssh/authorized_keys")
assert "syq-copy-worker" not in remote("cat ~/.ssh/authorized_keys")

print("case: explicit automatic selection uses restricted fallback", flush=True)
for option, name in [("--auth-from", "selected")]:
    start = trace_length()
    copy("/tmp/syq-real-ssh/forward/" + name, auth=(option, "auto"))
    # With the destination enrolled, the runner only signs: the server
    # connects to the destination itself, and nothing goes through here.
    assert runner_sessions_to_destination(start) == [], "the runner logged in to the destination"
    assert remote("sha256sum /tmp/syq-real-ssh/forward/" + name).split()[0] == expected

print("case: another source build hands off automatic and explicit authorization", flush=True)
for auth in [(), ("--auth-from", "auto")]:
    name = "skew-explicit" if auth else "skew-auto"
    copy("/tmp/syq-real-ssh/forward/" + name, auth=auth, binary="syq-other-build")
    assert remote("sha256sum /tmp/syq-real-ssh/forward/" + name).split()[0] == expected

print("case: automatic and explicit authorization preserve piped ignore rules across builds", flush=True)
for auth in [(), ("--auth-from", "auto")]:
    name = "filtered-explicit" if auth else "filtered-auto"
    path = "/tmp/syq-real-ssh/forward/" + name
    copy(path, auth=auth, binary="syq-other-build", source="/tmp/syq-real-ssh/return-source",
         extra=("--follow", "--ignore-from", "/dev/stdin"), stdin=b"*.bin\n")
    assert remote("cat " + path + "/message.txt") == "return\n"
    remote("test ! -e " + path + "/subdir/chunks.bin")

print("case: tilde paths use the destination home and ./~ stays literal", flush=True)
remote("mkdir -p ~/syq-real-ssh-forward-home './~/syq-real-ssh-forward-home'")
copy("~/syq-real-ssh-forward-home/expanded")
assert remote("sha256sum ~/syq-real-ssh-forward-home/expanded").split()[0] == expected
remote("test ! -e './~/syq-real-ssh-forward-home/expanded'")
copy("./~/syq-real-ssh-forward-home/literal")
assert remote("sha256sum './~/syq-real-ssh-forward-home/literal'").split()[0] == expected
remote("test ! -e ~/syq-real-ssh-forward-home/literal")

print("case: an approved copy's slow SSH setup does not block the next approval", flush=True)
def deny_during_setup():
    command = "exec timeout 15 syq cp /tmp/syq-real-ssh/return-source/message.txt --to @laptop --as during-forward-setup"
    process = subprocess.Popen(["ssh", "source", command], start_new_session=True)
    try:
        pending = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "3"))
        assert len(pending) == 1 and "during-forward-setup" in pending[0]["destination"], pending
        run("syq", "persist", "receive", "deny", pending[0]["id"])
        assert process.wait(timeout=5) not in (0, 124)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)

# Reading the destination's SSH configuration after approval is slow here;
# keep that window open long enough to exercise another request on the same
# return connection.
Path("/tmp/syq-real-ssh-slow-config").touch()
try:
    run("syq", "persist", "receive", "on", "--no-auto-approve-root", "--notify", "off")
    run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
    copy("/tmp/syq-real-ssh/forward/slow-setup", after_approval=deny_during_setup)
finally:
    Path("/tmp/syq-real-ssh-slow-config").unlink()

print("case: previews and protected paths remain restricted", flush=True)
copy("/tmp/syq-real-ssh/forward/preview", extra=("--dry-run",))
remote("test ! -e /tmp/syq-real-ssh/forward/preview")
copy("/tmp/syq-real-ssh/forward/approved", extra=("--dry-run", "--hash",))
source_hash = run("ssh", "source", "sha256sum /tmp/syq-real-ssh/return-source/subdir/chunks.bin").split()[0]
assert remote("sha256sum /tmp/syq-real-ssh/forward/approved").split()[0] == source_hash
authorized = remote("sha256sum ~/.ssh/authorized_keys")
copy(".ssh/authorized_keys", success=False)
assert remote("sha256sum ~/.ssh/authorized_keys") == authorized

print("case: approved copies keep ownership and special files as an ordinary account", flush=True)
# Outside the shared return-source tree, which later cases copy whole.
run("ssh", "source", "mkdir -p /tmp/syq-real-ssh/forward-specials && mkfifo /tmp/syq-real-ssh/forward-specials/pipe")
copy("/tmp/syq-real-ssh/forward/pipe", source="/tmp/syq-real-ssh/forward-specials/pipe",
     extra=("--copy-metadata=mtime,ownership,specials",))
remote("test -p /tmp/syq-real-ssh/forward/pipe")

print("case: approved copies prune within the laptop's own limit", flush=True)
run("ssh", "source", "mkdir -p /tmp/syq-real-ssh/forward-prune-source && printf kept > /tmp/syq-real-ssh/forward-prune-source/kept")
remote("mkdir -p /tmp/syq-real-ssh/forward/pruned && cd /tmp/syq-real-ssh/forward/pruned && "
       "printf kept > kept && printf extra > extra-1 && printf extra > extra-2")
run("syq", "persist", "receive", "on", "--max-delete", "1", "--notify", "off")
run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
try:
    # Two planned deletions exceed the laptop's limit of one: none happen,
    # and a dry run, whose grant deletes nothing, predicts that.
    for extra in [("--prune", "--dry-run"), ("--prune",)]:
        copy("/tmp/syq-real-ssh/forward/pruned", source="/tmp/syq-real-ssh/forward-prune-source",
             extra=extra, success=False)
        remote("test -e /tmp/syq-real-ssh/forward/pruned/extra-1 && test -e /tmp/syq-real-ssh/forward/pruned/extra-2")
    remote("rm /tmp/syq-real-ssh/forward/pruned/extra-2")
    copy("/tmp/syq-real-ssh/forward/pruned", source="/tmp/syq-real-ssh/forward-prune-source",
         extra=("--prune", "--dry-run"))
    remote("test -e /tmp/syq-real-ssh/forward/pruned/extra-1")
    copy("/tmp/syq-real-ssh/forward/pruned", source="/tmp/syq-real-ssh/forward-prune-source",
         extra=("--prune",))
    remote("test ! -e /tmp/syq-real-ssh/forward/pruned/extra-1 && test -e /tmp/syq-real-ssh/forward/pruned/kept")
    # With pruning off on the laptop, the copy is refused before it asks for
    # approval, and so is its dry run, the same way, with nothing to delete.
    run("syq", "persist", "receive", "on", "--max-delete", "0", "--notify", "off")
    run("syq", "persist", "receive", "wait", "source", "--timeout", "30")

    def refused(*extra):
        argv = ["syq", "cp", "/tmp/syq-real-ssh/forward-prune-source", "--to", "destination",
                "--as", "/tmp/syq-real-ssh/forward/pruned", "--no-progress", *extra]
        command = "test -z \"${SSH_AUTH_SOCK:-}\" && test ! -e ~/.ssh/id_ed25519 && exec timeout 75 " + shlex.join(argv)
        result = subprocess.run(["ssh", "source", command], capture_output=True, text=True, timeout=90)
        assert result.returncode not in (0, 124), result
        reasons = [line for line in result.stderr.splitlines() if "pruning needs a positive --max-delete" in line]
        assert reasons, result
        assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == [], result
        return result.returncode, reasons
    assert refused("--prune", "--dry-run") == refused("--prune")
finally:
    run("syq", "persist", "receive", "on", "--max-delete", "0", "--notify", "off")
    run("syq", "persist", "receive", "wait", "source", "--timeout", "30")

print("case: unreachable TCP falls back to direct restricted SSH data", flush=True)
port = os.environ["SYQ_REAL_SSH_BLOCKED_TCP_PORT"]
started = time.monotonic()
copy("/tmp/syq-real-ssh/forward/blocked", extra=("--tcp-ports", f"{port}-{port}"))
print("cold approved SSH fallback including approval polling:", round(time.monotonic() - started, 3), "seconds", flush=True)
assert remote("sha256sum /tmp/syq-real-ssh/forward/blocked").split()[0] == source_hash
assert remote("sha256sum ~/.ssh/authorized_keys") == authorized

print("case: explicit SSH uses the entry key without source credentials", flush=True)
copy("/tmp/syq-real-ssh/forward/ssh", extra=("--no-tcp",), auth=("--auth-from", "auto"))
assert remote("sha256sum /tmp/syq-real-ssh/forward/ssh").split()[0] == source_hash
assert remote("sha256sum ~/.ssh/authorized_keys") == authorized

print("case: an approved copy finishes after receiving stops on the runner", flush=True)
source = "/tmp/syq-real-ssh/return-source/forward-resume.bin"
run("ssh", "source", f"dd if=/dev/urandom of={source} bs=1M count=16 status=none")
prefix = run("ssh", "source", f"dd if={source} bs=1M count=4 status=none | sha256sum")
expected = run("ssh", "source", f"sha256sum {source}").split()[0]
copy("/tmp/syq-real-ssh/forward/survived", source=source, prefix=prefix,
     extra=("--resource-limits", "bandwidth=2048"), drop_laptop=True)
assert remote("sha256sum /tmp/syq-real-ssh/forward/survived").split()[0] == expected
run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off")
run("syq", "persist", "receive", "wait", "source", "--timeout", "30")

print("case: interrupting the source's command stops its copy; a new approval resumes it", flush=True)
# Wait for a complete hash block, so the retry must actually reuse copied data.
copy("/tmp/syq-real-ssh/forward/cancelled", source=source, prefix=prefix,
     extra=("--resource-limits", "bandwidth=512"), interrupt=True, success=False)
remote("test ! -e /tmp/syq-real-ssh/forward/cancelled")
results = "/tmp/syq-real-ssh/forward-resume.ndjson"
copy("/tmp/syq-real-ssh/forward/cancelled", source=source, extra=("--results", results))
records = [json.loads(line) for line in run("ssh", "source", f"cat {results}").splitlines()]
assert records[-1]["type"] == "result", records
assert records[-1]["bytes_unchanged"] >= 4 * 1024 * 1024, records[-1]
assert remote("sha256sum /tmp/syq-real-ssh/forward/cancelled").split()[0] == expected
assert len(remote("find /tmp/syq-real-ssh/forward -type f -name '.cancelled.syq-tmp.*'").splitlines()) == 1
run("syq", "clean-partials", "--on", "destination", "/tmp/syq-real-ssh/forward")
assert not remote("find /tmp/syq-real-ssh/forward -type f -name '.cancelled.syq-tmp.*'")
assert remote("sha256sum /tmp/syq-real-ssh/forward/cancelled").split()[0] == expected
print("case: a requester that goes while its approval enrolls ends the setup and frees it", flush=True)
for enrollment in destination_enrollments():
    run("syq", "receiver", "revoke", enrollment)
hold = Path("/tmp/syq-real-ssh-hold-enrollment")
waiting = Path("/tmp/syq-real-ssh-hold-enrollment.waiting")
waiting.unlink(missing_ok=True)
hold.touch()
try:
    held = source_copy()
    try:
        pending = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
        assert len(pending) == 1, pending
        run("syq", "persist", "receive", "approve", pending[0]["id"])
        wait_until("the enrolling login", lambda: (waiting.exists(), setup_processes()))
        login = int(waiting.read_text())
        assert alive(login) and setup_processes()
        # The requesting command goes away on the source.
        run("ssh", "source", "pkill -TERM -f '^timeout 75 syq cp '")
        _, stderr = held.communicate(timeout=30)
        assert held.returncode not in (0, 124), stderr
    finally:
        if held.poll() is None:
            os.killpg(held.pid, signal.SIGKILL)
            held.wait(timeout=3)
    # The setup child and the login it held end with it, well before the
    # setup deadline.
    wait_until("the setup to end", lambda: (not alive(login) and not setup_processes(),
                                             (alive(login), setup_processes())), seconds=10)
    assert destination_enrollments() == []
finally:
    hold.unlink(missing_ok=True)
    waiting.unlink(missing_ok=True)
# The enrollment lock and the request's slot are free again: the next
# approval sets restricted copying up.
copy("/tmp/syq-real-ssh/forward/after-held-setup")
assert remote("sha256sum /tmp/syq-real-ssh/forward/after-held-setup").split()[0] == source_hash
assert len(destination_enrollments()) == 1

class ForwardingListener:
    """An SSH listener on the source that permits forwarding, which the lab's
    own servers refuse, trusted by the runner while it runs."""

    def __init__(self, trust=True):
        self.trust = trust

    def __enter__(self):
        self.listener = json.loads(run("ssh", "source", "python3 -", stdin="""
import json, pathlib, socket, subprocess, tempfile
root = pathlib.Path(tempfile.mkdtemp(prefix="syq-real-ssh-jump-"))
key = root / "host_key"
subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
with socket.socket() as probe:
    probe.bind(("0.0.0.0", 0))
    port = probe.getsockname()[1]
config = root / "sshd_config"
config.write_text("\\n".join([
    "Port " + str(port), "ListenAddress 0.0.0.0", "AddressFamily inet", "HostKey " + str(key),
    "PidFile " + str(root / "sshd.pid"), "AuthorizedKeysFile /etc/ssh/lab_authorized_keys",
    "StrictModes yes", "AllowUsers syq", "AuthenticationMethods publickey", "PubkeyAuthentication yes",
    "PasswordAuthentication no", "KbdInteractiveAuthentication no", "UsePAM no", "UseDNS no",
    "AllowAgentForwarding no", "AllowTcpForwarding local", "X11Forwarding no", "PermitTTY no",
    "LogLevel VERBOSE", "",
]))
subprocess.run(["/usr/sbin/sshd", "-f", str(config), "-E", str(root / "sshd.log")], check=True)
print(json.dumps({"root": str(root), "port": port,
                  "key": " ".join(key.with_suffix(".pub").read_text().split()[:2])}))
"""))
        self.port = self.listener["port"]
        self.known_hosts = Path.home() / ".ssh/known_hosts"
        self.trusted = self.known_hosts.read_bytes()
        try:
            def listening():
                try:
                    with socket.create_connection(("source", self.port), timeout=.5):
                        return True, "listening"
                except OSError as error:
                    return False, str(error)
            wait_until("the jump listener", listening)
            if self.trust:
                with self.known_hosts.open("a") as hosts:
                    hosts.write(f"[source]:{self.port} {self.listener['key']}\n")
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def logins(self):
        log = shlex.quote(self.listener["root"] + "/sshd.log")
        return int(run("ssh", "source", f"grep -c 'Accepted publickey' {log} || true").strip() or 0)

    def __exit__(self, *_):
        self.known_hosts.write_bytes(self.trusted)
        run("ssh", "source", "kill $(cat " + shlex.quote(self.listener["root"] + "/sshd.pid") + "); rm -rf "
            + shlex.quote(self.listener["root"]))


def enrollment_events(start):
    events = trace_events(trace.read_text())[start:]
    ends = {event["pid"]: event for event in events if event["phase"] == "end"}
    starts = [event for event in events if event["phase"] == "start" and event.get("query") != "yes"]
    logins = [(event, ends[event["pid"]]["status"]) for event in starts if event.get("enrollment") == "yes"]
    return ([status for event, status in logins if event.get("via") == "no"],
            [status for event, status in logins if event.get("via") == "yes"],
            [event for event in starts if event.get("jump") == "yes"])


print("case: enrolling follows the runner's configured jump host", flush=True)
for enrollment in destination_enrollments():
    run("syq", "receiver", "revoke", enrollment)
config = Path.home() / ".ssh/config"
original = config.read_bytes() if config.exists() else None
with ForwardingListener() as listener:
    try:
        config.write_bytes(f"Host destination\n  ProxyJump syq@source:{listener.port}\n\n".encode()
                           + (original or b""))
        config.chmod(0o600)
        start = trace_length()
        copy("/tmp/syq-real-ssh/forward/configured-jump")
        configured, via, jumps = enrollment_events(start)
        assert len(destination_enrollments()) == 1
        # Enrolling from the command line takes the same route, and the
        # jump's own SSH trace stays out of the terminal.
        for enrollment in destination_enrollments():
            run("syq", "receiver", "revoke", enrollment)
        before = listener.logins()
        enrolled = subprocess.run(["syq", "receiver", "enroll", "destination"],
                                  capture_output=True, text=True, timeout=90)
        assert enrolled.returncode == 0, enrolled
        assert "debug1:" not in enrolled.stderr and "debug3:" not in enrolled.stderr, enrolled.stderr
        assert listener.logins() > before
    finally:
        if original is None:
            config.unlink()
        else:
            config.write_bytes(original)
        # OpenSSH starts a configured jump with its own path, not the lab's
        # wrapper: the jump listener's log shows it instead.
        jumped = listener.logins()
# The runner's own login went through the configured jump and set
# restricted copying up; nothing needed the retry through the server.
assert configured and all(status == "0" for status in configured), (configured, via, jumps)
assert via == [] and jumped >= 1, (configured, via, jumped)
assert remote("sha256sum /tmp/syq-real-ssh/forward/configured-jump").split()[0] == source_hash
assert len(destination_enrollments()) == 1

def receive_service_pids():
    found = []
    for entry in Path("/proc").iterdir():
        try:
            if entry.name.isdigit() and b"--receive-service" in (entry / "cmdline").read_bytes().split(b"\0"):
                if alive(int(entry.name)):
                    found.append(int(entry.name))
        except OSError:
            pass
    return found


def restart_receiving(environment):
    """Start the receiving service again, with `environment` added."""
    run("syq", "persist", "receive", "off")
    try:
        wait_until("the receiving service to stop", lambda: (not receive_service_pids(), receive_service_pids()),
                   seconds=15)
    except AssertionError:
        for pid in receive_service_pids():
            os.kill(pid, signal.SIGTERM)
        wait_until("the receiving service to end", lambda: (not receive_service_pids(), receive_service_pids()))
    result = subprocess.run(["syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off"],
                            env=dict(os.environ, **environment), capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, result
    run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
    pids = receive_service_pids()
    assert pids, "no receiving service"
    environ = Path(f"/proc/{pids[0]}/environ").read_bytes().split(b"\0")
    for name, value in environment.items():
        assert f"{name}={value}".encode() in environ, (name, environ)


print("case: the retry through the server that asked follows the host-key setting for it and never prompts", flush=True)
for enrollment in destination_enrollments():
    run("syq", "receiver", "revoke", enrollment)
askpass_root = Path(tempfile.mkdtemp(prefix="syq-real-ssh-askpass-"))
askpass = askpass_root / "askpass"
askpass_used = askpass_root / "used"
askpass.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(askpass_used))}\necho yes\n")
askpass.chmod(0o755)
restart_receiving({"SSH_ASKPASS": str(askpass), "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": "fixture"})
jump_port = Path("/tmp/syq-real-ssh-jump-port")
unreachable = Path("/tmp/syq-real-ssh-unreachable-direct")
config = Path.home() / ".ssh/config"
original = config.read_bytes() if config.exists() else None
known_hosts = Path.home() / ".ssh/known_hosts"
try:
    with ForwardingListener(trust=False) as listener:
        try:
            jump_port.write_text(str(listener.port))
            unreachable.touch()
            hosts = known_hosts.read_bytes()
            # With StrictHostKeyChecking yes for the server, the jump's new
            # key is refused, and nothing is recorded or asked.
            config.write_bytes(b"Host source\n  StrictHostKeyChecking yes\n\n" + (original or b""))
            config.chmod(0o600)
            refused = source_copy()
            pending = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
            assert len(pending) == 1, pending
            run("syq", "persist", "receive", "approve", pending[0]["id"])
            _, stderr = refused.communicate(timeout=120)
            assert refused.returncode not in (0, 124), stderr
            # The hop's own reason reaches the requester.
            assert "Host key verification failed" in stderr, stderr
            assert known_hosts.read_bytes() == hosts
            assert destination_enrollments() == []
            assert listener.logins() == 0
            # With `ask`, the default (the lab's configuration says `yes`),
            # the key is accepted the first time and recorded, and the copy
            # goes through the jump.
            config.write_bytes(b"Host source\n  StrictHostKeyChecking ask\n\n" + (original or b""))
            config.chmod(0o600)
            accepted = source_copy()
            pending = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
            assert len(pending) == 1, pending
            run("syq", "persist", "receive", "approve", pending[0]["id"])
            _, stderr = accepted.communicate(timeout=120)
            assert accepted.returncode == 0, stderr
            assert subprocess.run(["ssh-keygen", "-F", f"[source]:{listener.port}", "-f", str(known_hosts)],
                                  capture_output=True).returncode == 0
            assert listener.logins() >= 1
            assert len(destination_enrollments()) == 1
            assert not askpass_used.exists()
        finally:
            unreachable.unlink(missing_ok=True)
            jump_port.unlink(missing_ok=True)
            if original is None:
                config.unlink(missing_ok=True)
            else:
                config.write_bytes(original)
finally:
    restart_receiving({})

print("case: enrolling goes through the server that asked when the runner cannot reach the destination", flush=True)
for enrollment in destination_enrollments():
    run("syq", "receiver", "revoke", enrollment)
jump_port = Path("/tmp/syq-real-ssh-jump-port")
unreachable = Path("/tmp/syq-real-ssh-unreachable-direct")
with ForwardingListener() as listener:
    try:
        jump_port.write_text(str(listener.port))
        unreachable.touch()
        start = trace_length()
        copy("/tmp/syq-real-ssh/forward/through-server")
        configured, via, jumps = enrollment_events(start)
    finally:
        unreachable.unlink(missing_ok=True)
        jump_port.unlink(missing_ok=True)
assert configured and all(status == "255" for status in configured), (configured, via, jumps)
assert via and via[-1] == "0" and jumps, (configured, via, jumps)
assert remote("sha256sum /tmp/syq-real-ssh/forward/through-server").split()[0] == source_hash
assert len(destination_enrollments()) == 1

print("case: an outdated enrollment refuses a dry run before approval, and approving updates it", flush=True)
records = [(path.parent, json.loads(path.read_bytes()))
           for path in (Path.home() / ".local/state/syq/enrollments").glob("*/enrollment.json")]
directories = [directory for directory, record in records if record["host"] == "destination"]
assert len(directories) == 1, records
refreshing = directories[0] / "refreshing"
refreshing.touch(mode=0o600)
preview = source_copy("--dry-run")
_, stderr = preview.communicate(timeout=90)
assert preview.returncode not in (0, 124), stderr
assert "a dry run does not update syq on syq@destination" in stderr, stderr
assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
updating = source_copy()
pending = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
assert len(pending) == 1 and 'Also updates restricted copying on "destination"' in pending[0]["permission"], pending
run("syq", "persist", "receive", "approve", pending[0]["id"])
_, stderr = updating.communicate(timeout=90)
assert updating.returncode == 0, stderr
assert not refreshing.exists()
def source_known_hosts():
    return run("ssh", "source", "cat ~/.ssh/known_hosts 2>/dev/null || true")


def restore_source_known_hosts(text):
    run("ssh", "source", "umask 077; cat > ~/.ssh/known_hosts", stdin=text)


def source_knows(name):
    return subprocess.run(["ssh", "source", f"ssh-keygen -F {shlex.quote(name)} >/dev/null"],
                          timeout=40).returncode == 0


def with_source_config(text, action):
    """Run `action` with `text` first in the source's SSH configuration."""
    original = run("ssh", "source", "cat ~/.ssh/config 2>/dev/null || true")
    run("ssh", "source", "umask 077; cat > ~/.ssh/config", stdin=text + "\n" + original)
    try:
        return action()
    finally:
        run("ssh", "source", "umask 077; cat > ~/.ssh/config", stdin=original)


print("case: the server checks the destination's key with its own SSH configuration", flush=True)
assert len(destination_enrollments()) == 1
saved_source = source_known_hosts()
known_hosts = Path.home() / ".ssh/known_hosts"
saved_runner = known_hosts.read_bytes()
try:
    # Neither machine knows the destination: the server accepts its key the
    # first time and records it, as accept-new does for the default `ask`.
    run("ssh", "source", "ssh-keygen -R destination >/dev/null 2>&1 || true")
    run("ssh-keygen", "-R", "destination", "-f", str(known_hosts))
    assert not source_knows("destination")
    copy("/tmp/syq-real-ssh/forward/hostkey-first-use")
    assert source_knows("destination")
    print("the server recorded a destination neither machine knew", flush=True)

    # A key the server knows that contradicts the one presented, with
    # nothing else known: refused, naming the server's file.
    restore_source_known_hosts(saved_source)
    run("ssh", "source", "ssh-keygen -R destination >/dev/null 2>&1 || true; "
        "rm -f /tmp/syq-real-ssh-wrong-key*; ssh-keygen -q -t ed25519 -N '' -f /tmp/syq-real-ssh-wrong-key && "
        "printf 'destination %s\\n' \"$(cut -d' ' -f1,2 /tmp/syq-real-ssh-wrong-key.pub)\" >> ~/.ssh/known_hosts")
    changed = source_copy()
    pending = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
    assert len(pending) == 1, pending
    run("syq", "persist", "receive", "approve", pending[0]["id"])
    _, stderr = changed.communicate(timeout=90)
    assert changed.returncode not in (0, 124), stderr
    assert "Host key verification failed" in stderr, stderr
    assert "/.ssh/known_hosts" in stderr, stderr
    print("a key that contradicts the server's own was refused", flush=True)

    # A key only the runner knows that contradicts the one presented:
    # refused, and the copy says to fix the runner's known_hosts, since
    # OpenSSH names the runner's entries by a label no file has.
    run("ssh", "source", "ssh-keygen -R destination >/dev/null 2>&1 || true")
    wrong = run("ssh", "source", "cut -d' ' -f1,2 /tmp/syq-real-ssh-wrong-key.pub").strip()
    run("ssh-keygen", "-R", "destination", "-f", str(known_hosts))
    with known_hosts.open("a") as hosts:
        hosts.write(f"destination {wrong}\n")
    changed = source_copy()
    pending = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
    assert len(pending) == 1, pending
    run("syq", "persist", "receive", "approve", pending[0]["id"])
    _, stderr = changed.communicate(timeout=90)
    assert changed.returncode not in (0, 124), stderr
    assert "Host key verification failed" in stderr, stderr
    assert ("the approving machine's known_hosts lists a different key for destination; "
            "if that key is out of date, remove it there with `ssh-keygen -R destination`") in stderr, stderr
    assert not source_knows("destination")
    print("a key only the runner knows that contradicts the one presented was refused", flush=True)

    # What either machine knows is accepted: the runner's key for the
    # destination wins over the server's stale one, and over its strict
    # setting for a host it does not know, without recording anything there.
    known_hosts.write_bytes(saved_runner)
    copy("/tmp/syq-real-ssh/forward/hostkey-union-stale")
    run("ssh", "source", "ssh-keygen -R destination >/dev/null 2>&1 || true")
    with_source_config("Host destination\n  StrictHostKeyChecking yes\n",
                       lambda: copy("/tmp/syq-real-ssh/forward/hostkey-union-strict"))
    assert not source_knows("destination")
    print("the server accepted what the approving machine knows", flush=True)
finally:
    restore_source_known_hosts(saved_source)
    known_hosts.write_bytes(saved_runner)
for name in ["hostkey-first-use", "hostkey-union-stale", "hostkey-union-strict"]:
    assert remote(f"sha256sum /tmp/syq-real-ssh/forward/{name}").split()[0] == source_hash

print("case: a destination trusted only through a host certificate works on both sides", flush=True)
# A second SSH server for the destination account, presenting a host
# certificate that a CA the runner trusts signed.
authority = Path(tempfile.mkdtemp(prefix="syq-real-ssh-host-ca-")) / "ca"
run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(authority))
server = json.loads(remote("""python3 - <<'EOF'
import json, pathlib, socket, subprocess, tempfile
root = pathlib.Path(tempfile.mkdtemp(prefix="syq-real-ssh-certified-"))
subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / "host_key")], check=True)
with socket.socket() as probe:
    probe.bind(("0.0.0.0", 0))
    port = probe.getsockname()[1]
print(json.dumps({"root": str(root), "port": port, "key": (root / "host_key.pub").read_text()}))
EOF"""))
root, port = server["root"], server["port"]
signing = Path(authority.parent) / "host_key.pub"
signing.write_text(server["key"])
run("ssh-keygen", "-q", "-s", str(authority), "-h", "-I", "syq-real-ssh-destination", "-n", "destination",
    str(signing))
certificate = signing.with_name("host_key-cert.pub").read_text()
subprocess.run(["ssh", "destination", f"cat > {shlex.quote(root)}/host_key-cert.pub"],
               input=certificate, text=True, check=True, timeout=40)
remote(f"""cd {shlex.quote(root)} && printf '%s\\n' "Port {port}" "ListenAddress 0.0.0.0" "AddressFamily inet" \
  "HostKey $PWD/host_key" "HostCertificate $PWD/host_key-cert.pub" "PidFile $PWD/sshd.pid" \
  "AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/lab_authorized_keys" "StrictModes yes" "AllowUsers syq" \
  "AuthenticationMethods publickey" "PubkeyAuthentication yes" "PasswordAuthentication no" \
  "KbdInteractiveAuthentication no" "UsePAM no" "UseDNS no" "PermitTTY no" "LogLevel VERBOSE" > sshd_config && \
  /usr/sbin/sshd -f $PWD/sshd_config -E $PWD/sshd.log""")
saved_source = source_known_hosts()
saved_runner = known_hosts.read_bytes()
target = f"destination:{port}"
try:
    def listening():
        try:
            with socket.create_connection(("destination", port), timeout=.5):
                return True, "listening"
        except OSError as error:
            return False, str(error)
    wait_until("the certified SSH server", listening)
    # The runner trusts the destination at that port only through its CA;
    # the source knows nothing about it and refuses a host it has not seen.
    with known_hosts.open("a") as hosts:
        hosts.write(f"@cert-authority [destination]:{port} {authority.with_suffix('.pub').read_text()}")
    def certified_copy():
        copy("/tmp/syq-real-ssh/forward/hostkey-certificate", to=target)
    with_source_config(f"Host destination\n  StrictHostKeyChecking yes\n", certified_copy)
    assert not source_knows(f"[destination]:{port}")
    certified = [line.split("\t")[0] for line in run("syq", "receiver", "list").splitlines()
                 if f"\tsyq@destination:{port}" in line]
    assert len(certified) == 1, certified
    for enrollment in certified:
        run("syq", "receiver", "revoke", enrollment)
finally:
    restore_source_known_hosts(saved_source)
    known_hosts.write_bytes(saved_runner)
    remote(f"kill $(cat {shlex.quote(root)}/sshd.pid) 2>/dev/null; rm -rf {shlex.quote(root)}")
assert remote("sha256sum /tmp/syq-real-ssh/forward/hostkey-certificate").split()[0] == source_hash
print("case: a destination whose only known key is ECDSA is checked against that key", flush=True)
# The destination also offers ed25519, which OpenSSH prefers unless it
# already knows another type for the host: both machines know only ECDSA.
saved_source = source_known_hosts()
saved_runner = known_hosts.read_bytes()
ecdsa = run("ssh-keyscan", "-T", "5", "-t", "ecdsa", "destination")
assert ecdsa.split()[1].startswith("ecdsa-sha2-"), ecdsa
try:
    run("ssh-keygen", "-R", "destination", "-f", str(known_hosts))
    with known_hosts.open("a") as hosts:
        hosts.write(ecdsa)
    run("ssh", "source", "ssh-keygen -R destination >/dev/null 2>&1; umask 077; cat >> ~/.ssh/known_hosts",
        stdin=ecdsa)
    with_source_config("Host destination\n  StrictHostKeyChecking yes\n",
                       lambda: copy("/tmp/syq-real-ssh/forward/hostkey-ecdsa"))
finally:
    restore_source_known_hosts(saved_source)
    known_hosts.write_bytes(saved_runner)
assert remote("sha256sum /tmp/syq-real-ssh/forward/hostkey-ecdsa").split()[0] == source_hash
print("case: a user certificate the source's SSH configuration names does not replace the entry key", flush=True)
# The destination accepts a certificate the source's configuration offers,
# which OpenSSH would offer before any plain key. A copy between the servers
# started here, which the source coordinates with the entry key, must still
# log in with it and reach the enrolled receiver.
authority = run("ssh", "source", "rm -rf /tmp/syq-real-ssh-usercert && mkdir -m 700 /tmp/syq-real-ssh-usercert && "
                "cd /tmp/syq-real-ssh-usercert && ssh-keygen -q -t ed25519 -N '' -f ca && "
                "ssh-keygen -q -t ed25519 -N '' -f user && ssh-keygen -q -s ca -I user -n syq user.pub && "
                "cat ca.pub").strip()
authorized = remote("cat ~/.ssh/authorized_keys")
try:
    run("ssh", "destination", "cat >> ~/.ssh/authorized_keys", stdin=f"cert-authority {authority}\n")
    assert subprocess.run(["ssh", "source", "ssh -o BatchMode=yes -o IdentitiesOnly=yes "
                           "-i /tmp/syq-real-ssh-usercert/user destination true"], timeout=40).returncode == 0
    with_source_config("Host destination\n  IdentityFile /tmp/syq-real-ssh-usercert/user\n"
                       "  CertificateFile /tmp/syq-real-ssh-usercert/user-cert.pub\n",
                       lambda: run("syq", "cp", "--from", "source",
                                   "/tmp/syq-real-ssh/return-source/subdir/chunks.bin", "--to", "destination",
                                   "--as", "/tmp/syq-real-ssh/forward/hostkey-user-certificate",
                                   "--no-progress"))
finally:
    run("ssh", "destination", "umask 077; cat > ~/.ssh/authorized_keys", stdin=authorized)
    run("ssh", "source", "rm -rf /tmp/syq-real-ssh-usercert")
assert remote("sha256sum /tmp/syq-real-ssh/forward/hostkey-user-certificate").split()[0] == source_hash

def approved_source_copy():
    """Run `source_copy()`, approve it, and return its status and errors."""
    process = source_copy()
    pending = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
    assert len(pending) == 1, pending
    run("syq", "persist", "receive", "approve", pending[0]["id"])
    _, stderr = process.communicate(timeout=90)
    return process.returncode, stderr


print("case: the server's own KnownHostsCommand is kept", flush=True)
# The source knows the destination only through a KnownHostsCommand of its
# own. The runner's entries cannot join through another command, and the
# source's default GlobalKnownHostsFile list looks like one quoted name to
# `ssh -G`, so they are left out, and the copy says so.
WITHOUT = "without what the approving machine knows about it"
saved_source = source_known_hosts()
right = run("ssh-keyscan", "-T", "5", "destination")
try:
    run("ssh", "source", "ssh-keygen -R destination >/dev/null 2>&1; rm -rf /tmp/syq-real-ssh-khc && "
        "mkdir /tmp/syq-real-ssh-khc && cat > /tmp/syq-real-ssh-khc/hosts", stdin=right)
    status, stderr = with_source_config(
        "Host destination\n  StrictHostKeyChecking yes\n"
        "  KnownHostsCommand /usr/bin/env cat /tmp/syq-real-ssh-khc/hosts\n",
        approved_source_copy)
    assert status == 0, stderr
    assert f"{WITHOUT}: this machine's configuration has a KnownHostsCommand of its own" in stderr, stderr
    print("the source's own KnownHostsCommand decided", flush=True)
    # The same, with the source's command knowing nothing: only the runner
    # knows the destination, and its entries are left out, so the copy is
    # refused, as the source's own ssh would refuse it.
    status, stderr = with_source_config(
        "Host destination\n  StrictHostKeyChecking yes\n  KnownHostsCommand /bin/true\n",
        approved_source_copy)
    assert status not in (0, 124), stderr
    assert WITHOUT in stderr and "Host key verification failed" in stderr, stderr
    print("without the runner's entries, the copy was refused and said why", flush=True)
finally:
    restore_source_known_hosts(saved_source)
    run("ssh", "source", "rm -rf /tmp/syq-real-ssh-khc")

print("case: the runner says what of its own host-key checking the server cannot use", flush=True)
# The runner's own KnownHostsCommand is not run for the source; the source
# still checks the destination with what it and the runner's files know.
runner_config = Path.home() / ".ssh/config"
original_config = runner_config.read_bytes()
try:
    runner_config.write_bytes(b"Host destination\n  KnownHostsCommand /bin/true\n\n" + original_config)
    status, stderr = approved_source_copy()
finally:
    runner_config.write_bytes(original_config)
assert status == 0, stderr
assert ("without some of what the approving machine knows about it: "
        'its KnownHostsCommand "/bin/true" is not run for that') in stderr, stderr
print("source-shell remote copy checks passed", flush=True)
