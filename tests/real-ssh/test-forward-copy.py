"""Source-shell copies the runner approves for the destination's enrolled
receiver; all paths are disposable."""
import json
import os
from pathlib import Path
import shlex
import signal
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
         source="/tmp/syq-real-ssh/return-source/subdir/chunks.bin", prefix=None, after_approval=None, auth=(), binary="syq", stdin=None, ssh_trace=None):

    argv = [binary, "cp", "-vv", source, "--to", "destination",
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
            assert ' on "destination" using your SSH access' in request["destination"], request
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


def relayed_connections():
    # Pool warming also connects to destination in the background. A copy
    # relayed through this machine would start --return-receiver there.
    return [event for event in trace_events(trace.read_text())
            if event["phase"] == "start" and event["host"] == "destination"
            and event["return_receiver"] == "yes"]


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

print("case: a first copy to a destination this machine does not trust is refused without enrolling", flush=True)
known_hosts = Path.home() / ".ssh/known_hosts"
trusted = known_hosts.read_bytes()
run("ssh-keygen", "-R", "destination", "-f", str(known_hosts))
try:
    untrusted = source_copy()
    pending = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
    assert len(pending) == 1 and "Also sets up restricted copying" in pending[0]["permission"], pending
    run("syq", "persist", "receive", "approve", pending[0]["id"])
    _, stderr = untrusted.communicate(timeout=90)
    assert untrusted.returncode not in (0, 124), stderr
    assert "no exact trusted host key for destination" in stderr, stderr
    assert destination_enrollments() == []
finally:
    known_hosts.write_bytes(trusted)
assert "syq-enrollment:" not in remote("cat ~/.ssh/authorized_keys 2>/dev/null || true")
remote("test ! -e /tmp/syq-real-ssh/forward/first-use")

before = len(relayed_connections())
# The source has its own trace filesystem. Give this copy a separate file so
# an older source session's background activity cannot enter the assertion.
source_trace = run("ssh", "source", "mktemp /tmp/syq-real-ssh/forward-ssh.XXXXXX").strip()
try:
    # The first approved copy sets up restricted copying on the destination.
    copy("/tmp/syq-real-ssh/forward/approved", extra=("--stats",), ssh_trace=source_trace)
    assert relayed_connections()[before:] == [], "the copy was relayed through the runner"
    events = trace_events(run("ssh", "source", "cat " + shlex.quote(source_trace)))
    # RemoteSpec sets ControlMaster on every transport connection. The same
    # process also runs ssh -G to read config; that query never connects.
    attempts = [event for event in events
                if event["phase"] == "start" and event["host"] == "destination"
                and event["control_master"] != "unset" and event["entry_key"] == "no"]
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
    copy("/tmp/syq-real-ssh/forward/" + name, auth=(option, "auto"))
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
print("source-shell remote copy checks passed", flush=True)
