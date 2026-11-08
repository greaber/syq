"""A requester on a third machine copies between two other servers with one
approval from the laptop: the source's enrolled receiver runs the copy and
reaches the destination's enrolled receiver itself. All paths are disposable."""
import contextlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time


# Each probe runs as the account whose processes it inspects. Its inputs
# travel over stdin.
PROBES = {
    "coordinator": r'''
from pathlib import Path
import base64
operand = base64.b64encode(v["destination"].encode()).decode().rstrip("=")
processes = {}
for p in Path("/proc").iterdir():
    if not p.name.isdigit():
        continue
    try:
        args = p.joinpath("cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
        stat = p.joinpath("stat").read_text().rsplit(") ", 1)[1].split()
        processes[int(p.name)] = (args, int(stat[1]), stat[19], stat[0])
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
found = []
for pid, (args, parent, started, state) in processes.items():
    if state == "Z" or not args or Path(args[0]).name != "syq":
        continue
    if "--delegated-operands-b64" not in args or operand not in args:
        continue
    receiver = processes.get(parent, ([], 0, "", ""))[0]
    found.append({"pid": pid, "started": started, "receiver": receiver[1:2],
                  "parent": parent, "parent_started": processes.get(parent, ([], 0, "", ""))[2]})
print(json.dumps(found))
''',
    "exited": r'''
from pathlib import Path
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
    "partial": r'''
import hashlib
from pathlib import Path
root = Path(v["root"])
matches = list(root.glob("." + v["name"] + ".syq-tmp.*"))
print(json.dumps(any(hashlib.sha256(p.open("rb").read(1 << 20)).hexdigest() == v["digest"] for p in matches)))
''',
    "signal_requester": r'''
from pathlib import Path
import os, signal
pid = int(Path(v["pidfile"]).read_text())
args = Path("/proc", str(pid), "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
assert Path(args[0]).name == "syq" and args[1] == "cp", "PID is not the requesting syq copy"
os.kill(pid, getattr(signal, v["signal"]))
print("true")
''',
    "key_dirs": r'''
from pathlib import Path
import os, tempfile
owned = []
for p in Path(tempfile.gettempdir()).glob("syq-receiver-hosts-*"):
    try:
        if p.stat().st_uid == os.getuid():
            owned.append(str(p))
    except FileNotFoundError:
        pass
print(json.dumps(sorted(owned)))
''',
    "kill_receivers": r'''
from pathlib import Path
import os, signal
killed = []
for p in Path("/proc").iterdir():
    if not p.name.isdigit():
        continue
    try:
        args = p.joinpath("cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
        if (len(args) > 1 and Path(args[0]).name == "syq" and args[1] == "--restricted-receiver"
                and p.stat().st_uid == os.getuid()):
            os.kill(int(p.name), signal.SIGKILL)
            killed.append(int(p.name))
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
assert killed, "the destination has no restricted receiver"
print(json.dumps(killed))
''',
}


def run(*args, stdin=None, success=True):
    result = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=60)
    assert (result.returncode == 0) == success, (args, result)
    return result.stdout


def remote(host, command, **kwargs):
    return run("ssh", host, command, **kwargs)


def probe(host, selector, **values):
    script = "import json, sys\nv = json.load(sys.stdin)\n" + PROBES[selector]
    return json.loads(remote(host, "python3 -c " + shlex.quote(script), stdin=json.dumps(values)))


def wait_for(description, predicate, timeout=25):
    deadline, progress = time.monotonic() + timeout, time.monotonic() + 3
    state = None
    while time.monotonic() < deadline:
        state = predicate()
        if state:
            return state
        if time.monotonic() >= progress:
            print("Waiting for", description, "last state:", state, flush=True)
            progress += 3
        time.sleep(.1)
    raise AssertionError(("Timed out", description, "last state", state))


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


@contextlib.contextmanager
def running(command):
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(["ssh", "requester", command], stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=output, start_new_session=True)
        try:
            yield process, output
        except BaseException:
            print(os.pread(output.fileno(), 1024 * 1024, 0).decode(errors="replace"), flush=True)
            raise
        finally:
            stop(process)


def finish(process, output, success=True):
    deadline, offset = time.monotonic() + 90, 0
    while True:
        try:
            status = process.wait(timeout=5)
            break
        except subprocess.TimeoutExpired:
            data = os.pread(output.fileno(), 1024 * 1024, offset)
            offset += len(data)
            print(data.decode(errors="replace"), end="", flush=True)
            print("Waiting for the copy between servers", flush=True)
            assert time.monotonic() < deadline, "copy between servers exceeded its deadline"
    text = os.pread(output.fileno(), 1024 * 1024, 0).decode(errors="replace")
    print(text, end="", flush=True)
    assert status != 124, "copy between servers reached its safety timeout"
    assert (status == 0) == success, (status, text)
    return text


def pending():
    return json.loads(run("syq", "persist", "receive", "pending", "--json"))


def decide(allow=True):
    requests = json.loads(run("syq", "persist", "receive", "pending", "--json",
                              "--wait", "--timeout", "20"))
    assert len(requests) == 1, requests
    request = requests[0]
    assert ' on "destination" using your SSH access' in request["destination"], request
    assert '"source" runs the copy' in request["permission"], request
    run("syq", "persist", "receive", "approve" if allow else "deny", request["id"])
    return request


def enrollments():
    rows = {}
    for line in run("syq", "receiver", "list").splitlines():
        fields = line.split("\t")
        if len(fields) >= 3 and fields[1] == "active":
            rows[fields[2]] = fields[0]
    return rows


def digest(host, path):
    return remote(host, "sha256sum " + shlex.quote(path)).split()[0]


def authorized_keys(host):
    return remote(host, "cat ~/.ssh/authorized_keys 2>/dev/null || true")


def main():
    config = Path.home()/".ssh/config"
    original = config.read_bytes()
    roots = {}
    created_source_enrollment = False
    requester_config = None
    try:
        # The requester is a separate account on this machine, without the
        # laptop's keys.
        config.write_bytes(original + b"\nHost requester\n    HostName 127.0.0.1\n    User longhome\n"
                           b"    BatchMode yes\n    IdentityFile /home/syq/.ssh/id_ed25519\n"
                           b"    IdentitiesOnly yes\n    StrictHostKeyChecking yes\n"
                           b"    UserKnownHostsFile /home/syq/.ssh/known_hosts\n"
                           b"    GlobalKnownHostsFile /dev/null\n    UpdateHostKeys no\n")
        with (Path.home()/".ssh/known_hosts").open("a") as known_hosts:
            known_hosts.write(run("ssh-keyscan", "-T", "5", "-t", "ed25519", "127.0.0.1"))
        for host in ("requester", "source", "destination"):
            roots[host] = remote(host, "mktemp -d /tmp/syq-between.XXXXXX").strip()
        a, b, c = (roots[host] for host in ("requester", "source", "destination"))
        assert remote("requester", "id -un").strip() == "longhome"
        # The requester has no credentials of its own for either server: the
        # entry keys the laptop hands it are all it uses.
        remote("requester", 'test -z "${SSH_AUTH_SOCK:-}" && test ! -r /home/syq/.ssh/id_ed25519')
        requester_config = json.loads(remote("requester", "python3 -c " + shlex.quote(
            "from pathlib import Path; import json; p=Path.home()/'.ssh/config'; "
            "print(json.dumps({'content': p.read_text() if p.exists() else None}))")))
        remote("requester", "python3 -c " + shlex.quote(
            "from pathlib import Path; import sys; p=Path.home()/'.ssh/config'; "
            "p.parent.mkdir(mode=0o700, exist_ok=True); "
            "p.write_text(sys.stdin.read() + (p.read_text() if p.exists() else ''))"),
            stdin="Host source destination\n    User syq\n")
        run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off")
        run("syq", "persist", "connect", "requester")
        run("syq", "persist", "receive", "wait", "requester", "--timeout", "30")
        # Start from a source without an enrollment, so the first copy sets
        # it up; a focused run may follow an earlier one.
        if "syq@source" in enrollments():
            run("syq", "receiver", "revoke", enrollments()["syq@source"])

        remote("source", "dd if=/dev/urandom of=" + shlex.quote(b + "/data")
               + " bs=1M count=8 status=none && chmod 444 " + shlex.quote(b + "/data"))
        remote("source", "dd if=/dev/urandom of=" + shlex.quote(b + "/large")
               + " bs=1M count=32 status=none")
        expected = digest("source", b + "/data")
        prefix = remote("source", "dd if=" + shlex.quote(b + "/large")
                        + " bs=1M count=1 status=none | sha256sum").split()[0]

        attempts = {}

        def command(name, extra=(), source="data", auth=("--auth-from", "@laptop")):
            attempts[name] = attempts.get(name, 0) + 1
            argv = ["syq", "cp", "--from", "source", b + "/" + source, "--to", "destination",
                    "--as", c + "/" + name, *auth,
                    "--performance-tuning", "workers=2", "--no-progress",
                    "--results", f"{a}/{name}.{attempts[name]}.ndjson", *extra]
            script = ("test -z \"${SSH_AUTH_SOCK:-}\" && echo $$ > " + shlex.quote(a + "/pid")
                      + " && exec env PATH=/usr/bin:/bin:/usr/local/bin " + shlex.join(argv))
            # The recorded PID becomes syq itself.
            return shlex.join(["timeout", "120", "sh", "-c", script])

        def results(name):
            return [json.loads(line) for line in remote("requester", "cat " + shlex.quote(
                f"{a}/{name}.{attempts[name]}.ndjson")).splitlines()]

        def assert_copied(name, expected_digest=expected):
            records = results(name)
            terminal = records[-1]
            assert terminal["type"] == "result" and terminal["status"] == "success", terminal
            assert terminal["files_transferred"] == 1 and terminal["errors"] == 0, terminal
            # The destination's own record of the file, which the requester
            # checked.
            assert [record["action"] for record in records
                    if record["type"] == "operation_result"] == ["transfer_file"], records
            assert digest("destination", c + "/" + name) == expected_digest
            assert pending() == []

        def partial(name, expected_prefix=prefix):
            return probe("destination", "partial", root=c, name=name, digest=expected_prefix)

        def stopped(name, description, stop):
            """Start a slow copy and stop it with `stop` once data arrives: the
            source's receiver and the coordinator it runs both end, and
            nothing is published."""
            with running(command(name, ("--no-tcp", "--resource-limits", "bandwidth=512K"),
                                 source="large")) as (process, output):
                decide()
                wait_for("copy data before " + description, lambda: partial(name))
                coordinator = probe("source", "coordinator", destination=c + "/" + name)
                assert len(coordinator) == 1, coordinator
                owned = [[coordinator[0]["pid"], coordinator[0]["started"]],
                         [coordinator[0]["parent"], coordinator[0]["parent_started"]]]
                stop()
                wait_for("the source's receiver and coordinator after " + description,
                         lambda: probe("source", "exited", processes=owned), timeout=10)
                finish(process, output, success=False)
            remote("destination", "test ! -e " + shlex.quote(c + "/" + name))
            assert pending() == []

        # The private directories that hold the destination's entry key on
        # the source go when its coordinator ends.
        key_dirs = probe("source", "key_dirs")

        def no_key_dirs():
            return probe("source", "key_dirs") == key_dirs

        print("case: a dry run between two servers does not set restricted copying up", flush=True)
        with running(command("dry", ("--dry-run",))) as (process, output):
            text = finish(process, output, success=False)
        assert "a dry run does not set up restricted copying on syq@source" in text, text
        assert pending() == []
        assert "syq@source" not in enrollments()

        print("case: one approval enrolls the source and copies directly to the destination", flush=True)
        with running(command("first")) as (process, output):
            request = decide()
            assert 'Also sets up restricted copying on "source"' in request["permission"], request
            finish(process, output)
        assert_copied("first")
        assert "syq@source" in enrollments() and "syq@destination" in enrollments()
        created_source_enrollment = True
        for host in ("source", "destination"):
            keys = authorized_keys(host)
            assert "syq-enrollment:" in keys and "syq-copy-worker" not in keys, keys
        # The requester got no login of its own to either account.
        assert json.loads(remote("requester", "syq persist status --json"))["authorized_ssh"] == []

        print("case: a denied copy between servers changes nothing", flush=True)
        before = authorized_keys("source")
        with running(command("denied")) as (process, output):
            decide(allow=False)
            finish(process, output, success=False)
        remote("destination", "test ! -e " + shlex.quote(c + "/denied"))
        assert authorized_keys("source") == before

        print("case: the source's receiver runs the copy and sends data over direct TCP", flush=True)
        port = 47821
        with running(command("tcp", ("--tcp-ports", f"{port}-{port}",
                                     "--resource-limits", "bandwidth=1M"))) as (process, output):
            decide()
            coordinator = wait_for("the source's coordinator",
                                   lambda: probe("source", "coordinator", destination=c + "/tcp"))
            assert len(coordinator) == 1, coordinator
            # Its parent is the restricted receiver that verified the copy.
            receiver = coordinator[0]["receiver"]
            assert receiver and receiver[0] == "--restricted-receiver", coordinator
            wait_for("direct source-to-destination TCP", lambda: probe("source", "tcp", port=port))
            finish(process, output)
        assert_copied("tcp")

        print("case: an SSH-only copy between servers uses the destination's entry key", flush=True)
        with running(command("ssh", ("--no-tcp",))) as (process, output):
            decide()
            finish(process, output)
        assert_copied("ssh")
        assert "syq-copy-worker" not in authorized_keys("destination")
        wait_for("the source's entry key cleanup after completed copies", no_key_dirs)

        print("case: a saved choice approves a copy between servers, and blocked TCP falls back to SSH", flush=True)
        remote("requester", "syq persist auth-from @laptop --for source")
        blocked = os.environ["SYQ_REAL_SSH_BLOCKED_TCP_PORT"]
        with running(command("fallback", ("--tcp-ports", f"{blocked}-{blocked}"),
                             auth=())) as (process, output):
            decide()
            finish(process, output)
        assert_copied("fallback")
        remote("requester", "syq persist auth-from --reset --for source")

        print("case: a different key for the source that only the laptop lists is refused with advice", flush=True)
        known_hosts = Path.home()/".ssh/known_hosts"
        saved_known_hosts = known_hosts.read_bytes()
        # The requester's known_hosts too, and whether ssh-keygen's backup of
        # it existed.
        requester_known_hosts = json.loads(remote("requester", "python3 -c " + shlex.quote(
            "from pathlib import Path; import base64, json; p=Path.home()/'.ssh/known_hosts'; "
            "print(json.dumps({'content': base64.b64encode(p.read_bytes()).decode() "
            "if p.exists() else None, 'old': p.with_name('known_hosts.old').exists()}))")))
        try:
            # The requester forgets the source, and the laptop lists another
            # key for it. The laptop does not log in to the enrolled source.
            remote("requester", "ssh-keygen -R source >/dev/null 2>&1 || true")
            run("ssh-keygen", "-R", "source", "-f", str(known_hosts))
            with tempfile.TemporaryDirectory() as directory:
                key = Path(directory)/"wrong"
                run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
                wrong = key.with_suffix(".pub").read_text().split()[:2]
            with known_hosts.open("a") as entries:
                entries.write("source " + " ".join(wrong) + "\n")
            with running(command("wrong-key")) as (process, output):
                decide()
                text = finish(process, output, success=False)
            assert "remove it there with `ssh-keygen -R source`" in text, text
        finally:
            known_hosts.write_bytes(saved_known_hosts)
            remote("requester", "python3 -c " + shlex.quote(
                "from pathlib import Path; import base64, json, sys; "
                "v=json.load(sys.stdin); p=Path.home()/'.ssh/known_hosts'; "
                "p.write_bytes(base64.b64decode(v['content'])) if v['content'] is not None "
                "else p.unlink(missing_ok=True); "
                "v['old'] or p.with_name('known_hosts.old').unlink(missing_ok=True)"),
                stdin=json.dumps(requester_known_hosts))
        remote("destination", "test ! -e " + shlex.quote(c + "/wrong-key"))

        print("case: the copy continues when the laptop stops receiving", flush=True)
        with running(command("laptop-gone", ("--no-tcp", "--resource-limits", "bandwidth=2M"),
                             source="large")) as (process, output):
            decide()
            wait_for("copy data before receiving stops", lambda: partial("laptop-gone"))
            run("syq", "persist", "receive", "off", "--name", "laptop")
            finish(process, output)
        assert digest("destination", c + "/laptop-gone") == digest("source", b + "/large")
        run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off")
        run("syq", "persist", "receive", "wait", "requester", "--timeout", "30")

        for signal_name in ("SIGTERM", "SIGKILL"):
            print(f"case: {signal_name} to the requester stops the copy on the source", flush=True)
            stopped("stopped-" + signal_name.lower(), "the requester is stopped",
                    lambda: probe("requester", "signal_requester", pidfile=a + "/pid",
                                  signal=signal_name))
            wait_for("the source's entry key cleanup after the requester stopped", no_key_dirs)
        # A new approval copies it again.
        with running(command("stopped-sigkill", ("--no-tcp",), source="large")) as (process, output):
            decide()
            finish(process, output)
        assert_copied("stopped-sigkill", digest("source", b + "/large"))

        print("case: losing the destination's receiver ends the copy on the source", flush=True)
        stopped("destination-lost", "the destination's receiver is killed",
                lambda: probe("destination", "kill_receivers"))
        wait_for("the source's entry key cleanup after the destination was lost", no_key_dirs)

        print("case: revoking the source's enrollment stops its receiver and coordinator", flush=True)
        stopped("revoked", "the source's enrollment is revoked",
                lambda: run("syq", "receiver", "revoke", enrollments()["syq@source"]))
        assert "syq@source" not in enrollments()
        assert "syq-enrollment:" not in authorized_keys("source")
        # Revocation kills the coordinator, which leaves its private key
        # directory behind; the key only starts the destination's receiver.
        for leftover in set(probe("source", "key_dirs")) - set(key_dirs):
            remote("source", "rm -rf -- " + shlex.quote(leftover))
        # The next approval sets the source up again.
        with running(command("re-enrolled")) as (process, output):
            request = decide()
            assert 'Also sets up restricted copying on "source"' in request["permission"], request
            finish(process, output)
        assert_copied("re-enrolled")
        print("Copies between two other servers passed", flush=True)
    finally:
        if "requester" in roots:
            remote("requester", "syq persist auth-from --reset --for source")
        if created_source_enrollment and "syq@source" in enrollments():
            run("syq", "receiver", "revoke", enrollments()["syq@source"])
        if requester_config is not None:
            remote("requester", "python3 -c " + shlex.quote(
                "from pathlib import Path; import json, sys; p=Path.home()/'.ssh/config'; "
                "value=json.load(sys.stdin)['content']; "
                "p.write_text(value) if value is not None else p.unlink()"),
                stdin=json.dumps(requester_config))
        if "requester" in roots:
            remote("requester", "syq persist off")
        for host, root in roots.items():
            remote(host, "rm -rf -- " + shlex.quote(root))
        config.write_bytes(original)


if __name__ == "__main__":
    main()
