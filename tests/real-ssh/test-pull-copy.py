"""Downloads from another server that the runner approves per copy: the
requesting server reads through the source's enrolled receiver, which serves
only what the signed command reads. All paths are disposable."""
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
    "receivers": r'''
from pathlib import Path
import os
found = []
for p in Path("/proc").iterdir():
    if not p.name.isdigit():
        continue
    try:
        args = p.joinpath("cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
        stat = p.joinpath("stat").read_text().rsplit(") ", 1)[1].split()
        if (len(args) > 1 and Path(args[0]).name == "syq" and args[1] == "--restricted-receiver"
                and stat[0] != "Z" and p.stat().st_uid == os.getuid()):
            found.append([int(p.name), stat[19]])
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
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
print(json.dumps(any(hashlib.sha256(p.open("rb").read(4 << 20)).hexdigest() == v["digest"] for p in matches)))
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
        process = subprocess.Popen(["ssh", "source", command], stdin=subprocess.DEVNULL,
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
            print("Waiting for the source download", flush=True)
            assert time.monotonic() < deadline, "source download exceeded its deadline"
    text = os.pread(output.fileno(), 1024 * 1024, 0).decode(errors="replace")
    print(text, end="", flush=True)
    assert status != 124, "source download reached its safety timeout"
    assert (status == 0) == success, (status, text)
    return text


def pending():
    return json.loads(run("syq", "persist", "receive", "pending", "--json"))


def decide(allow=True, setup=None):
    requests = json.loads(run("syq", "persist", "receive", "pending", "--json",
                              "--wait", "--timeout", "20"))
    assert len(requests) == 1, requests
    request = requests[0]
    assert request["kind"] == "source", request
    assert request["source"] == "destination", request
    assert "destination" not in request, request
    assert "syq's receiver" in request["permission"], request
    if setup is not None:
        assert setup in request["permission"], request
    run("syq", "persist", "receive", "approve" if allow else "deny", request["id"])
    run("syq", "persist", "receive", "approve", request["id"], success=False)
    return request


def enrollments():
    return [line.split("\t")[0] for line in run("syq", "receiver", "list").splitlines()
            if "\tactive\tsyq@destination" in line]


def digest(host, path):
    return remote(host, "sha256sum " + shlex.quote(path)).split()[0]


def authorized_keys():
    return remote("destination", "cat ~/.ssh/authorized_keys 2>/dev/null || true")


def main():
    roots = {}
    try:
        roots["destination"] = remote("destination", "mktemp -d /tmp/syq-pull-source.XXXXXX").strip()
        roots["source"] = remote("source", "mktemp -d /tmp/syq-pull-destination.XXXXXX").strip()
        files, into = roots["destination"], roots["source"]
        Path("/tmp/syq-real-ssh-receive").mkdir(exist_ok=True)
        # Automatic approval of downloads to this machine does not cover
        # reading another server's files.
        run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off",
            "--auto-approve-root", "/tmp/syq-real-ssh-receive")
        run("syq", "persist", "connect", "source")
        run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
        remote("destination", "dd if=/dev/urandom of=" + shlex.quote(files + "/data")
               + " bs=1M count=8 status=none && chmod 444 " + shlex.quote(files + "/data"))
        remote("destination", "dd if=/dev/urandom of=" + shlex.quote(files + "/large")
               + " bs=1M count=32 status=none")
        expected, large = digest("destination", files + "/data"), digest("destination", files + "/large")
        # One whole comparison block, which a later copy can reuse.
        prefix = remote("destination", "dd if=" + shlex.quote(files + "/large")
                        + " bs=1M count=4 status=none | sha256sum").split()[0]
        attempts = {}

        def command(name, extra=(), source="data", binary="syq", tcp=False, path=None):
            attempts[name] = attempts.get(name, 0) + 1
            argv = [binary, "cp", "--from", "destination", path or files + "/" + source,
                    "--as", into + "/" + name, "--auth-from", "auto", "--no-progress",
                    "--performance-tuning", "workers=2",
                    "--results", f"{into}/{name}.{attempts[name]}.ndjson", *extra]
            # The requesting server has no credentials of its own for the
            # source: the entry key the runner hands it is all it uses.
            return ('test -z "${SSH_AUTH_SOCK:-}" && test ! -e ~/.ssh/id_ed25519 && exec timeout 120 env '
                    + ("SYQ_TEST_REQUIRE_TCP=1 " if tcp else "") + shlex.join(argv))

        def results(name):
            return [json.loads(line) for line in remote("source", "cat " + shlex.quote(
                f"{into}/{name}.{attempts[name]}.ndjson")).splitlines()]

        def copied(name, expected_digest=expected):
            terminal = results(name)[-1]
            assert terminal["type"] == "result" and terminal["status"] == "success", terminal
            assert digest("source", into + "/" + name) == expected_digest
            assert pending() == []
            return terminal

        def absent(name):
            remote("source", "test ! -e " + shlex.quote(into + "/" + name))

        def partial(name):
            return probe("source", "partial", root=into, name=name, digest=prefix)

        print("case: a dry run of a source download does not set restricted copying up", flush=True)
        for enrollment in enrollments():
            run("syq", "receiver", "revoke", enrollment)
        with running(command("dry", ("--dry-run",))) as (process, output):
            text = finish(process, output, success=False)
        assert "a dry run does not set up restricted copying on syq@destination" in text, text
        assert pending() == [] and enrollments() == []

        print("case: source access requires separate approval despite automatic receiving", flush=True)
        keys = authorized_keys()
        with running(command("denied")) as (process, output):
            decide(allow=False)
            finish(process, output, success=False)
        absent("denied")
        assert authorized_keys() == keys and enrollments() == []

        print("case: one approval enrolls the source, whose receiver sends data over direct TCP", flush=True)
        port = 47831
        with running(command("approved", ("--tcp-ports", f"{port}-{port}",
                                          "--resource-limits", "bandwidth=2M"),
                             tcp=True)) as (process, output):
            decide(setup='Also sets up restricted copying on "destination"')
            receivers = wait_for("the source's restricted receiver",
                                 lambda: probe("destination", "receivers"))
            wait_for("direct TCP from the requesting server to the source",
                     lambda: probe("source", "tcp", port=port))
            finish(process, output)
        copied("approved")
        assert len(enrollments()) == 1
        keys = authorized_keys()
        assert "syq-enrollment:" in keys and "syq-copy-worker" not in keys, keys
        # The receiver ends with the copy, and the requesting server got no
        # login of its own to the source.
        wait_for("the source's receiver after the copy",
                 lambda: probe("destination", "exited", processes=receivers))
        assert json.loads(remote("source", "syq persist status --json"))["authorized_ssh"] == []

        print("case: an approved download hands off to the receiving build", flush=True)
        with running(command("other-build", binary="syq-other-build")) as (process, output):
            decide(setup="Signs this copy with your SSH login key")
            finish(process, output)
        copied("other-build")

        print("case: an SSH-only download reads through the source's entry key", flush=True)
        with running(command("ssh-only", ("--no-tcp",))) as (process, output):
            decide()
            finish(process, output)
        copied("ssh-only")
        assert "syq-copy-worker" not in authorized_keys()

        print("case: relative and ~/ sources are read from the source account's home", flush=True)
        # The receiver works in its state directory, yet reads these where
        # the account's own login would.
        home_dir = Path(files).name
        remote("destination", "mkdir ~/" + shlex.quote(home_dir) + " && cp "
               + shlex.quote(files + "/data") + " ~/" + shlex.quote(home_dir) + "/data")
        roots["home"] = home_dir
        for name, path in [("relative", home_dir + "/data"), ("tilde", "~/" + home_dir + "/data")]:
            with running(command(name, path=path)) as (process, output):
                request = decide()
                assert any("destination:" + path in scope for scope in request["scopes"]), request
                finish(process, output)
            copied(name)

        print("case: blocked TCP falls back to SSH", flush=True)
        blocked = os.environ["SYQ_REAL_SSH_BLOCKED_TCP_PORT"]
        with running(command("blocked", ("--tcp-ports", f"{blocked}-{blocked}"))) as (process, output):
            decide()
            finish(process, output)
        copied("blocked")

        print("case: the download continues when the laptop stops receiving", flush=True)
        with running(command("laptop-gone", ("--no-tcp", "--resource-limits", "bandwidth=2M"),
                             source="large")) as (process, output):
            decide()
            wait_for("data before receiving stops", lambda: partial("laptop-gone"))
            run("syq", "persist", "receive", "off", "--name", "laptop")
            finish(process, output)
        copied("laptop-gone", large)
        run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off")
        run("syq", "persist", "receive", "wait", "source", "--timeout", "30")

        print("case: interrupting the download on the requesting server ends the source's receiver", flush=True)
        with running(command("interrupted", ("--resource-limits", "bandwidth=1M"),
                             source="large")) as (process, output):
            decide()
            wait_for("data before the interruption", lambda: partial("interrupted"))
            receivers = probe("destination", "receivers")
            assert receivers, "the source has no restricted receiver"
            # Only this copy runs there; the pattern cannot match the shell
            # that runs pkill.
            remote("source", "pkill -TERM -f '^syq cp --from destination '")
            wait_for("the source's receiver after the interruption",
                     lambda: probe("destination", "exited", processes=receivers), timeout=10)
            finish(process, output, success=False)
        absent("interrupted")
        assert pending() == []

        print("case: revoking the source's enrollment stops a download, and a new approval resumes it", flush=True)
        with running(command("revoked", ("--resource-limits", "bandwidth=1M"),
                             source="large")) as (process, output):
            decide()
            wait_for("data before the revocation", lambda: partial("revoked"))
            receivers = probe("destination", "receivers")
            run("syq", "receiver", "revoke", enrollments()[0])
            wait_for("the source's receiver after the revocation",
                     lambda: probe("destination", "exited", processes=receivers), timeout=10)
            finish(process, output, success=False)
        absent("revoked")
        assert enrollments() == [] and "syq-enrollment:" not in authorized_keys()
        with running(command("revoked", ("--no-tcp",), source="large")) as (process, output):
            decide(setup='Also sets up restricted copying on "destination"')
            finish(process, output)
        terminal = copied("revoked", large)
        assert terminal["bytes_unchanged"] >= 4 << 20, terminal
        print("Source downloads passed", flush=True)
    finally:
        if "home" in roots:
            remote("destination", "rm -rf -- ~/" + shlex.quote(roots.pop("home")))
        for host, root in roots.items():
            remote(host, "rm -rf -- " + shlex.quote(root))


if __name__ == "__main__":
    main()
