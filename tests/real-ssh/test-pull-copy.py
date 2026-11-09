"""Downloads from another server that the runner approves per copy: the
requesting server reads through the source's enrolled receiver, which serves
only what the signed command reads. The source's root account, which only this
lab endpoint lets log in, serves downloads too, but no copy writes to it, and
toor, another name for user ID 0, cannot enroll. All paths are disposable."""
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


def decide(allow=True, setup=None, source="destination"):
    requests = json.loads(run("syq", "persist", "receive", "pending", "--json",
                              "--wait", "--timeout", "20"))
    assert len(requests) == 1, requests
    request = requests[0]
    assert request["kind"] == "source", request
    assert request["source"] == source, request
    assert "destination" not in request, request
    assert "syq's receiver" in request["permission"], request
    if setup is not None:
        assert setup in request["permission"], request
    run("syq", "persist", "receive", "approve" if allow else "deny", request["id"])
    run("syq", "persist", "receive", "approve", request["id"], success=False)
    return request


def enrollments(account="syq@destination"):
    return [line.split("\t")[0] for line in run("syq", "receiver", "list").splitlines()
            if "\tactive\t" + account in line]


def digest(host, path):
    return remote(host, "sha256sum " + shlex.quote(path)).split()[0]


def authorized_keys(account="destination"):
    return remote(account, "cat ~/.ssh/authorized_keys 2>/dev/null || true")


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

        def command(name, extra=(), source="data", binary="syq", tcp=False, path=None,
                    account="destination"):
            attempts[name] = attempts.get(name, 0) + 1
            argv = [binary, "cp", "--from", account, path or files + "/" + source,
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

        print("case: approving a dry run of a download allows a preview, which reads no contents", flush=True)
        # The existing file differs in time only, so the preview compares
        # whole files by hash; the new one needs nothing read.
        remote("source", "touch -d @1000000000 " + shlex.quote(into + "/approved"))
        for name in ("approved", "preview"):
            with running(command(name, ("--dry-run",))) as (process, output):
                request = decide()
                assert request["permission"].startswith("Preview only (a dry run)"), request
                finish(process, output)
        absent("preview")
        assert digest("source", into + "/approved") == expected

        print("case: an approved download hands off to the receiving build", flush=True)
        with running(command("other-build", binary="syq-other-build")) as (process, output):
            decide(setup="Signs this copy with your SSH login key")
            finish(process, output)
        copied("other-build")

        print("case: an SSH-only download reads through the source's entry key", flush=True)
        with running(command("ssh-only", ("--no-tcp",))) as (process, output):
            request = decide()
            assert "without encryption" not in request["permission"], request
            finish(process, output)
        copied("ssh-only")
        assert "syq-copy-worker" not in authorized_keys()

        print("case: an approved download sends unencrypted TCP only when its command asks", flush=True)
        # The source's receiver starts a listener without encryption only
        # because the signed command asks for it, and the prompt warns.
        with running(command("plain", ("--no-tcp-encryption",), tcp=True)) as (process, output):
            request = decide()
            assert "over TCP without encryption" in request["permission"], request
            finish(process, output)
        copied("plain")

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

        print("case: a root login serves an approved download of a root-only file", flush=True)
        as_root = "root@destination"
        roots[as_root] = remote(as_root, "mktemp -d /tmp/syq-pull-root.XXXXXX").strip()
        secret = roots[as_root] + "/secret"
        remote(as_root, "dd if=/dev/urandom of=" + shlex.quote(secret)
               + " bs=1M count=8 status=none && chmod 600 " + shlex.quote(secret))
        assert remote(as_root, "stat -c '%U %a' " + shlex.quote(secret)).split() == ["root", "600"]
        remote("destination", "cat " + shlex.quote(secret), success=False)
        secret_digest, account_keys = digest(as_root, secret), authorized_keys()
        assert enrollments(as_root) == [] and "syq-enrollment:" not in authorized_keys(as_root)
        with running(command("root-secret", ("--resource-limits", "bandwidth=2M"), path=secret,
                             account=as_root)) as (process, output):
            decide(setup='Also sets up restricted copying on "root@destination"', source=as_root)
            receivers = wait_for("root's restricted receiver", lambda: probe(as_root, "receivers"))
            finish(process, output)
        copied("root-secret", secret_digest)
        root_enrollment = enrollments(as_root)
        assert len(root_enrollment) == 1
        root_keys = authorized_keys(as_root)
        assert root_keys.count("syq-enrollment:") == 1 and "syq-copy-worker" not in root_keys, root_keys
        # The ordinary account's keys did not change.
        assert authorized_keys() == account_keys
        wait_for("root's receiver after the copy",
                 lambda: probe(as_root, "exited", processes=receivers))

        def root_state():
            # Everything in root's home and the directory a copy would write
            # to, so a refusal can be seen to change nothing there.
            return remote(as_root, "find ~ " + shlex.quote(roots[as_root])
                          + " -printf '%p %y %s %m %T@\\n' | LC_ALL=C sort")

        def refused(host, argv, expected, before):
            # A bounded wait: a copy waiting for an approval would time out.
            command = "exec timeout --kill-after=5 30 " + shlex.join(argv)
            with tempfile.TemporaryFile() as output:
                process = subprocess.Popen(["sh", "-c", command] if host is None else ["ssh", host, command],
                                           stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                           start_new_session=True)
                try:
                    status = process.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    status = None
                    print("Still running; pending:", pending(), flush=True)
                    stop(process)
                text = os.pread(output.fileno(), 1024 * 1024, 0).decode(errors="replace")
            print(text, end="", flush=True)
            assert status not in (None, 0, 124, 137), (status, text)
            assert expected in text, text
            assert pending() == []
            assert root_state() == before
            assert enrollments(as_root) == root_enrollment
            return text

        print("case: on that root enrollment, an upload to root is refused before any prompt", flush=True)
        before = root_state()
        refused("source", ["syq", "cp", into + "/approved", "--to", as_root,
                           "--as", roots[as_root] + "/upload", "--auth-from", "auto",
                           "--no-progress"],
                "does not write or run copies as root, so a copy to root@destination cannot be approved", before)

        print("case: a copy this machine starts between servers to root is refused before setup", flush=True)
        text = refused(None, ["syq", "cp", "--from", "source", into + "/approved", "--to", as_root,
                              "--as", roots[as_root] + "/between", "--no-progress"],
                       "restricted receivers do not write or run copies as root", before)
        # Refused here, not by root's receiver, which would name its enrollment.
        assert "serves only downloads" not in text, text

        print("case: revoking the root enrollment removes its key from root's account", flush=True)
        run("syq", "receiver", "revoke", root_enrollment[0])
        assert enrollments(as_root) == [] and "syq-enrollment:" not in authorized_keys(as_root)

        print("case: an upload to another name for user ID 0 is refused by its enrollment session", flush=True)
        # toor shares root's user ID and is listed after it. The laptop's
        # check of the name passes; the user ID the session reports does not.
        alias = "toor@destination"
        assert remote(alias, "id -u; id -un; printf '%s\\n' \"$HOME\"").split() == ["0", "root", "/home/toor"]

        def alias_home():
            return remote(as_root, "find /home/toor -printf '%p %y %m\\n' | LC_ALL=C sort")

        alias_before = alias_home()
        upload = ["syq", "cp", into + "/approved", "--to", alias, "--as", "/home/toor/upload",
                  "--auth-from", "auto", "--no-progress"]
        with running("exec timeout 120 " + shlex.join(upload)) as (process, output):
            requests = json.loads(run("syq", "persist", "receive", "pending", "--json",
                                      "--wait", "--timeout", "20"))
            assert len(requests) == 1, requests
            assert 'on "toor@destination"' in requests[0]["destination"], requests
            assert 'Also sets up restricted copying on "toor@destination"' in requests[0]["permission"], requests
            run("syq", "persist", "receive", "approve", requests[0]["id"])
            text = finish(process, output, success=False)
        assert "restricted receivers do not write or run copies as root" in text, text
        # Nothing was left pending, so the error does not say so.
        assert "remains pending" not in text, text
        # Nothing reached toor's home: no key line, no stored syq, no state.
        assert alias_home() == alias_before
        remote(alias, "test ! -e ~/.local/lib/syq && test ! -e ~/.local/share/syq"
               " && ! grep -s -q syq-enrollment: ~/.ssh/authorized_keys")
        assert pending() == []
        assert [line for line in run("syq", "receiver", "list").splitlines()
                if "\ttoor@destination" in line] == []

        print("case: a download through another name for user ID 0 is refused before setup", flush=True)
        # Root may serve downloads, but only under the name the server gives
        # user ID 0; nothing is installed or left pending for toor. The first
        # attempt finds the pending enrollment an earlier build left, which
        # nothing could install or revoke, and removes it.
        leftover = "5a" * 16
        state = Path.home() / ".local/state/syq/enrollments"
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        (state / leftover).mkdir(mode=0o700)
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(state / leftover / "entry-key"))
        (state / leftover / "entry-key.pub").unlink()
        record = state / leftover / "pending.json"
        record.write_text(json.dumps({"version": 7, "id": list(bytes.fromhex(leftover)),
                                      "host": "destination", "port": None, "target_login": "toor"}))
        record.chmod(0o600)
        assert (leftover + "\tpending\ttoor@destination") in run("syq", "receiver", "list")
        for attempt, removed in ((1, True), (2, False)):
            name = f"toor-secret-{attempt}"
            with running(command(name, path=secret, account=alias)) as (process, output):
                decide(setup='Also sets up restricted copying on "toor@destination"', source=alias)
                text = finish(process, output, success=False)
            assert ("toor@destination logs in as user ID 0, which that server calls root; restricted"
                    " copying works only under that name, so use root@destination instead") in text, text
            assert (f"removed enrollment {leftover}, which an earlier attempt left pending" in text) == removed, text
            assert "remains pending" not in text, text
            absent(name)
            assert not (state / leftover).exists()
            assert alias_home() == alias_before
            remote(alias, "test ! -e ~/.local/lib/syq && test ! -e ~/.local/share/syq"
                   " && ! grep -s -q syq-enrollment: ~/.ssh/authorized_keys")
            assert pending() == []
            assert [line for line in run("syq", "receiver", "list").splitlines()
                    if "\ttoor@destination" in line] == []
        print("Source downloads passed", flush=True)
    finally:
        for enrollment in enrollments("root@destination"):
            run("syq", "receiver", "revoke", enrollment)
        for line in run("syq", "receiver", "list").splitlines():
            if "\ttoor@destination" in line:
                subprocess.run(["syq", "receiver", "revoke", line.split("\t")[0]],
                               capture_output=True, timeout=60)
        if "home" in roots:
            remote("destination", "rm -rf -- ~/" + shlex.quote(roots.pop("home")))
        for host, root in roots.items():
            remote(host, "rm -rf -- " + shlex.quote(root))


if __name__ == "__main__":
    main()
