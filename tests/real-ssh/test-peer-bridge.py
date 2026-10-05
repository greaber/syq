"""Account-approved A starts direct B-to-C copies without forwarding credentials."""
import contextlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time


# Each probe runs as the ordinary account whose authority it inspects. Inputs,
# including the late-worker capability, travel over stdin and are never logged.
PROBES = {
    "pool_spares": r'''
from pathlib import Path
found = {}
for p in Path("/proc").iterdir():
    if not p.name.isdigit():
        continue
    try:
        args = p.joinpath("cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
        if not args or Path(args[0]).name != "ssh" or "-S" not in args or "--server" not in args[-1]:
            continue
        control = args[args.index("-S") + 1]
        stat = p.joinpath("stat").read_text().rsplit(") ", 1)[1].split()
        parent = Path("/proc", stat[1], "cmdline").read_bytes().split(b"\0")
        if b"--session-pool" in parent and stat[0] != "Z":
            found[control] = [int(p.name), stat[19]]
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
print(json.dumps({control: found[control] for control in v["controls"] if control in found}))
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
    "key_directories": r'''
from pathlib import Path
import os, tempfile
root = Path(tempfile.gettempdir())
paths = list(root.glob("syq-copy-key-*")) + list(root.glob("syq-peer-*/syq-copy-key-*"))
owned = []
for p in paths:
    try:
        if p.stat().st_uid == os.getuid():
            owned.append(str(p))
    except FileNotFoundError:
        pass
print(json.dumps(sorted(owned)))
''',
    "partial": r'''
import hashlib
from pathlib import Path
root = Path(v["root"])
matches = list(root.glob("." + v["name"] + ".syq-tmp.*"))
print(json.dumps(any(hashlib.sha256(p.open("rb").read(1 << 20)).hexdigest() == v["digest"] for p in matches)))
''',
    "ticket": r'''
from pathlib import Path
import re
p = Path.home()/".ssh/authorized_keys"
text = p.read_text() if p.exists() else ""
tickets = [re.search(r"--return-ssh-worker ([A-Za-z0-9_-]+)", line).group(1)
           for line in text.splitlines() if "syq-copy-worker-" in line]
assert len(tickets) <= 1, "unexpected concurrent copy authorization"
print(json.dumps(tickets[0] if tickets else None))
''',
    "forced_command": r'''
from pathlib import Path
import socket, subprocess
workers = []
for p in Path("/proc").iterdir():
    if not p.name.isdigit():
        continue
    try:
        if p.joinpath("exe").readlink() != Path("/usr/bin/ssh"):
            continue
        args = p.joinpath("cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
        if args[-1:] == ["syq-copy-worker"]:
            workers.append(args)
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
assert workers, "source has no direct SSH copy worker"
args = workers[0]
assert socket.gethostbyname(args[-2]) == socket.gethostbyname("destination")
assert args[args.index("-l") + 1] == "syq"
for option in ["IdentityAgent=none", "ControlPath=none", "ProxyCommand=none", "ClearAllForwardings=yes"]:
    assert option in args, "worker has ambient SSH authority"
key = Path(args[args.index("-i") + 1])
assert key.parent.name.startswith("syq-copy-key-")
assert key.stat().st_mode & 0o777 == 0o600
# The server must ignore this requested command, even though the key can enter
# the live transfer's worker. EOF finishes that worker without a valid Hello.
import shlex
args[-1] = "printf escaped > " + shlex.quote(v["outside"]) + "; printf SHELL_ESCAPE"
try:
    result = subprocess.run(args, input=b"", capture_output=True, timeout=15)
except subprocess.TimeoutExpired:
    raise AssertionError("forced-command probe timed out") from None
assert result.returncode == 0, "live copy key could not enter its forced worker"
assert b"SHELL_ESCAPE" not in result.stdout, "copy key executed a shell command"
print("true")
''',
    "workers": r'''
from pathlib import Path
import socket
workers = []
for p in Path("/proc").iterdir():
    if not p.name.isdigit():
        continue
    try:
        if p.joinpath("exe").readlink() != Path("/usr/bin/ssh"):
            continue
        args = p.joinpath("cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
        if args[-1:] == ["syq-copy-worker"]:
            assert socket.gethostbyname(args[-2]) == socket.gethostbyname("destination")
            stat = p.joinpath("stat").read_text().rsplit(") ", 1)[1].split()
            workers.append([int(p.name), stat[19]])
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
print(json.dumps(workers))
''',
    "copy_processes": r'''
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
        processes[int(p.name)] = (args, int(stat[1]), stat[19])
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
copies = [pid for pid, (args, _, _) in processes.items()
          if args and Path(args[0]).name == "syq" and "--delegated-operands-b64" in args
          and operand in args]
assert len(copies) == 1, "expected one delegated source copy"
owned = []
pid = copies[0]
for _ in range(8):
    args, parent, started = processes[pid]
    owned.append([pid, started])
    if args[-1:] == ["--peer-coordinator"]:
        break
    pid = parent
else:
    raise AssertionError("source copy has no peer coordinator parent")
print(json.dumps(owned))
''',
    "workers_exited": r'''
from pathlib import Path
active = []
for pid, started in v["workers"]:
    try:
        stat = Path("/proc", str(pid), "stat").read_text().rsplit(") ", 1)[1].split()
        if stat[19] == started and stat[0] != "Z":
            active.append(pid)
    except FileNotFoundError:
        pass
print(json.dumps(not active))
''',
    "kill_requester": r'''
from pathlib import Path
import os, signal
pid = int(Path(v["pidfile"]).read_text())
args = Path("/proc", str(pid), "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
assert Path(args[0]).name == "syq" and args[1] == "cp", "PID is not the requesting syq copy"
assert v["destination"] in args, "PID belongs to a different copy"
os.kill(pid, signal.SIGKILL)
print("true")
''',
    "late_worker": r'''
import subprocess
try:
    result = subprocess.run(["syq", "--return-ssh-worker", v["ticket"]],
                            input=b"", capture_output=True, timeout=15)
except subprocess.TimeoutExpired:
    raise AssertionError("late-worker probe timed out") from None
assert result.returncode != 0, "closed copy admitted a late worker"
print("true")
''',
}


def run(*args, stdin=None, success=True):
    result = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=40)
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
            # Predicates that return a capability are reduced to booleans by
            # their caller, so neither progress nor timeout reveals it.
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
def running(command, *, pidfile=None):
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(["ssh", "requester", command], stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=output, start_new_session=True)
        try:
            yield process, output
        except BaseException:
            print(os.pread(output.fileno(), 1024 * 1024, 0).decode(errors="replace"), flush=True)
            raise
        finally:
            if pidfile is not None and process.poll() is None:
                remote("requester", "if test -f " + shlex.quote(pidfile)
                       + "; then kill -TERM $(cat " + shlex.quote(pidfile) + ") 2>/dev/null || true; fi")
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            stop(process)


def finish(process, output, success=True):
    deadline, offset = time.monotonic() + 60, 0
    while True:
        try:
            status = process.wait(timeout=5)
            break
        except subprocess.TimeoutExpired:
            data = os.pread(output.fileno(), 1024 * 1024, offset)
            offset += len(data)
            print(data.decode(errors="replace"), end="", flush=True)
            print("Waiting for peer bridge", flush=True)
            assert time.monotonic() < deadline, "peer bridge exceeded its deadline"
    text = os.pread(output.fileno(), 1024 * 1024, 0).decode(errors="replace")
    print(text, end="", flush=True)
    assert status != 124, "peer bridge reached its safety timeout"
    assert (status == 0) == success, (status, text)
    return text


def requester(*args, **kwargs):
    return remote("requester", shlex.join(["syq", *args]), **kwargs)


def no_pending():
    assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []


def approve_account(host, allow=True, *, ask=True):
    # Native ssh implements keeper termination directly; the lab tracing shell
    # wrapper deliberately remains outside this signal/lifetime test.
    command = shlex.join(["env", "PATH=/usr/bin:/bin:/usr/local/bin", "syq", "persist",
                          "connect", host, "--auth-from", "@laptop"])
    with running(command) as (process, output):
        if ask:
            pending = json.loads(run("syq", "persist", "receive", "pending", "--json",
                                     "--wait", "--timeout", "15"))
            assert len(pending) == 1, pending
            request = pending[0]
            assert request["kind"] == "ssh" and request["reusable"], request
            assert request["destination"] == "syq@" + host, request
            account = request["account"]["destination"]
            assert account["trusted_host"] == host, request
            assert account["endpoint"] == {"user": "syq", "host": host, "port": 22}, request
            assert "full authority" in request["permission"], request
            run("syq", "persist", "receive", "approve" if allow else "deny", request["id"])
        finish(process, output, success=allow)
    no_pending()


def fingerprint(host):
    return remote(host, "if test -f ~/.ssh/authorized_keys; then sha256sum ~/.ssh/authorized_keys; "
                  "else printf absent; fi")


def digest(host, path):
    return remote(host, "sha256sum " + shlex.quote(path)).split()[0]


def assert_no_native_credentials(host):
    remote(host, 'test -z "${SSH_AUTH_SOCK:-}" && test ! -e ~/.ssh/id_ed25519 && '
           'test ! -e ~/.ssh/id_rsa && test ! -r /run/lab/id_ed25519')
    command = shlex.join(["/usr/bin/ssh", "-F", "/dev/null", "-a", "-o", "BatchMode=yes",
                          "-o", "IdentityAgent=none", "-o", "IdentityFile=none",
                          "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                          "-o", "ConnectTimeout=5", "syq@destination", "true"])
    remote(host, command, success=False)


def main():
    config = Path.home()/".ssh/config"
    original = config.read_bytes()
    requester_config = None
    roots = {}
    try:
        config.write_bytes(original + b"\nHost requester\n    HostName 127.0.0.1\n    User longhome\n"
                           b"    BatchMode yes\n    IdentityFile /home/syq/.ssh/id_ed25519\n"
                           b"    IdentitiesOnly yes\n    StrictHostKeyChecking yes\n"
                           b"    UserKnownHostsFile /home/syq/.ssh/known_hosts\n"
                           b"    GlobalKnownHostsFile /dev/null\n    UpdateHostKeys no\n")
        with (Path.home()/".ssh/known_hosts").open("a") as known_hosts:
            known_hosts.write(run("ssh-keyscan", "-T", "5", "-t", "ed25519", "127.0.0.1"))
        for host in ("requester", "source", "destination"):
            roots[host] = remote(host, "mktemp -d /tmp/syq-peer-bridge.XXXXXX").strip()
        a, b, c = (roots[host] for host in ("requester", "source", "destination"))
        assert remote("requester", "id -un").strip() == "longhome"
        # The requester chooses the accounts; the laptop supplies their trust
        # and authentication. These aliases carry no keys or agent authority.
        requester_config = json.loads(remote("requester", "python3 -c " + shlex.quote(
            "from pathlib import Path; import json; p=Path.home()/'.ssh/config'; "
            "print(json.dumps({'content': p.read_text() if p.exists() else None}))")))
        remote("requester", "python3 -c " + shlex.quote(
            "from pathlib import Path; import sys; p=Path.home()/'.ssh/config'; "
            "p.parent.mkdir(mode=0o700, exist_ok=True); "
            "p.write_text(sys.stdin.read() + (p.read_text() if p.exists() else ''))"),
            stdin="Host source destination\n    User syq\n")
        remote("requester", "test ! -r /home/syq/.ssh/id_ed25519")
        assert_no_native_credentials("requester")
        assert_no_native_credentials("source")
        # Earlier fixtures must not leave B a full-account login to C.
        assert json.loads(remote("source", "syq persist status --json"))["authorized_ssh"] == []
        run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off")
        run("syq", "persist", "connect", "requester")
        run("syq", "persist", "receive", "wait", "requester", "--timeout", "30")

        print("case: the separate requester needs explicit reusable account approvals", flush=True)
        approve_account("destination", allow=False)
        assert json.loads(requester("persist", "status", "--json"))["authorized_ssh"] == []
        approve_account("source")
        approve_account("destination")
        rows = json.loads(requester("persist", "status", "--json"))["authorized_ssh"]
        assert len(rows) == 2 and all(row["connected"] for row in rows), rows
        assert requester("ssh", "--auth-from", "@laptop", "source", "--", "id -un").strip() == "syq"
        no_pending()
        # A focused run may begin without this file; worker-key cleanup leaves
        # an empty file, so establish the same baseline as the full suite.
        remote("destination", "mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys")
        b_keys, c_keys = fingerprint("source"), fingerprint("destination")
        initial_key_directories = probe("source", "key_directories")

        def no_copy_keys():
            return probe("source", "key_directories") == initial_key_directories

        remote("source", "dd if=/dev/urandom of=" + shlex.quote(b + "/data")
               + " bs=1M count=8 status=none && chmod 444 " + shlex.quote(b + "/data"))
        expected = digest("source", b + "/data")
        prefix = remote("source", "dd if=" + shlex.quote(b + "/data")
                        + " bs=1M count=1 status=none | sha256sum").split()[0]
        outside = c + "/outside-copy"

        attempts = {}

        def copy_command(name, extra=(), auth=("--auth-from", "@laptop"), source="data"):
            attempts[name] = attempts.get(name, 0) + 1
            argv = ["syq", "cp", "--from", "source", b + "/" + source, "--to", "destination",
                    "--as", c + "/" + name, *auth, "--performance-tuning", "workers=2",
                    "--no-progress", "--results", f"{a}/{name}.{attempts[name]}.ndjson", *extra]
            command = ("test -z \"${SSH_AUTH_SOCK:-}\" && echo $$ > " + shlex.quote(a + "/pid")
                       + " && exec env PATH=/usr/bin:/bin:/usr/local/bin " + shlex.join(argv))
            # The recorded PID becomes syq itself. Killing timeout or a tracing
            # shell would test a different process-lifetime boundary.
            return shlex.join(["timeout", "90", "sh", "-c", command])

        def copying(name, extra=(), auth=("--auth-from", "@laptop"), source="data"):
            return running(copy_command(name, extra, auth, source), pidfile=a + "/pid")

        def partial(name, expected_prefix=prefix):
            return probe("destination", "partial", root=c, name=name, digest=expected_prefix)

        def assert_results(name, expected_digest=expected):
            records = [json.loads(line) for line in remote("requester", "cat "
                       + shlex.quote(f"{a}/{name}.{attempts[name]}.ndjson")).splitlines()]
            terminal = records[-1]
            assert terminal["type"] == "result" and terminal["status"] == "success", terminal
            assert terminal["provenance"] == "receiver_attested", terminal
            assert terminal["receipt_status"] == "clean", terminal
            assert terminal["files_transferred"] == 1, terminal
            assert any(record["type"] == "final_state" and record["provenance"] == "receiver_attested"
                       for record in records), records
            assert digest("destination", c + "/" + name) == expected_digest
            assert fingerprint("source") == b_keys
            wait_for("destination temporary key cleanup", lambda: fingerprint("destination") == c_keys)
            assert json.loads(remote("source", "syq persist status --json"))["authorized_ssh"] == []
            no_pending()
            wait_for("source temporary key directory cleanup", no_copy_keys)

        print("case: peer TCP preserves warm helpers unless SSH refuses a session", flush=True)
        controls = {row["control"] for row in rows}
        for host, path in (("source", b + "/da"), ("destination", c + "/")):
            words = ["syq", "cp", "--auth-from", "@laptop", "--from", host, path]
            remote("requester", shlex.join([
                "env", "PATH=/usr/bin:/bin:/usr/local/bin", "syq", "completion",
                "__complete", "fish", str(len(words) - 1), "--", *words]))
        def spares():
            return probe("requester", "pool_spares", controls=list(controls))

        wait_for("prepared helpers on both approved masters",
                 lambda: set(spares()) == controls)
        warm_spares = spares()
        assert set(warm_spares) == controls, "prepared helpers disappeared before copy"
        no_pending()
        port = 47811
        with copying("tcp", ("--tcp-ports", f"{port}-{port}",
                             "--resource-limits", "bandwidth=1M")) as (process, output):
            wait_for("direct B-to-C TCP connection", lambda: probe("source", "tcp", port=port))
            wait_for("TCP copy data", lambda: partial("tcp"))
            assert fingerprint("destination") == c_keys
            finish(process, output)
        assert_results("tcp")
        after = json.loads(requester("persist", "status", "--json"))["authorized_ssh"]
        assert {row["control"] for row in after} == controls, "peer copy replaced approved masters"
        assert all(row["connected"] for row in after), after

        # TCP uses one session on each master; SSH key setup needs another
        # beside C's live control. This limit must fail without a different route.
        if os.environ.get("SYQ_REAL_SSH_PROFILE") == "max-sessions-1":
            print("case: one-session destination refuses concurrent SSH worker setup", flush=True)
            with copying("ssh-session-limit", ("--no-tcp",)) as (process, output):
                # Session contention uses the normal bounded worker retries.
                text = finish(process, output, success=False)
                assert "MaxSessions >= 2" in text, text
            remote("destination", "test ! -e " + shlex.quote(c + "/ssh-session-limit"))
            wait_for("session-limit destination key cleanup", lambda: fingerprint("destination") == c_keys)
            assert fingerprint("source") == b_keys
            no_pending()
            return

        assert spares() == warm_spares, "successful TCP copy discarded warm completion helpers"
        print("case: blocked TCP falls back to direct restricted SSH with saved providers", flush=True)
        for host in ("source", "destination"):
            requester("persist", "auth-from", "@laptop", "--for", host)
        blocked = os.environ["SYQ_REAL_SSH_BLOCKED_TCP_PORT"]
        with copying("fallback", ("--tcp-ports", blocked + "-" + blocked,
                                  "--resource-limits", "bandwidth=512K"), auth=()) as (process, output):
            wait_for("fallback SSH authorization", lambda: bool(probe("destination", "ticket")))
            wait_for("fallback copy data", lambda: partial("fallback"))
            assert probe("source", "forced_command", outside=outside)
            remote("destination", "test ! -e " + shlex.quote(outside))
            finish(process, output)
        assert_results("fallback")
        assert spares() == warm_spares, "successful SSH fallback discarded warm completion helpers"

        print("case: completion consumes the helper preserved across peer copies", flush=True)
        words = ["syq", "cp", "--auth-from", "@laptop", "--from", "source", b + "/da"]
        candidates = remote("requester", shlex.join([
            "env", "PATH=/usr/bin:/bin:/usr/local/bin", "syq", "completion",
            "__complete", "fish", str(len(words) - 1), "--", *words]))
        assert b + "/data" in candidates, candidates
        source_control = next(row["control"] for row in after if row["requested"]["host"] == "source")
        assert spares().get(source_control) != warm_spares[source_control], "completion did not consume its spare"

        print("case: SSH-only source coordination restricts the key and cancels its authority", flush=True)
        with copying("cancelled", ("--no-tcp", "--coordinate-at", "src",
                                   "--resource-limits", "bandwidth=256K")) as (process, output):
            wait_for("SSH-only authorization", lambda: bool(probe("destination", "ticket")))
            ticket = probe("destination", "ticket")
            assert ticket
            wait_for("SSH-only copy data", lambda: partial("cancelled"))
            assert probe("source", "forced_command", outside=outside)
            remote("destination", "test ! -e " + shlex.quote(outside))
            remote("requester", "kill -TERM $(cat " + shlex.quote(a + "/pid") + ")")
            finish(process, output, success=False)
        wait_for("cancelled source key directory cleanup", no_copy_keys)
        wait_for("cancelled destination key cleanup", lambda: fingerprint("destination") == c_keys)
        assert probe("destination", "late_worker", ticket=ticket)
        remote("destination", "test ! -e " + shlex.quote(c + "/cancelled"))
        assert fingerprint("source") == b_keys
        no_pending()
        with copying("cancelled", ("--no-tcp",)) as (process, output):
            finish(process, output)
        assert_results("cancelled")

        print("case: requester SIGKILL closes direct workers and the copy authority", flush=True)
        # More than the active workers can publish before the kill: this checks
        # loss during transfer rather than racing an already-admitted finalize.
        remote("source", "dd if=/dev/urandom of=" + shlex.quote(b + "/crash-data")
               + " bs=1M count=32 status=none")
        crash_digest = digest("source", b + "/crash-data")
        crash_prefix = remote("source", "dd if=" + shlex.quote(b + "/crash-data")
                              + " bs=1M count=1 status=none | sha256sum").split()[0]
        controls = {row["control"] for row in json.loads(requester("persist", "status", "--json"))["authorized_ssh"]}
        with copying("crashed", ("--no-tcp", "--resource-limits", "bandwidth=256K"),
                     source="crash-data") as (process, output):
            wait_for("copy before requester crash", lambda: partial("crashed", crash_prefix))
            ticket = probe("destination", "ticket")
            assert ticket
            workers = probe("source", "workers")
            assert workers, "crash copy has no direct B-to-C SSH worker"
            owned = probe("source", "copy_processes", destination=c + "/crashed")
            assert probe("requester", "kill_requester", pidfile=a + "/pid", destination=c + "/crashed")
            wait_for("copy and workers after requester crash", lambda: probe("source", "workers_exited", workers=workers + owned), timeout=5)
            wait_for("source key directory cleanup after requester crash", no_copy_keys)
            wait_for("destination key cleanup after requester crash", lambda: fingerprint("destination") == c_keys)
            assert probe("destination", "late_worker", ticket=ticket)
            finish(process, output, success=False)
        remote("destination", "test ! -e " + shlex.quote(c + "/crashed"))
        assert fingerprint("source") == b_keys
        assert_no_native_credentials("source")
        rows = json.loads(requester("persist", "status", "--json"))["authorized_ssh"]
        assert len(rows) == 2 and all(row["connected"] for row in rows), rows
        assert {row["control"] for row in rows} == controls, "requester crash replaced account authority"
        no_pending()
        with copying("crashed", ("--no-tcp",), source="crash-data") as (process, output):
            finish(process, output)
        assert_results("crashed", crash_digest)

        print("case: losing only C's account connection stops B's active data workers", flush=True)
        accounts = {row["requested"]["host"]: row for row in
                    json.loads(requester("persist", "status", "--json"))["authorized_ssh"]}
        destination_account = accounts["destination"]
        endpoint = destination_account["endpoint"]
        with copying("peer-loss", ("--no-tcp", "--resource-limits", "bandwidth=256K"),
                     source="crash-data") as (process, output):
            wait_for("copy before destination connection loss", lambda: partial("peer-loss", crash_prefix))
            workers = probe("source", "workers")
            assert workers
            owned = probe("source", "copy_processes", destination=c + "/peer-loss")
            remote("requester", shlex.join(["/usr/bin/ssh", "-F", "/dev/null", "-S", destination_account["control"],
                   "-o", "ControlMaster=no", "-o", "ProxyCommand=false", "-o", "BatchMode=yes",
                   "-l", endpoint["user"], "-p", str(endpoint["port"]), "-O", "exit", "--", endpoint["host"]]))
            wait_for("copy and workers after destination connection loss", lambda: probe("source", "workers_exited", workers=workers + owned), timeout=5)
            finish(process, output, success=False)
        wait_for("source key directory cleanup after connection loss", no_copy_keys)
        wait_for("destination key cleanup after connection loss", lambda: fingerprint("destination") == c_keys)
        remote("destination", "test ! -e " + shlex.quote(c + "/peer-loss"))
        rows = json.loads(requester("persist", "status", "--json"))["authorized_ssh"]
        assert len(rows) == 1 and rows[0]["connected"] and rows[0]["control"] == accounts["source"]["control"], rows
        assert requester("ssh", "--auth-from", "@laptop", "source", "--", "id -un").strip() == "syq"
        no_pending()
        approve_account("destination", ask=False)
        with copying("peer-loss", ("--no-tcp",), source="crash-data") as (process, output):
            finish(process, output)
        assert_results("peer-loss", crash_digest)

        print("case: withdrawing account authority cancels the bridge and requires new approval", flush=True)
        with copying("revoked", ("--no-tcp", "--resource-limits", "bandwidth=256K")) as (process, output):
            wait_for("copy before revocation", lambda: partial("revoked"))
            run("syq", "persist", "receive", "off", "--name", "laptop")
            finish(process, output, success=False)
        wait_for("revoked source key directory cleanup", no_copy_keys)
        wait_for("revoked destination key cleanup", lambda: fingerprint("destination") == c_keys)
        remote("destination", "test ! -e " + shlex.quote(c + "/revoked"))
        run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off")
        run("syq", "persist", "receive", "wait", "requester", "--timeout", "30")
        assert json.loads(requester("persist", "status", "--json"))["authorized_ssh"] == []
        no_pending()
        approve_account("source")
        approve_account("destination")
        with copying("revoked", ("--no-tcp",)) as (process, output):
            finish(process, output)
        assert_results("revoked")
        print("Direct account-approved peer bridge passed", flush=True)
    finally:
        if "requester" in roots:
            for host in ("source", "destination"):
                requester("persist", "auth-from", "--reset", "--for", host)
            requester("persist", "off")
        if requester_config is not None:
            remote("requester", "python3 -c " + shlex.quote(
                "from pathlib import Path; import json, sys; p=Path.home()/'.ssh/config'; "
                "value=json.load(sys.stdin)['content']; "
                "p.write_text(value) if value is not None else p.unlink()"),
                stdin=json.dumps(requester_config))
        for host, root in roots.items():
            remote(host, "rm -rf -- " + shlex.quote(root))
        config.write_bytes(original)


if __name__ == "__main__":
    main()
