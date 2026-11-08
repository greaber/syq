"""A requester on a third machine copies between two other servers with one
approval from an SSH authorization provider, which can't tell which server
asks. The provider is a disposable SSH listener for the runner's account,
which holds the lab's key; the requester logs in to it with a key of its own.
All paths are disposable."""
import contextlib
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time


NATIVE_PATH = "PATH=/usr/bin:/bin:/usr/local/bin"


def run(*args, stdin=None, success=True, env=None):
    result = subprocess.run(args, input=stdin, capture_output=True, text=True,
                            timeout=60, env=env)
    assert (result.returncode == 0) == success, (args, result)
    return result.stdout


def remote(host, command, **kwargs):
    return run("ssh", host, command, **kwargs)


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


def cleanup_actions(actions):
    original_failure = sys.exc_info()[1]
    failures = []
    for description, action in actions:
        try:
            action()
        except Exception as error:
            failures.append((description, repr(error)))
    if failures:
        print("Provider fixture cleanup failures:", failures, flush=True)
        if original_failure is None:
            raise AssertionError(failures)


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
            print("Waiting for the provider-approved copy", flush=True)
            assert time.monotonic() < deadline, "provider-approved copy exceeded its deadline"
    text = os.pread(output.fileno(), 1024 * 1024, 0).decode(errors="replace")
    print(text, end="", flush=True)
    assert status != 124, "provider-approved copy reached its safety timeout"
    assert (status == 0) == success, (status, text)
    return text


@contextlib.contextmanager
def provider_sshd(root, public_key, environment):
    """Only this disposable listener permits local Unix forwarding, and only
    the requester's own key logs in to it."""
    key = root / "host_key"
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
    authorized = root / "authorized_keys"
    authorized.write_text(public_key)
    authorized.chmod(0o600)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    config = root / "sshd_config"
    max_sessions = 1 if os.environ.get("SYQ_REAL_SSH_PROFILE") == "max-sessions-1" else 10
    config.write_text("\n".join([
        "Port " + str(port), "ListenAddress 127.0.0.1", "AddressFamily inet",
        "HostKey " + str(key), "PidFile " + str(root / "sshd.pid"),
        "AuthorizedKeysFile " + str(authorized), "StrictModes yes", "AllowUsers syq",
        "AuthenticationMethods publickey", "PubkeyAuthentication yes",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no", "UsePAM no",
        "UseDNS no", "AllowAgentForwarding no",
        # OpenSSH 9.2 initializes shared local-forward permissions from the
        # TCP flag; denying it also denies Unix socket connections.
        "AllowTcpForwarding local", "AllowStreamLocalForwarding local",
        "X11Forwarding no", "PermitTTY no",
        "MaxSessions " + str(max_sessions), "LogLevel VERBOSE",
        # OpenSSH uses only the first SetEnv directive.
        "SetEnv XDG_CONFIG_HOME=" + environment["XDG_CONFIG_HOME"]
        + " XDG_RUNTIME_DIR=" + environment["XDG_RUNTIME_DIR"], "",
    ]))
    sshd_environment = environment.copy()
    # The provider's service has the lab's agent. Logins to it do not.
    sshd_environment.pop("SSH_AUTH_SOCK", None)
    sshd_environment.pop("SSH_AGENT_PID", None)
    run("/usr/sbin/sshd", "-t", "-f", str(config), env=sshd_environment)
    with (root / "sshd.log").open("w+") as log:
        process = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                   env=sshd_environment, start_new_session=True)

        def ready():
            assert process.poll() is None, "fixture provider sshd exited"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    return True
            except OSError:
                return False
        try:
            wait_for("fixture provider SSH listener", ready, timeout=15)
            yield port, key.with_suffix(".pub").read_text()
        except BaseException:
            log.seek(0)
            print(log.read(), flush=True)
            raise
        finally:
            cleanup_actions([
                ("provider persistence", lambda: run("syq", "persist", "off", env=environment)),
                ("fixture provider sshd", lambda: stop(process)),
            ])


def enrollments():
    rows = {}
    for line in run("syq", "receiver", "list").splitlines():
        fields = line.split("\t")
        if len(fields) >= 3 and fields[1] == "active":
            rows[fields[2]] = fields[0]
    return rows


def digest(host, path):
    return remote(host, "sha256sum " + shlex.quote(path)).split()[0]


def main():
    config = Path.home() / ".ssh/config"
    original = config.read_bytes()
    roots = {}
    requester_config = None
    created_source_enrollment = False
    scopes = []
    requester_environment = []

    def requester(*args, **kwargs):
        return remote("requester", shlex.join([*requester_environment, *args]), **kwargs)

    try:
        # The requester is a separate account on this machine, without the
        # lab's key; it logs in to the provider with a key of its own.
        config.write_bytes(original + b"\nHost requester\n    HostName 127.0.0.1\n    User longhome\n"
                           b"    BatchMode yes\n    IdentityFile /home/syq/.ssh/id_ed25519\n"
                           b"    IdentitiesOnly yes\n    StrictHostKeyChecking yes\n"
                           b"    UserKnownHostsFile /home/syq/.ssh/known_hosts\n"
                           b"    GlobalKnownHostsFile /dev/null\n    UpdateHostKeys no\n")
        with (Path.home() / ".ssh/known_hosts").open("a") as known_hosts:
            known_hosts.write(run("ssh-keyscan", "-T", "5", "-t", "ed25519", "127.0.0.1"))
        for host in ("requester", "source", "destination"):
            roots[host] = remote(host, "mktemp -d /tmp/syq-pbetween.XXXXXX").strip()
        a, b, c = (roots[host] for host in ("requester", "source", "destination"))
        # Its own short directories: the account's home is too long for the
        # provider connection's sockets.
        requester_environment[:] = ["env", NATIVE_PATH, "XDG_CONFIG_HOME=" + a + "/c",
                                    "XDG_RUNTIME_DIR=" + a + "/r"]
        requester("mkdir", "-m", "700", a + "/c", a + "/r")
        remote("requester", 'test -z "${SSH_AUTH_SOCK:-}" && test ! -r /home/syq/.ssh/id_ed25519')
        requester("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", a + "/provider_key")
        public_key = requester("cat", a + "/provider_key.pub")
        requester_config = json.loads(remote("requester", "python3 -c " + shlex.quote(
            "from pathlib import Path; import json; p=Path.home()/'.ssh/config'; "
            "print(json.dumps({'content': p.read_text() if p.exists() else None}))")))
        # Start from a source without an enrollment, so the first copy sets
        # it up through the provider.
        if "syq@source" in enrollments():
            run("syq", "receiver", "revoke", enrollments()["syq@source"])
        remote("source", "dd if=/dev/urandom of=" + shlex.quote(b + "/data")
               + " bs=1M count=4 status=none")
        expected = digest("source", b + "/data")
        requester("python3", "-c", "from pathlib import Path; import sys; "
                  "Path(sys.argv[1]).write_bytes(b'upload\\n')", a + "/upload")

        # sshd StrictModes checks every directory above authorized_keys, so
        # its files live below the account's private ~/.ssh.
        with tempfile.TemporaryDirectory(prefix="syq-pbetween-", dir=Path.home() / ".ssh") as temporary:
            root = Path(temporary)
            for directory in (root / "config", root / "runtime"):
                directory.mkdir(mode=0o700)
            provider_environment = os.environ.copy()
            provider_environment.update(XDG_CONFIG_HOME=str(root / "config"),
                                        XDG_RUNTIME_DIR=str(root / "runtime"))
            with provider_sshd(root, public_key, provider_environment) as (port, host_key):
                requester("python3", "-c", "from pathlib import Path; import sys; "
                          "Path(sys.argv[1]).write_text(sys.stdin.read())", a + "/known_hosts",
                          stdin="[127.0.0.1]:{} {}".format(port, host_key))
                prefix = ("Host provider\n    HostName 127.0.0.1\n    Port {}\n    User syq\n"
                          "    IdentityFile {}\n    IdentityAgent none\n    IdentitiesOnly yes\n"
                          "    BatchMode yes\n    StrictHostKeyChecking yes\n"
                          "    UserKnownHostsFile {}\n    GlobalKnownHostsFile /dev/null\n"
                          "    UpdateHostKeys no\n"
                          "Host source destination\n    User syq\n").format(
                              port, a + "/provider_key", a + "/known_hosts")
                remote("requester", "python3 -c " + shlex.quote(
                    "from pathlib import Path; import sys; p=Path.home()/'.ssh/config'; "
                    "p.parent.mkdir(mode=0o700, exist_ok=True); "
                    "p.write_text(sys.stdin.read() + (p.read_text() if p.exists() else '')); "
                    "p.chmod(0o600)"), stdin=prefix)
                run("syq", "persist", "receive", "on", "--notify", "off", env=provider_environment)

                def pending():
                    return json.loads(run("syq", "persist", "receive", "pending", "--json",
                                          env=provider_environment))

                def command(name, extra=(), auth=("--auth-from", "provider"), scope=None):
                    argv = ["syq", "cp", *(("--pscope", scope) if scope else ()),
                            "--from", "source", b + "/data", "--to", "destination",
                            "--as", c + "/" + name, *auth,
                            "--performance-tuning", "workers=2", "--no-progress",
                            "--results", a + "/" + name + ".ndjson", *extra]
                    script = ('test -z "${SSH_AUTH_SOCK:-}" && exec '
                              + shlex.join([*requester_environment, *argv]))
                    return shlex.join(["timeout", "120", "sh", "-c", script])

                def checked(request):
                    """A provider's prompt for a copy between two servers."""
                    assert "kind" not in request, request
                    assert request["from"].startswith(
                        '"a server logged in to provider account syq (provider profile @'), request
                    assert request["permission"].startswith(
                        "syq can't confirm which server is asking: any machine that can log in"
                        " to provider account syq over SSH can send this request."), request
                    assert '"source" runs the copy' in request["permission"], request
                    assert ' on "destination" using your SSH access' in request["destination"], request
                    return request

                def decide(allow=True):
                    requests = json.loads(run("syq", "persist", "receive", "pending", "--json",
                                              "--wait", "--timeout", "20", env=provider_environment))
                    assert len(requests) == 1, requests
                    request = checked(requests[0])
                    run("syq", "persist", "receive", "approve" if allow else "deny", request["id"],
                        env=provider_environment)
                    return request

                def assert_copied(name):
                    records = [json.loads(line) for line in requester(
                        "cat", a + "/" + name + ".ndjson").splitlines()]
                    terminal = records[-1]
                    assert terminal["type"] == "result" and terminal["status"] == "success", terminal
                    assert terminal["files_transferred"] == 1 and terminal["errors"] == 0, terminal
                    # The destination's own record of the file, which the
                    # requester checked.
                    assert [record["action"] for record in records
                            if record["type"] == "operation_result"] == ["transfer_file"], records
                    assert digest("destination", c + "/" + name) == expected
                    assert pending() == []

                print("case: a dry run through the provider does not set restricted copying up", flush=True)
                with running(command("dry", ("--dry-run",))) as (process, output):
                    text = finish(process, output, success=False)
                assert "a dry run does not set up restricted copying on syq@source" in text, text
                assert pending() == []
                assert "syq@source" not in enrollments()

                print("case: one provider approval enrolls the source and copies between the servers", flush=True)
                with running(command("first")) as (process, output):
                    request = decide()
                    assert 'Also sets up restricted copying on "source"' in request["permission"], request
                    text = finish(process, output)
                assert "for provider to approve this copy from source to destination" in text, text
                assert_copied("first")
                assert "syq@source" in enrollments() and "syq@destination" in enrollments()
                created_source_enrollment = True
                # The requester got no login of its own to either account.
                assert json.loads(requester("syq", "persist", "status", "--json"))["authorized_ssh"] == []

                print("case: a copy the provider denies changes nothing", flush=True)
                with running(command("denied")) as (process, output):
                    decide(allow=False)
                    finish(process, output, success=False)
                remote("destination", "test ! -e " + shlex.quote(c + "/denied"))

                print("case: a saved provider choice approves a copy between servers", flush=True)
                requester("syq", "persist", "auth-from", "provider", "--for", "source")
                with running(command("saved", auth=())) as (process, output):
                    decide()
                    finish(process, output)
                assert_copied("saved")
                requester("syq", "persist", "auth-from", "--reset", "--for", "source")

                print("case: each provider login's copy request gets its own decision", flush=True)
                for _ in range(2):
                    scopes.append(requester("syq", "persist", "on", "--ephemeral").strip())
                with running(command("picked", scope=scopes[0])) as (picked, picked_output), \
                        running(command("passed", scope=scopes[1])) as (passed, passed_output):
                    requests = wait_for("both logins' requests", lambda: (
                        lambda requests: requests if len(requests) == 2 else None)(pending()))
                    for request in requests:
                        checked(request)
                    chosen = [request for request in requests if "/picked" in request["destination"]]
                    assert len(chosen) == 1, requests
                    other = next(request for request in requests if request is not chosen[0])
                    run("syq", "persist", "receive", "deny", other["id"], env=provider_environment)
                    finish(passed, passed_output, success=False)
                    assert [request["id"] for request in pending()] == [chosen[0]["id"]]
                    run("syq", "persist", "receive", "approve", chosen[0]["id"], env=provider_environment)
                    finish(picked, picked_output)
                assert_copied("picked")
                remote("destination", "test ! -e " + shlex.quote(c + "/passed"))
                for scope in list(scopes):
                    requester("syq", "persist", "--pscope", scope, "off")
                    scopes.remove(scope)

                print("case: an upload that selects the provider asks for account access", flush=True)
                upload = shlex.join(["timeout", "120", "sh", "-c", 'test -z "${SSH_AUTH_SOCK:-}" && exec '
                                     + shlex.join([*requester_environment, "syq", "cp", a + "/upload",
                                                   "--to", "destination", "--as", c + "/upload",
                                                   "--auth-from", "provider", "--no-progress"])])
                with running(upload) as (process, output):
                    requests = json.loads(run("syq", "persist", "receive", "pending", "--json",
                                              "--wait", "--timeout", "20", env=provider_environment))
                    assert len(requests) == 1 and requests[0]["kind"] == "provider_ssh", requests
                    run("syq", "persist", "receive", "deny", requests[0]["id"], env=provider_environment)
                    finish(process, output, success=False)
                remote("destination", "test ! -e " + shlex.quote(c + "/upload"))
                requester("syq", "persist", "off")
                assert pending() == []
                print("Copies between two other servers through a provider passed", flush=True)
    finally:
        actions = [("requester scope", lambda scope=scope: requester("syq", "persist", "--pscope", scope, "off"))
                   for scope in scopes]
        if "requester" in roots:
            actions.extend([
                ("requester saved choice", lambda: requester("syq", "persist", "auth-from", "--reset",
                                                             "--for", "source")),
                ("requester persistence", lambda: requester("syq", "persist", "off")),
            ])
        if created_source_enrollment:
            actions.append(("source enrollment", lambda: "syq@source" in enrollments()
                            and run("syq", "receiver", "revoke", enrollments()["syq@source"])))
        if requester_config is not None:
            actions.append(("requester SSH config", lambda: remote("requester", "python3 -c " + shlex.quote(
                "from pathlib import Path; import json, sys; p=Path.home()/'.ssh/config'; "
                "value=json.load(sys.stdin)['content']; "
                "p.write_text(value) if value is not None else p.unlink()"),
                stdin=json.dumps(requester_config))))
        actions.extend((host + " files", lambda root=root, host=host: remote(host, "rm -rf -- " + shlex.quote(root)))
                       for host, root in roots.items())
        actions.append(("runner SSH config", lambda: config.write_bytes(original)))
        cleanup_actions(actions)


if __name__ == "__main__":
    main()
