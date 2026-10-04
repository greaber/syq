"""Laptop-approved account access over direct native SSH, in disposable paths."""
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import struct
import subprocess
import tempfile
import termios
import time


def run(*args, stdin=None, success=True):
    result = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=40)
    assert (result.returncode == 0) == success, (args, result)
    return result.stdout


def ready():
    run("syq", "persist", "receive", "wait", "source", "--timeout", "30")


def wait_for(description, predicate, timeout=10):
    deadline, progress = time.monotonic() + timeout, time.monotonic() + 2
    state = None
    while time.monotonic() < deadline:
        state = predicate()
        if state:
            return state
        if time.monotonic() >= progress:
            print("Waiting for", description, "last state:", state, flush=True)
            progress += 2
        time.sleep(.05)
    raise AssertionError(("Timed out", description, "last state", state))


def pending(allow=True, reusable=True, remember=False, target="syq@destination", endpoint=None):
    items = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
    assert len(items) == 1, items
    request = items[0]
    assert request["kind"] == "ssh", request
    assert target == request["destination"], request
    user, trusted_host = target.split("@", 1)
    destination = request["account"]["destination"]
    assert destination["trusted_host"] == trusted_host, request
    assert destination["endpoint"] == (endpoint or {"user": user, "host": trusted_host, "port": 22}), request
    assert "full authority" in request["permission"], request
    assert request["reusable"] == reusable, request
    if reusable:
        assert "commands and copies" in request["permission"], request
    run("syq", "persist", "receive", "approve" if allow else "deny", request["id"],
        *(["--remember"] if remember else []))
    run("syq", "persist", "receive", "approve", request["id"], success=False)


root = run("ssh", "source", "mktemp -d /tmp/syq-return-ssh.XXXXXX").strip()
destination_root = run("ssh", "destination", "mktemp -d /tmp/syq-return-ssh.XXXXXX").strip()
# Test the native OpenSSH child itself. The lab's tracing shell wrapper forks
# another client and does not implement the native client's signal lifecycle.
native_path = "PATH=/usr/bin:/bin:/usr/local/bin"


def source_command(command=(), *, tty=False, binary="/usr/local/bin/syq", target="destination"):
    args = [binary, "ssh", "--auth-from", "@laptop"]
    if tty:
        args.append("-t")
    args.append(target)
    if command:
        args.extend(["--", *command])
    return ('test -z "${SSH_AUTH_SOCK:-}" && test ! -e ~/.ssh/id_ed25519 && '
            'echo $$ > ' + shlex.quote(root + "/client") + ' && exec env ' + native_path + ' ' + shlex.join(args))


def execute(command, *, allow=True, status=0, data=b"", cancel=None, binary="/usr/local/bin/syq",
            ask=False, remember=False, target="destination", approval_target=None):
    with tempfile.TemporaryFile() as input_file, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        input_file.write(data)
        input_file.seek(0)
        process = subprocess.Popen(["ssh", "source", source_command(command, binary=binary, target=target)],
                                   stdin=input_file, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            if ask:
                pending(allow, remember=remember, target=approval_target or "syq@" + target)
            if cancel:
                wait_for("SSH command output", lambda: b"READY" in os.pread(stdout.fileno(), 4096, 0))
                if cancel == "interrupt":
                    run("ssh", "source", "kill -INT $(cat " + shlex.quote(root + "/client") + ")")
                else:
                    run("syq", "persist", "receive", "off", "--name", "laptop")
            deadline = time.monotonic() + 30
            while True:
                try:
                    actual = process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    print("Waiting for direct SSH:", command, "output:", os.pread(stdout.fileno(), 4096, 0), flush=True)
                    assert time.monotonic() < deadline, "SSH exceeded its fixture deadline"
            stdout.seek(0)
            stderr.seek(0)
            out, err = stdout.read(), stderr.read()
            assert actual == status, (actual, status, out, err)
            return out, err
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)


def interactive_shell():
    child, terminal = pty.fork()
    if child == 0:
        os.execvp("ssh", ["ssh", "-tt", "source", source_command(tty=True)])
    output = bytearray()
    reaped = False
    def read_until(expected):
        deadline, progress = time.monotonic() + 15, time.monotonic() + 3
        while expected not in output:
            if time.monotonic() > deadline:
                raise AssertionError(("terminal response missing", expected, bytes(output)))
            readable, _, _ = select.select([terminal], [], [], .2)
            if readable:
                try:
                    block = os.read(terminal, 16384)
                except OSError as error:
                    if error.errno == errno.EIO:
                        block = b""
                    else:
                        raise
                assert block, ("terminal closed early", bytes(output))
                output.extend(block)
            if time.monotonic() >= progress:
                print("Waiting for interactive shell:", bytes(output[-500:]), flush=True)
                progress += 3
    try:
        fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        os.write(terminal, b"printf '\\n__READY_SHELL__\\n'\n")
        read_until(b"\r\n__READY_SHELL__\r\n")
        fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack("HHHH", 37, 103, 0, 0))
        os.write(terminal, b"i=0; while [ \"$(stty size)\" != '37 103' ] && [ \"$i\" -lt 50 ]; do i=$((i+1)); sleep .1; done; stty size; printf '__SHELL_OK__\\n'; exit 17\n")
        read_until(b"37 103\r\n")
        read_until(b"\r\n__SHELL_OK__\r\n")
        def exited():
            state = os.waitpid(child, os.WNOHANG)
            return state if state[0] else None
        state = wait_for("interactive SSH exit", exited)
        reaped = True
        assert os.waitstatus_to_exitcode(state[1]) == 17, (state, bytes(output))
    finally:
        os.close(terminal)
        if not reaped:
            os.killpg(child, signal.SIGKILL)
            os.waitpid(child, 0)


def source_run(args, success=True, *, stdin=None, tcp=False, trace=None, pool_idle=None):
    # Trace transfer children only. The command/terminal cancellation cases
    # above continue to exercise native OpenSSH without a tracing parent.
    environment = native_path if trace is None else "PATH=/usr/local/bin:/usr/bin:/bin"
    if tcp:
        environment += " SYQ_TEST_REQUIRE_TCP=1"
    if trace is not None:
        environment += " SYQ_REAL_SSH_TRACE_FILE=" + shlex.quote(trace)
    if pool_idle is not None:
        environment += " SYQ_TEST_POOL_IDLE_SECS=" + str(pool_idle)
    return run("ssh", "source", "exec env " + environment + " " + shlex.join(["syq", *args]),
               success=success, stdin=stdin)


def assert_copy_transports(trace, independent, *, expect_control=False):
    text = run("ssh", "source", "if test -f " + shlex.quote(trace)
               + "; then cat " + shlex.quote(trace) + "; fi")
    events = [dict(field.split("=", 1) for field in line.split("\t"))
              for line in text.splitlines()]
    starts = [event for event in events if event["phase"] == "start"
              and event["host"] == "destination"]
    workers = [event for event in starts if event["control_master"] == "no"
               and event["control_path"] == "none"]
    if not independent:
        assert not workers, ("TCP data opened an independent SSH login", events)
        return
    ended = {event["pid"] for event in events if event["phase"] == "end"
             and event["status"] == "0"}
    pids = {event["pid"] for event in workers}
    assert len(pids) >= 2 and pids <= ended, ("missing successful independent SSH workers", events)
    if expect_control:
        controls = [event for event in starts if event["control_socket"] == "present"]
        assert controls and events.index(controls[0]) < events.index(workers[0]), events
    active, peak = set(), 0
    for event in events:
        if event["pid"] in pids:
            if event["phase"] == "start":
                active.add(event["pid"])
                peak = max(peak, len(active))
            else:
                active.remove(event["pid"])
    assert peak >= 2 and not active, ("independent SSH workers did not overlap and exit", events)
    assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []


def persistent_connect(allow=True, ask=False):
    args = ["persist", "connect", "destination", "--auth-from", "@laptop"]
    process = subprocess.Popen(["ssh", "source", "exec env " + native_path + " " + shlex.join(["syq", *args])],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        if ask:
            pending(allow, reusable=True)
        out, err = process.communicate(timeout=30)
        assert (process.returncode == 0) == allow, (process.returncode, out, err)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)


def persistent_cases(expected):
    print("case: account connection setup can be cancelled before approval", flush=True)
    reset_session()
    # Turning persistence off while approval is pending closes that request too.
    args = ["syq", "persist", "connect", "destination", "--auth-from", "@laptop"]
    process = subprocess.Popen(["ssh", "source", "exec env " + native_path + " " + shlex.join(args)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        items = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
        assert len(items) == 1 and items[0]["reusable"], items
        source_run(["persist", "off"])
        out, err = process.communicate(timeout=10)
        assert process.returncode != 0, (out, err)
        wait_for("cancelled persistent approval", lambda: not json.loads(run("syq", "persist", "receive", "pending", "--json")))
    finally:
        if process.poll() is None:
            process.kill(); process.wait(timeout=5)
    persistent_connect(False, ask=True)
    persistent_connect(ask=True)
    rows = json.loads(source_run(["persist", "status", "--json"]))["authorized_ssh"]
    assert len(rows) == 1 and rows[0]["connected"], rows
    control = rows[0]["control"]
    # OpenSSH tools can also use the explicitly approved connection. A missing
    # master must not trigger a fresh login through local keys or other config.
    direct = run("ssh", "source", shlex.join(["env", native_path, "ssh", "-F", "/dev/null", "-S", control,
                 "-o", "ProxyCommand=false", "-o", "BatchMode=yes", "destination", "hostname"]))
    assert direct.encode() == expected, direct
    for _ in range(3):
        assert source_run(["ssh", "--auth-from", "@laptop", "destination", "--", "hostname"]).encode() == expected
    # Merely opening account access must not change native auto selection.
    source_run(["ssh", "destination", "--", "hostname"], success=False)
    assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
    # A preference selects the same existing authority without changing the
    # approval command or consulting preferences on the laptop.
    source_run(["persist", "auth-from", "@laptop", "--for", "destination"])
    assert source_run(["ssh", "destination", "--", "hostname"]).encode() == expected
    source_run(["ssh", "--auth-from", "auto", "destination", "--", "hostname"], success=False)
    assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
    transport = ["--no-tcp"]
    rsync_transport = ["--syq-no-tcp"]
    print("case: reusable account approval supports independent SSH uploads and downloads",
          "including MaxSessions=1", flush=True)
    copy_root = run("ssh", "destination", "mktemp -d /tmp/syq-account-copy.XXXXXX").strip()
    try:
        run("ssh", "source", "dd if=/dev/urandom of=" + shlex.quote(root + "/data") + " bs=1M count=8 status=none")
        # A modest bandwidth cap keeps both workers active long enough for
        # the trace to prove overlapping native connections, not just retries.
        workers = ["--performance-tuning", "workers=2", "--resource-limits", "bandwidth=2M"]
        upload_trace, download_trace = root + "/upload.trace", root + "/download.trace"
        source_run(["cp", root + "/data", "--to", "destination", "--as", copy_root + "/data",
                    *transport, *workers], trace=upload_trace)
        assert_copy_transports(upload_trace, True, expect_control=True)
        source_run(["cp", "--from", "destination", copy_root + "/data", "--as", root + "/roundtrip",
                    *transport, *workers], trace=download_trace)
        assert_copy_transports(download_trace, True)
        run("ssh", "source", "cmp " + shlex.quote(root + "/data") + " " + shlex.quote(root + "/roundtrip"))
        print("case: encrypted TCP workers need no additional SSH authentication", flush=True)
        tcp_trace = root + "/tcp.trace"
        source_run(["cp", root + "/data", "--to", "destination", "--as", copy_root + "/tcp-data",
                    "--performance-tuning", "workers=2"], tcp=True, trace=tcp_trace)
        assert_copy_transports(tcp_trace, False)
        run("ssh", "destination", "cmp " + shlex.quote(copy_root + "/data") + " " + shlex.quote(copy_root + "/tcp-data"))
        assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
        mapping = source_run(["map", "--from", "destination", "-C", copy_root, "data"])
        assert len(mapping.splitlines()) == 1, mapping
        source_run(["rsync", "-a", *rsync_transport, root + "/data", "destination:" + copy_root + "/rsync-data"])
        source_run(["rsync", "-a", *rsync_transport, "--syq-auth-from", "@laptop", "destination:" + copy_root + "/rsync-data", root + "/rsync-roundtrip"])
        run("ssh", "source", "cmp " + shlex.quote(root + "/data") + " " + shlex.quote(root + "/rsync-roundtrip"))
        stream_data = "stream through approved SSH\n"
        source_run(["cp", "--src-fd", "0", "--to", "destination", "--as", copy_root + "/stream",
                    *transport, "--auth-from", "@laptop"], stdin=stream_data)
        assert source_run(["cp", "--from", "destination", copy_root + "/stream", "--as-fd", "1",
                           *transport]) == stream_data
        source_run(["clean-partials", "--on", "destination", copy_root, "--auth-from", "@laptop"])
        run("ssh", "destination", "test -f " + shlex.quote(copy_root + "/data"))
        source_run(["rm", "--on", "destination", copy_root + "/rsync-data", "--auth-from", "@laptop"])
        run("ssh", "destination", "test ! -e " + shlex.quote(copy_root + "/rsync-data"))
    finally:
        run("ssh", "destination", "rm -rf -- " + shlex.quote(copy_root))
    assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
    # Native auth must not retry through the saved laptop preference on failure.
    source_run(["ssh", "--auth-from", "ssh", "destination", "--", "hostname"], success=False)
    assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
    source_run(["persist", "auth-from", "--for", "destination", "--reset"])
    source_run(["persist", "off"])
    run("ssh", "source", "test ! -S " + shlex.quote(control))
    assert json.loads(source_run(["persist", "status", "--json"]))["authorized_ssh"] == []
    # The laptop's session approval still permits a fresh login after closing
    # the local master, without another prompt or enabling ordinary persistence.
    assert source_run(["ssh", "destination", "--auth-from", "@laptop", "--", "hostname"]).encode() == expected
    source_run(["persist", "off"])
    assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
    run("ssh", "source", shlex.join(["env", native_path, "ssh", "-F", "/dev/null", "-S", control,
                 "-o", "ProxyCommand=false", "-o", "BatchMode=yes", "destination", "hostname"]), success=False)
    # Losing the laptop profile also closes the reusable master, including an
    # active command. Reconnection alone must not restore that account login.
    persistent_connect()
    rows = json.loads(source_run(["persist", "status", "--json"]))["authorized_ssh"]
    control = rows[0]["control"]
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(["ssh", "source", source_command(["printf READY; exec sleep 60"])], stdout=output, stderr=subprocess.PIPE)
        try:
            wait_for("reused SSH command output", lambda: b"READY" in os.pread(output.fileno(), 4096, 0))
            run("syq", "persist", "receive", "off", "--name", "laptop")
            _, err = process.communicate(timeout=10)
            assert process.returncode != 0, err
            run("ssh", "source", "test ! -S " + shlex.quote(control))
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
    run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off")
    ready()
    assert json.loads(source_run(["persist", "status", "--json"]))["authorized_ssh"] == []
    assert execute(["hostname"], ask=True)[0] == expected
    source_run(["persist", "off"])



def scoped_account_cases(expected):
    print("case: scoped account reuse and native config stay isolated from default connections", flush=True)
    # The current laptop session has approved this account already. New local
    # domains borrow that provider but create and own their own SSH connection.
    assert source_run(["ssh", "destination", "--auth-from", "@laptop", "--", "hostname"]).encode() == expected
    default = json.loads(source_run(["persist", "status", "--json"]))["authorized_ssh"]
    assert len(default) == 1 and default[0]["connected"], default
    scope = source_run(["persist", "on", "--ephemeral"]).strip()
    config = root + "/scoped-ssh-config"
    closed = False
    try:
        # Scoped saved authorization must win over the default domain's setting.
        source_run(["persist", "auth-from", "ssh", "--for", "destination"])
        source_run(["persist", "auth-from", "@laptop", "--for", "destination", "--pscope", scope])
        assert json.loads(source_run(["persist", "status", "--json", "--pscope", scope]))["authorized_ssh"] == []
        assert source_run(["ssh", "--pscope", scope, "destination", "--", "hostname"]).encode() == expected
        scoped = json.loads(source_run(["persist", "status", "--json", "--pscope", scope]))["authorized_ssh"]
        assert len(scoped) == 1 and scoped[0]["connected"], scoped
        assert Path(scoped[0]["control"]).parent.parent == Path(scope), scoped
        assert scoped[0]["control"] != default[0]["control"], (scoped, default)
        exported = source_run(["persist", "ssh-config", "destination", "--pscope", scope])
        run("ssh", "source", "cat > " + shlex.quote(config), stdin=exported)
        native = shlex.join(["env", native_path, "ssh", "-F", config, "destination", "hostname"])
        assert run("ssh", "source", native).encode() == expected
        assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
        source_run(["persist", "off", "--pscope", scope])
        closed = True
        # off waits for the keeper's native daemon and all scoped files, so the
        # exported snapshot fails without fresh authentication or another prompt.
        run("ssh", "source", "test ! -e " + shlex.quote(scope))
        run("ssh", "source", native, success=False)
        remaining = json.loads(source_run(["persist", "status", "--json"]))["authorized_ssh"]
        assert {row["control"] for row in remaining} == {default[0]["control"]}, remaining
        assert source_run(["ssh", "--auth-from", "@laptop", "destination", "--", "hostname"]).encode() == expected
        assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
    finally:
        source_run(["persist", "auth-from", "--for", "destination", "--reset"])
        if not closed:
            source_run(["persist", "off", "--pscope", scope])



def requester_config_cases(expected):
    print("case: requester config selects accounts and routes before account-cache lookup", flush=True)
    alias, source_trust = "syq-requester-fixture", "syq-source-trust-fixture"
    scope = source_run(["persist", "on", "--ephemeral"]).strip()
    config = Path.home() / ".ssh/config"
    original = config.read_bytes()
    source_original = run("ssh", "source", "python3 -c " + shlex.quote(
        "import json,pathlib; p=pathlib.Path.home()/'.ssh/config'; "
        "print(json.dumps(p.read_text() if p.exists() else None))"))
    source_original = json.loads(source_original)
    addresses = json.loads(run("python3", "-c", "import json,socket; print(json.dumps("
        "{host:socket.gethostbyname(host) for host in ['source','destination']}))"))
    public_key = run("ssh-keygen", "-y", "-f", str(Path.home() / ".ssh/id_ed25519"))
    public_path, wrong_path = root + "/destination.pub", root + "/wrong.pub"
    local_marker = root + "/local-lookups"
    source_name = run("ssh", "source", "hostname").encode()
    with tempfile.TemporaryDirectory(prefix="syq-requester-config-") as temporary:
        marker = Path(temporary) / "provider-lookups"
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", temporary + "/wrong")
        for path, key in [(public_path, public_key), (wrong_path, Path(temporary + "/wrong.pub").read_text())]:
            run("ssh", "source", "cat > " + shlex.quote(path), stdin=key)
        # The provider's route/user differ deliberately. Only its trust policy
        # applies: this alias trusts destination's key, not source's key.
        trust_files = "  UserKnownHostsFile /home/syq/.ssh/known_hosts\n  GlobalKnownHostsFile /dev/null\n"
        prefix = ("Host " + alias + "\n  HostName source\n  User longhome\n  HostKeyAlias destination\n"
                  + trust_files + "Host " + source_trust + "\n  HostName source\n  HostKeyAlias source\n"
                  + trust_files + "Match originalhost " + alias + "," + source_trust
                  + " exec \"printf x >> " + str(marker) + "\"\nMatch all\n")
        config.write_bytes(prefix.encode() + original)

        def configure(user, host, identity=public_path, trust=None):
            local = ("Host " + alias + "\n  HostName " + addresses[host] + "\n  User " + user
                     + "\n  Port 22\n  IdentityFile " + identity + "\n  IdentitiesOnly yes\n"
                     + ("  HostKeyAlias " + trust + "\n" if trust else "")
                     + "Match originalhost " + alias + " exec \"printf x >> " + local_marker + "\"\nMatch all\n")
            run("ssh", "source", "python3 -c " + shlex.quote(
                "import pathlib,sys; p=pathlib.Path.home()/'.ssh/config'; "
                "p.write_text(sys.stdin.read()); p.chmod(0o600)"), stdin=local + (source_original or ""))

        def command():
            return "exec env " + native_path + " " + shlex.join([
                "syq", "ssh", "--pscope", scope, "--auth-from", "@laptop", alias,
                "--", "printf '%s ' \"$(id -un)\"; hostname"])

        def invoke(*, approve=None, endpoint=None, success=True):
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                process = subprocess.Popen(["ssh", "source", command()], stdout=stdout,
                                           stderr=stderr, start_new_session=True)
                try:
                    if approve:
                        pending(target=approve, endpoint=endpoint)
                    status = process.wait(timeout=30)
                    stdout.seek(0); stderr.seek(0)
                    out, err = stdout.read(), stderr.read()
                    assert (status == 0) == success, (out, err, status)
                    if not success:
                        assert status == 255, (out, err, status)
                    return out
                except BaseException:
                    stdout.seek(0); stderr.seek(0)
                    print("Requester config command status:", process.poll(),
                          "stdout:", stdout.read(), "stderr:", stderr.read(), flush=True)
                    raise
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait(timeout=3)

        def completion():
            words = ["syq", "cp", "--pscope", scope, "--auth-from", "@laptop",
                     "--from", alias, destination_root + "/comple"]
            # A prepared helper occupies the sole shared session with
            # MaxSessions=1. Keep account-selection checks independent of that
            # accepted limit; the default profile still exercises prewarming.
            pool_idle = 0 if os.environ.get("SYQ_REAL_SSH_PROFILE") == "max-sessions-1" else None
            return source_run(["completion", "__complete", "fish", str(len(words)-1), "--", *words],
                              pool_idle=pool_idle)

        def no_pending():
            assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []

        try:
            configure("syq", "destination")
            assert invoke(approve="syq@destination", endpoint={"user": "syq", "host": addresses["destination"], "port": 22}) == b"syq " + expected
            calls = marker.read_bytes()
            assert calls, "cold authorization did not consult provider trust"
            for _ in range(2):
                assert invoke() == b"syq " + expected
            assert marker.read_bytes() == calls, "warm login inspected provider config again"
            run("ssh", "destination", "touch " + shlex.quote(destination_root + "/completion.txt"))
            local_calls = run("ssh", "source", "cat " + shlex.quote(local_marker))
            assert destination_root + "/completion.txt\0" in completion()
            assert len(run("ssh", "source", "cat " + shlex.quote(local_marker))) > len(local_calls), "completion did not validate local SSH config"
            assert marker.read_bytes() == calls, "completion contacted provider trust lookup"
            no_pending()

            print("case: IdentitiesOnly honors the requester's selected public identity", flush=True)
            configure("syq", "destination", identity=wrong_path)
            invoke(success=False)
            no_pending()
            configure("syq", "destination")
            assert invoke() == b"syq " + expected

            print("case: local account and address edits cannot reuse the old destination", flush=True)
            configure("longhome", "destination")
            before = marker.read_bytes()
            local_calls = run("ssh", "source", "cat " + shlex.quote(local_marker))
            assert completion() == "", "completion reused a stale local SSH configuration"
            assert marker.read_bytes() == before, "cold completion contacted the provider"
            assert len(run("ssh", "source", "cat " + shlex.quote(local_marker))) > len(local_calls), "completion missed the local config change"
            no_pending()
            assert invoke(approve="longhome@destination", endpoint={"user": "longhome", "host": addresses["destination"], "port": 22}) == b"longhome " + expected
            configure("longhome", "source", trust=source_trust)
            assert invoke(approve="longhome@source", endpoint={"user": "longhome", "host": addresses["source"], "port": 22}) == b"longhome " + source_name
            assert invoke() == b"longhome " + source_name
            rows = json.loads(source_run(["persist", "status", "--pscope", scope, "--json"]))["authorized_ssh"]
            selected = {(row["endpoint"]["user"], row["endpoint"]["host"]) for row in rows if row["connected"]}
            assert selected == {("syq", addresses["destination"]), ("longhome", addresses["destination"]),
                                ("longhome", addresses["source"])}, rows
            # The same local selection also applies when its master is absent.
            row = next(row for row in rows if row["endpoint"]["host"] == addresses["source"])
            run("ssh", "source", shlex.join(["env", native_path, "ssh", "-F", "/dev/null", "-S", row["control"],
                "-O", "exit", "-l", "longhome", addresses["source"]]))
            wait_for("closed requester-selected master", lambda: not any(
                item["control"] == row["control"] and item["connected"] for item in
                json.loads(source_run(["persist", "status", "--pscope", scope, "--json"]))["authorized_ssh"]))
            assert invoke() == b"longhome " + source_name
            no_pending()
        finally:
            config.write_bytes(original)
            run("ssh", "source", "python3 -c " + shlex.quote(
                "import json,pathlib,sys; p=pathlib.Path.home()/'.ssh/config'; value=json.load(sys.stdin); "
                "p.write_text(value) if value is not None else p.unlink()"), stdin=json.dumps(source_original))
            source_run(["persist", "off", "--pscope", scope])


def persistent_crash():
    print("case: killing the keeper hangs up its active native master", flush=True)
    persistent_connect()
    rows = json.loads(source_run(["persist", "status", "--json"]))["authorized_ssh"]
    control = rows[0]["control"]
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(["ssh", "source", source_command(["printf READY; exec sleep 60"])], stdout=output, stderr=subprocess.PIPE)
        try:
            wait_for("command before keeper crash", lambda: b"READY" in os.pread(output.fileno(), 4096, 0))
            run("ssh", "source", "python3 -", stdin="control = " + repr(control) + "\n" + r'''
import os, pathlib, signal, time
matches = []
for entry in pathlib.Path('/proc').iterdir():
    if not entry.name.isdigit(): continue
    try:
        args = (entry/'cmdline').read_bytes().split(b'\0')
        if not args or pathlib.Path(os.fsdecode(args[0])).name != 'ssh': continue
        if os.fsencode(control) not in args: continue
        stat = (entry/'stat').read_text().rsplit(') ', 1)[1].split()
        keeper = int(stat[1])
        owner = pathlib.Path('/proc')/str(keeper)/'cmdline'
        if b'--approved-ssh-master' in owner.read_bytes().split(b'\0'):
            matches.append((int(entry.name), keeper))
    except FileNotFoundError: pass
assert len(matches) == 1, matches
master, keeper = matches[0]
os.kill(keeper, signal.SIGKILL)
deadline, progress = time.monotonic()+5, time.monotonic()+1
while pathlib.Path(control).exists():
    assert time.monotonic() < deadline, ('master survived keeper', master, keeper)
    if time.monotonic() >= progress:
        print('Waiting for crashed keeper master', master, flush=True); progress += 1
    time.sleep(.025)
''')
            _, err = process.communicate(timeout=10)
            assert process.returncode == 255, (process.returncode, err)
            assert json.loads(source_run(["persist", "status", "--json"]))["authorized_ssh"] == []
            assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
    source_run(["persist", "off"])


def reset_session():
    source_run(["persist", "off"])
    run("syq", "persist", "receive", "off", "--name", "laptop")
    run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off")
    ready()


def cold_copy_and_remembered_cases(expected):
    print("case: cold copy requests account access without persist connect", flush=True)
    reset_session()
    source_run(["persist", "off"])
    source_run(["persist", "auth-from", "@laptop", "--for", "destination"])
    remote_root = run("ssh", "destination", "mktemp -d /tmp/syq-cold-account.XXXXXX").strip()
    try:
        data = "cold account copy\n" * 65536
        run("ssh", "source", "cat > " + shlex.quote(root + "/cold"), stdin=data)
        transport = ["--no-tcp", "--performance-tuning", "workers=2"]
        args = ["syq", "cp", root + "/cold", "--to", "destination", "--as", remote_root + "/data",
                "--inplace", "--syq-path", "/usr/local/bin/syq", *transport]
        process = subprocess.Popen(["ssh", "source", "exec env " + native_path + " " + shlex.join(args)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            pending()
            out, err = process.communicate(timeout=30)
            assert process.returncode == 0, (out, err)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
        source_run(["cp", "--from", "destination", remote_root + "/data", "--as", root + "/cold-back",
                    "--no-bootstrap", *transport])
        assert run("ssh", "source", "cat " + shlex.quote(root + "/cold-back")) == data
        assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
    finally:
        source_run(["persist", "auth-from", "--for", "destination", "--reset"])
        run("ssh", "destination", "rm -rf -- " + shlex.quote(remote_root))

    print("case: remembered permission survives reconnect and removal asks again", flush=True)
    reset_session()
    assert execute(["hostname"], ask=True, remember=True)[0] == expected
    rows = json.loads(run("syq", "persist", "receive", "permissions", "list", "--json"))
    assert len(rows) == 1, rows
    permission_id = rows[0]["id"]
    assert rows[0]["permission"]["source"]["endpoint"]["user"] == "syq", rows
    assert rows[0]["permission"]["destination"]["endpoint"]["user"] == "syq", rows
    assert rows[0]["permission"]["destination"]["trusted_host"] == "destination", rows
    assert rows[0]["permission"]["source"]["host_keys"] and rows[0]["permission"]["destination"]["host_keys"], rows
    try:
        reset_session()
        assert execute(["hostname"])[0] == expected
        assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
        # A destination login change never inherits the remembered account grant.
        execute(["hostname"], target="root@destination:22", approval_target="root@destination", ask=True, allow=False, status=255)
        run("syq", "persist", "receive", "permissions", "remove", permission_id)
        source_run(["persist", "off"])
        execute(["hostname"], ask=True, allow=False, status=255)
        assert json.loads(run("syq", "persist", "receive", "permissions", "list", "--json")) == []
    finally:
        for row in json.loads(run("syq", "persist", "receive", "permissions", "list", "--json")):
            run("syq", "persist", "receive", "permissions", "remove", row["id"])


try:
    print("case: first direct SSH asks for account approval", flush=True)
    Path("/tmp/syq-real-ssh-receive").mkdir(exist_ok=True)
    run("syq", "persist", "receive", "on", "--name", "laptop", "--auto-approve-root", "/tmp/syq-real-ssh-receive", "--notify", "off")
    run("syq", "persist", "connect", "source")
    ready()
    execute(["hostname"], allow=False, status=255, ask=True)
    expected = run("ssh", "destination", "hostname").encode()
    assert execute(["hostname"], ask=True)[0] == expected
    assert execute(["hostname"], binary="/usr/local/bin/syq-other-build")[0] == expected

    print("case: direct SSH preserves binary stdin, EOF, output and exit status", flush=True)
    program = "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); sys.stderr.buffer.write(b'error\\x00\\xff'); sys.exit(17)"
    command = [shlex.join(["python3", "-c", program])]
    payload = bytes(range(256)) * 1024
    out, err = execute(command, data=payload, status=17)
    assert out == payload, len(out)
    assert err.endswith(b"error\x00\xff"), err

    print("case: obsolete SSH requests cannot disclose provider resolution or request approval", flush=True)
    run("ssh", "source", "python3 -", stdin='''
import json, pathlib, socket, struct
r = json.loads((pathlib.Path.home()/'.syq-destinations-v3/laptop.json').read_text())
command = ['ssh','--auth-from','@laptop','destination','--','hostname']
def request(message):
    envelope = {'version':2,'identity':r['identity'],'secret':r['secret'],'message':message}
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(10); s.connect(r['socket'])
        b=json.dumps(envelope).encode(); s.sendall(struct.pack('>I',len(b))+b)
        def exact(size):
            data=b''
            while len(data)<size:
                part=s.recv(size-len(data)); assert part; data+=part
            return data
        reply=json.loads(exact(struct.unpack('>I',exact(4))[0]))
        kind=next(iter(message))
        assert set(reply) == {'Error'}, reply
        assert 'unknown variant `' + kind + '`' in reply['Error'], reply
        assert s.recv(1) == b'', 'obsolete request returned more than its rejection'
request({'Ssh':{'target':{'user':None,'host':'source','port':None},
                'command':[list(a.encode()) for a in command],'cwd':'/tmp'}})
request({'ResolveSsh':{'user':None,'host':'destination','port':None}})
''')
    assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []

    print("case: native interactive SSH shell carries terminal size and exit status", flush=True)
    interactive_shell()

    for mode in ("interrupt", "stop"):
        print("case: direct SSH ends after", mode, flush=True)
        controls = {row["control"] for row in json.loads(source_run(["persist", "status", "--json"]))["authorized_ssh"]}
        pidfile = destination_root + "/sleep-pid"
        try:
            execute(["echo $$ > " + shlex.quote(pidfile) + "; printf READY; exec sleep 60"],
                    status=130 if mode == "interrupt" else 255, cancel=mode)
        finally:
            # Native mux interruption ends the local command but can leave the
            # remote sleep occupying MaxSessions=1. Clean up only after the
            # interrupt assertion, so cleanup cannot hide a local exit hang.
            run("ssh", "destination", "if test -f " + shlex.quote(pidfile)
                + "; then kill -TERM $(cat " + shlex.quote(pidfile) + ") 2>/dev/null || true; fi")
        if mode == "interrupt":
            rows = json.loads(source_run(["persist", "status", "--json"]))["authorized_ssh"]
            assert {row["control"] for row in rows} == controls and all(row["connected"] for row in rows), rows
            def reused():
                result = subprocess.run(["ssh", "source", source_command(["hostname"])],
                                        input=b"", capture_output=True, timeout=5)
                return result.returncode == 0 and result.stdout == expected
            wait_for("same master available after interrupted command", reused)
            assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
        else:
            run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off")
            ready()
    assert execute(["hostname"], ask=True)[0] == expected
    persistent_cases(expected)
    scoped_account_cases(expected)
    requester_config_cases(expected)
    persistent_crash()
    cold_copy_and_remembered_cases(expected)
    print("Direct laptop-authorized SSH passed", flush=True)
finally:
    source_run(["persist", "off"])
    run("ssh", "source", "rm -rf -- " + shlex.quote(root))
    run("ssh", "destination", "rm -rf -- " + shlex.quote(destination_root))
