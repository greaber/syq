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


def pending(allow=True, reusable=False):
    items = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
    assert len(items) == 1, items
    request = items[0]
    assert request["kind"] == "ssh", request
    assert "syq@destination:22" == request["destination"], request
    assert "full authority" in request["permission"], request
    assert request["reusable"] == reusable, request
    if reusable:
        assert "commands and copies" in request["permission"], request
    run("syq", "persist", "receive", "approve" if allow else "deny", request["id"])
    run("syq", "persist", "receive", "approve", request["id"], success=False)


root = run("ssh", "source", "mktemp -d /tmp/syq-return-ssh.XXXXXX").strip()
# Test the native OpenSSH child itself. The lab's tracing shell wrapper forks
# another client and does not implement the native client's signal lifecycle.
native_path = "PATH=/usr/bin:/bin:/usr/local/bin"


def source_command(command=(), *, tty=False, binary="/usr/local/bin/syq"):
    args = [binary, "ssh", "--auth-from", "@laptop"]
    if tty:
        args.append("-t")
    args.append("destination")
    if command:
        args.extend(["--", *command])
    return ('test -z "${SSH_AUTH_SOCK:-}" && test ! -e ~/.ssh/id_ed25519 && '
            'echo $$ > ' + shlex.quote(root + "/client") + ' && exec env ' + native_path + ' ' + shlex.join(args))


def execute(command, *, allow=True, status=0, data=b"", cancel=None, binary="/usr/local/bin/syq"):
    with tempfile.TemporaryFile() as input_file, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        input_file.write(data)
        input_file.seek(0)
        process = subprocess.Popen(["ssh", "source", source_command(command, binary=binary)],
                                   stdin=input_file, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            pending(allow)
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
        pending()
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


def source_run(args, success=True):
    return run("ssh", "source", "exec env " + native_path + " " + shlex.join(["syq", *args]), success=success)


def persistent_connect(allow=True):
    args = ["persist", "connect", "destination", "--auth-from", "@laptop"]
    process = subprocess.Popen(["ssh", "source", "exec env " + native_path + " " + shlex.join(["syq", *args])],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        pending(allow, reusable=True)
        out, err = process.communicate(timeout=30)
        assert (process.returncode == 0) == allow, (process.returncode, out, err)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)


def persistent_cases(expected):
    print("case: reusable account access has separate explicit approval", flush=True)
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
    persistent_connect(False)
    persistent_connect()
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
    # A preference selects the same existing authority without changing the
    # approval command or consulting preferences on the laptop.
    source_run(["persist", "auth-from", "@laptop", "--for", "destination"])
    assert source_run(["ssh", "destination", "--", "hostname"]).encode() == expected
    assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
    # Native auth must not retry through the saved laptop preference on failure.
    source_run(["ssh", "--auth-from", "ssh", "destination", "--", "hostname"], success=False)
    assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
    source_run(["persist", "auth-from", "--for", "destination", "--reset"])
    source_run(["persist", "off"])
    run("ssh", "source", "test ! -S " + shlex.quote(control))
    assert json.loads(source_run(["persist", "status", "--json"]))["authorized_ssh"] == []
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
    assert execute(["hostname"])[0] == expected
    source_run(["persist", "off"])


try:
    print("case: direct SSH always asks for account approval", flush=True)
    Path("/tmp/syq-real-ssh-receive").mkdir(exist_ok=True)
    run("syq", "persist", "receive", "on", "--name", "laptop", "--auto-approve-root", "/tmp/syq-real-ssh-receive", "--notify", "off")
    run("syq", "persist", "connect", "source")
    ready()
    execute(["hostname"], allow=False, status=1)
    expected = run("ssh", "destination", "hostname").encode()
    assert execute(["hostname"])[0] == expected
    assert execute(["hostname"], binary="/usr/local/bin/syq-other-build")[0] == expected

    print("case: direct SSH preserves binary stdin, EOF, output and exit status", flush=True)
    program = "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); sys.stderr.buffer.write(b'error\\x00\\xff'); sys.exit(17)"
    command = [shlex.join(["python3", "-c", program])]
    payload = bytes(range(256)) * 1024
    out, err = execute(command, data=payload, status=17)
    assert out == payload, len(out)
    assert err.endswith(b"error\x00\xff"), err

    print("case: a forged SSH target cannot differ from the displayed command", flush=True)
    run("ssh", "source", "python3 -", stdin='''
import json, pathlib, socket, struct
r = json.loads((pathlib.Path.home()/'.syq-destinations-v3/laptop.json').read_text())
command = ['ssh','--auth-from','@laptop','destination','--','hostname']
request = {'version':2,'identity':r['identity'],'secret':r['secret'],
           'message':{'Ssh':{'target':{'user':None,'host':'source','port':None},
                             'command':[list(a.encode()) for a in command],'cwd':'/tmp'}}}
s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(r['socket'])
b = json.dumps(request).encode(); s.sendall(struct.pack('>I',len(b))+b)
def exact(size):
    data=b''
    while len(data)<size:
        part=s.recv(size-len(data)); assert part; data+=part
    return data
reply=json.loads(exact(struct.unpack('>I',exact(4))[0]))
assert 'does not match' in reply['Error'], reply
''')
    assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []

    print("case: native interactive SSH shell carries terminal size and exit status", flush=True)
    interactive_shell()

    for mode in ("interrupt", "stop"):
        print("case: direct SSH ends after", mode, flush=True)
        execute(["printf READY; exec sleep 60"], status=130 if mode == "interrupt" else 1, cancel=mode)
        if mode == "stop":
            run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off")
            ready()
    assert execute(["hostname"])[0] == expected
    persistent_cases(expected)
    print("Direct laptop-authorized SSH passed", flush=True)
finally:
    source_run(["persist", "off"])
    run("ssh", "source", "rm -rf -- " + shlex.quote(root))
