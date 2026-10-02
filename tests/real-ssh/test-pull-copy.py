"""Server-started, laptop-approved source reads in disposable directories."""
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time


def run(*args, stdin=None, success=True):
    result = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=40)
    assert (result.returncode == 0) == success, (args, result)
    return result.stdout


def remote(host, command, **kwargs):
    return run("ssh", host, command, **kwargs)


def wait_for(description, predicate, timeout=20):
    deadline, report = time.monotonic() + timeout, time.monotonic() + 3
    state = None
    while time.monotonic() < deadline:
        state = predicate()
        if state:
            return state
        if time.monotonic() >= report:
            print("Waiting for", description, "last state:", state, flush=True)
            report += 3
        time.sleep(.1)
    raise AssertionError(("Timed out", description, "last state", state))


source = remote("destination", "mktemp -d /tmp/syq-pull-source.XXXXXX").strip()
destination = remote("source", "mktemp -d /tmp/syq-pull-destination.XXXXXX").strip()


def argv(name, extra=(), binary="syq"):
    return [binary, "cp", "--from", "destination", source + "/data",
            "--as", destination + "/" + name, "--auth-from", "@laptop",
            "--performance-tuning", "workers=2", *extra]


def command(arguments, tcp=True):
    return ('test -z "${SSH_AUTH_SOCK:-}" && test ! -e ~/.ssh/id_ed25519 && exec env '
            + ("SYQ_TEST_REQUIRE_TCP=1 " if tcp else "") + shlex.join(arguments))


def approve(allow):
    requests = json.loads(run("syq", "persist", "receive", "pending", "--json",
                              "--wait", "--timeout", "15"))
    assert len(requests) == 1, requests
    request = requests[0]
    assert request["kind"] == "source", request
    assert request["source"] == "destination", request
    assert source + "/data" in request["scopes"][0], request
    assert "destination" not in request, request
    run("syq", "persist", "receive", "approve" if allow else "deny", request["id"])
    run("syq", "persist", "receive", "approve", request["id"], success=False)


def pull(name, *, allow=True, success=True, extra=(), cancel=False, binary="syq", tcp=True):
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(["ssh", "source", command(argv(name, extra, binary), tcp)],
                                   stdout=output, stderr=output, start_new_session=True)
        try:
            approve(allow)
            if cancel:
                code = ("import hashlib,json,pathlib; p=pathlib.Path(" + repr(destination) + "); "
                        "print(json.dumps(any(hashlib.sha256(f.open('rb').read(4*1024*1024)).hexdigest() == "
                        + repr(prefix) + " for f in p.glob('.cancelled.syq-tmp.*'))))")
                wait_for("partial source download", lambda: json.loads(
                    remote("source", "python3 -c " + shlex.quote(code))))
                run("syq", "persist", "receive", "off", "--name", "laptop")
            deadline = time.monotonic() + 60
            offset = 0
            while True:
                try:
                    status = process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    data = os.pread(output.fileno(), 1024 * 1024, offset)
                    offset += len(data)
                    print(data.decode(errors="replace"), end="", flush=True)
                    print("Waiting for source download:", name, flush=True)
                    assert time.monotonic() < deadline, "source download exceeded deadline"
            output.seek(0)
            text = output.read().decode(errors="replace")
            print(text, end="", flush=True)
            assert (status == 0) == success, (status, text)
        except BaseException:
            print(os.pread(output.fileno(), 1024 * 1024, 0).decode(errors="replace"), flush=True)
            raise
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)


def digest(host, path):
    return remote(host, "sha256sum " + shlex.quote(path)).split()[0]


def source_keys():
    return remote("destination", 'if test -f ~/.ssh/authorized_keys; then '
                  'sha256sum ~/.ssh/authorized_keys; else printf absent; fi')


try:
    Path("/tmp/syq-real-ssh-receive").mkdir(exist_ok=True)
    run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off",
        "--auto-approve-root", "/tmp/syq-real-ssh-receive")
    run("syq", "persist", "connect", "source")
    run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
    remote("destination", "dd if=/dev/urandom of=" + shlex.quote(source + "/data")
           + " bs=1M count=8 status=none && chmod 444 " + shlex.quote(source + "/data"))
    expected, keys = digest("destination", source + "/data"), source_keys()
    prefix = remote("destination", "dd if=" + shlex.quote(source + "/data")
                    + " bs=1M count=4 status=none | sha256sum").split()[0]

    print("case: source access requires separate approval despite automatic receiving", flush=True)
    pull("denied", allow=False, success=False)
    remote("source", "test ! -e " + shlex.quote(destination + "/denied"))

    print("case: encrypted direct source reads need no requesting-server SSH credentials", flush=True)
    pull("approved")
    assert digest("source", destination + "/approved") == expected
    assert source_keys() == keys

    print("case: source authorization hands off to the receiving build", flush=True)
    pull("other-build", binary="syq-other-build")
    assert digest("source", destination + "/other-build") == expected

    print("case: scoped source authorization cannot silently relay blocked TCP data", flush=True)
    blocked = os.environ["SYQ_REAL_SSH_BLOCKED_TCP_PORT"]
    pull("blocked", extra=("--tcp-ports", blocked + "-" + blocked), success=False, tcp=False)
    remote("source", "test ! -e " + shlex.quote(destination + "/blocked"))
    assert source_keys() == keys

    print("case: explicit SSH-only scoped source access fails before approval", flush=True)
    remote("source", command(argv("ssh-only", ("--no-tcp",)), tcp=False), success=False)
    assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
    remote("source", "test ! -e " + shlex.quote(destination + "/ssh-only"))

    print("case: stopping receiving cancels a source download and a new approval resumes", flush=True)
    pull("cancelled", extra=("--resource-limits", "bandwidth=512"), cancel=True, success=False)
    remote("source", "test ! -e " + shlex.quote(destination + "/cancelled"))
    run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off")
    run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
    results = destination + "/resume.ndjson"
    pull("cancelled", extra=("--results", results))
    records = [json.loads(line) for line in remote("source", "cat " + shlex.quote(results)).splitlines()]
    assert records[-1]["type"] == "result" and records[-1]["bytes_unchanged"] >= 4 * 1024 * 1024, records
    assert digest("source", destination + "/cancelled") == expected
    assert source_keys() == keys
finally:
    remote("destination", "rm -rf -- " + shlex.quote(source))
    remote("source", "rm -rf -- " + shlex.quote(destination))
