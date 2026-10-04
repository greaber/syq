"""Native SSH tools reuse approved accounts without a source key or forwarded agent."""
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess


NATIVE_PATH = "PATH=/usr/bin:/bin:/usr/local/bin"


def run(*args, data=None, success=True):
    result = subprocess.run(args, input=data, capture_output=True, timeout=40)
    assert (result.returncode == 0) == success, (args, result)
    return result.stdout


def source(*args, data=None, success=True):
    return run("ssh", "source", shlex.join(["env", NATIVE_PATH, *args]), data=data, success=success)


def no_pending():
    assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []


def connect(*, ask=True):
    args = ["env", NATIVE_PATH, "syq", "persist", "connect", "destination", "--auth-from", "@laptop"]
    process = subprocess.Popen(["ssh", "source", shlex.join(args)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        if ask:
            requests = json.loads(run("syq", "persist", "receive", "pending", "--json", "--wait", "--timeout", "15"))
            assert len(requests) == 1, requests
            request = requests[0]
            assert request["kind"] == "ssh" and request["reusable"], request
            assert request["destination"] == "syq@destination", request
            account = request["account"]["destination"]
            assert account["trusted_host"] == "destination", request
            assert account["endpoint"] == {"user": "syq", "host": "destination", "port": 22}, request
            assert "commands and copies" in request["permission"], request
            run("syq", "persist", "receive", "approve", request["id"])
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, (stdout, stderr)
        no_pending()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)


def export(config, *options):
    result = source("syq", "persist", "ssh-config", "destination", *options)
    assert result.startswith(b"# Snapshot"), result
    source("python3", "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())",
           config, data=result)


def read(path):
    return source("cat", path)


root = run("ssh", "source", "mktemp -d /tmp/syq-ssh-tools.XXXXXX").decode().strip()
remote = run("ssh", "destination", "mktemp -d /tmp/syq-ssh-tools.XXXXXX").decode().strip()
config = root + "/ssh config"
payload = bytes(range(256)) * 4096
try:
    Path("/tmp/syq-real-ssh-receive").mkdir(exist_ok=True)
    run("syq", "persist", "receive", "on", "--name", "laptop", "--notify", "off")
    run("syq", "persist", "connect", "source")
    run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
    source("syq", "persist", "off")
    run("ssh", "source", 'test -z "${SSH_AUTH_SOCK:-}" && test ! -e ~/.ssh/id_ed25519')

    print("case: config export never creates account approval", flush=True)
    source("syq", "persist", "ssh-config", "destination", success=False)
    no_pending()
    connect()
    source("syq", "persist", "ssh-config", "destination", "--auth-from", "ssh", success=False)
    source("syq", "persist", "ssh-config", "destination", "--auth-from", "@other", success=False)
    export(config)
    # An explicit authorizer and saved selection produce the same snapshot.
    explicit = source("syq", "persist", "ssh-config", "destination", "--auth-from", "@laptop")
    source("syq", "persist", "auth-from", "@laptop", "--for", "destination")
    assert source("syq", "persist", "ssh-config", "destination") == explicit
    source("syq", "persist", "auth-from", "--for", "destination", "--reset")

    print("case: native ssh preserves binary input/output and remote exit", flush=True)
    command = "python3 -c 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())'"
    assert source("ssh", "-F", config, "destination", command, data=payload) == payload
    result = subprocess.run(["ssh", "source", shlex.join(["env", NATIVE_PATH, "ssh", "-F", config,
                             "destination", "exit 17"])], capture_output=True, timeout=40)
    assert result.returncode == 17, result

    print("case: native scp uploads and downloads over the approved connection", flush=True)
    source("python3", "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())",
           root + "/original", data=payload)
    source("scp", "-F", config, root + "/original", "destination:" + remote + "/scp")
    source("scp", "-F", config, "destination:" + remote + "/scp", root + "/scp-roundtrip")
    assert read(root + "/scp-roundtrip") == payload

    print("case: native sftp batch transfers use its subsystem", flush=True)
    batch = "put {0}/original {1}/sftp\nget {1}/sftp {0}/sftp-roundtrip\n".format(root, remote)
    source("sftp", "-F", config, "-b", "-", "destination", data=batch.encode())
    assert read(root + "/sftp-roundtrip") == payload

    print("case: native rsync delegates its SSH command without socket plumbing", flush=True)
    ssh_command = shlex.join(["ssh", "-F", config])
    source("rsync", "-a", "-e", ssh_command, root + "/original", "destination:" + remote + "/rsync")
    source("rsync", "-a", "-e", ssh_command, "destination:" + remote + "/rsync", root + "/rsync-roundtrip")
    assert read(root + "/rsync-roundtrip") == payload

    print("case: Git push and clone use native SSH with the same exported config", flush=True)
    run("ssh", "destination", shlex.join(["git", "init", "--bare", "-q", remote + "/repository.git"]))
    source("git", "init", "-q", root + "/repository")
    source("cp", root + "/original", root + "/repository/data")
    source("git", "-C", root + "/repository", "add", "data")
    source("git", "-C", root + "/repository", "-c", "user.name=SSH fixture", "-c", "user.email=fixture@example.invalid",
           "commit", "-qm", "fixture")
    git_environment = "GIT_SSH_COMMAND=" + ssh_command
    source("env", git_environment, "git", "-C", root + "/repository", "push", "destination:" + remote + "/repository.git",
           "HEAD:refs/heads/main")
    source("env", git_environment, "git", "clone", "-q", "--branch", "main", "destination:" + remote + "/repository.git",
           root + "/clone")
    assert read(root + "/clone/data") == payload
    no_pending()

    print("case: altered account, host and port cannot reuse the approved socket", flush=True)
    for options in (["-l", "root"], ["-p", "2222"], ["-o", "HostName=source"]):
        source("ssh", "-F", config, *options, "destination", "true", success=False)
    source("ssh", "-F", config, "source", "true", success=False)
    no_pending()

    print("case: stopped and reconnected masters do not revive an old export", flush=True)
    source("syq", "persist", "off")
    source("ssh", "-F", config, "destination", "true", success=False)
    source("syq", "persist", "ssh-config", "destination", success=False)
    no_pending()
    connect(ask=False)
    source("ssh", "-F", config, "destination", "true", success=False)
    export(config)
    source("ssh", "-F", config, "destination", "true")
    no_pending()
    print("Native SSH tools passed", flush=True)
finally:
    source("syq", "persist", "auth-from", "--for", "destination", "--reset")
    source("syq", "persist", "off")
    run("ssh", "source", "rm -rf -- " + shlex.quote(root))
    run("ssh", "destination", "rm -rf -- " + shlex.quote(remote))
