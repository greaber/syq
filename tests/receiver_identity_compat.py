#!/usr/bin/env python3
"""Run against candidate and released v0.5.2 binaries; uses only temporary state.

Usage: python3 tests/receiver_identity_compat.py CANDIDATE V0_5_2_BINARY
"""
import contextlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

candidate, previous = map(lambda arg: str(Path(arg).resolve()), sys.argv[1:])


def run(*args, env=None, success=True, input=None):
    result = subprocess.run(args, env=env, input=input, capture_output=True, timeout=15)
    assert (result.returncode == 0) == success, (args, result.returncode, result.stderr)
    return result


def read_frame(stream):
    deadline = time.monotonic() + 10

    def exact(count):
        data = b""
        while len(data) < count:
            remaining = deadline - time.monotonic()
            assert remaining > 0 and select.select([stream], [], [], remaining)[0], "frame timeout"
            block = os.read(stream.fileno(), count - len(data))
            assert block, "truncated frame"
            data += block
        return data

    return json.loads(exact(struct.unpack("!I", exact(4))[0]))


@contextlib.contextmanager
def registration(binary, home, key, *, success=True, legacy=False, retry=False, messages=None,
                 secret="test-connection-secret"):
    """A local test peer exercises the binary's actual registration entry point."""
    env = dict(os.environ, HOME=str(home), SYQ_NO_UPDATE_CHECK="1")
    path = home / ("return-" + uuid.uuid4().hex + ".sock")
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(path))
    path.chmod(0o600)
    listener.listen()
    listener.settimeout(.1)
    stopped = threading.Event()
    errors = []

    def serve():
        try:
            while not stopped.is_set():
                try:
                    stream, _ = listener.accept()
                except TimeoutError:
                    continue
                with stream:
                    stream.settimeout(10)
                    envelope = read_frame(stream)
                    assert envelope["secret"] == secret
                    message = envelope["message"]
                    if messages is not None:
                        messages.append(message)
                    if message == "Ping":
                        reply = "Ready"
                    elif legacy:
                        reply = {"Error": "unknown variant Identify (v0.5.2 peer)"}
                    else:
                        fields = message["Identify"]
                        payload = json.dumps([fields["name"], fields["challenge"], envelope["secret"]],
                                             separators=(",", ":")).encode()
                        signing_env = dict(os.environ)
                        signing_env.pop("SSH_AUTH_SOCK", None)
                        signature = run("ssh-keygen", "-Y", "sign", "-f", str(key),
                                        "-n", "syq-receiver-identity-v1", env=signing_env,
                                        input=payload).stdout.decode()
                        reply = {"Identity": {"public_key": key.with_suffix(".pub").read_text().strip(),
                                              "signature": signature}}
                    data = json.dumps(reply).encode()
                    stream.sendall(struct.pack("!I", len(data)) + data)
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    process = subprocess.Popen([binary, "--destination-register", "laptop", str(path),
                                secret], env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if retry:
            _, stderr = process.communicate(timeout=15)
            assert process.returncode == 75 and b"still closing" in stderr, stderr
        elif success:
            assert read_frame(process.stdout) == "Ready"
        else:
            _, stderr = process.communicate(timeout=15)
            assert process.returncode != 0 and b"different receiver" in stderr, stderr
        yield env
    finally:
        if process.poll() is None:
            process.stdin.close()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise
        stopped.set()
        thread.join(timeout=12)
        listener.close()
        assert not thread.is_alive() and not errors, errors


with tempfile.TemporaryDirectory(prefix="syq-id-compat-") as directory:
    home = Path(directory)
    key_one, key_two = home / "one", home / "two"
    for key in (key_one, key_two):
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
    owner = home / ".syq-destinations-v3/laptop.owner"
    advertisement = home / ".syq-destinations-v3/laptop.json"
    with registration(previous, home, key_one, legacy=True) as env:
        old_bytes = advertisement.read_bytes()
        run(candidate, "persist", "destinations", "wait", "laptop", "--timeout", "1", env=env)
        assert advertisement.read_bytes() == old_bytes and not owner.exists()
    print("PASS: new binary reads unchanged v0.5.2 advertisement and discovery", flush=True)

    messages = []
    with registration(candidate, home, key_one, messages=messages) as env:
        owned_bytes = owner.read_bytes()
        before_retry = list(messages)
        with registration(candidate, home, key_one, retry=True):
            assert messages == before_retry, messages
            assert owner.read_bytes() == owned_bytes
        with registration(candidate, home, key_one, retry=True, secret="restarted-service"):
            assert messages == before_retry, messages
            assert owner.read_bytes() == owned_bytes
        with registration(candidate, home, key_two, success=False, secret="other-receiver"):
            assert owner.read_bytes() == owned_bytes
        print("PASS: reconnects and service restarts wait without contacting or displacing the old transport", flush=True)
        run(previous, "persist", "destinations", "wait", "laptop", "--timeout", "1", env=env)
        run(candidate, "persist", "destinations", "wait", "laptop", "--timeout", "1", env=env)
    assert owner.read_bytes() == owned_bytes and not advertisement.exists()
    print("PASS: v0.5.2 discovers new advertisements; disconnect preserves ownership", flush=True)

    with registration(previous, home, key_one, legacy=True) as env:
        result = run(candidate, "persist", "destinations", "wait", "laptop", "--timeout", "1",
                     env=env, success=False)
        assert b"cannot verify receiver identity" in result.stderr, result.stderr
        assert owner.read_bytes() == owned_bytes
    print("PASS: downgraded receiver without identity support is rejected for an assigned name", flush=True)

    with registration(previous, home, key_two) as env:
        result = run(candidate, "persist", "destinations", "wait", "laptop", "--timeout", "1",
                     env=env, success=False)
        assert b"different receiver" in result.stderr, result.stderr
        assert owner.read_bytes() == owned_bytes
    print("PASS: new lookup rejects a conflicting advertisement written by v0.5.2", flush=True)

    with registration(candidate, home, key_two, success=False):
        assert owner.read_bytes() == owned_bytes
    run(candidate, "persist", "destinations", "forget", "laptop", env=env)
    with registration(candidate, home, key_two):
        assert owner.read_bytes() != owned_bytes
    print("PASS: offline collision is rejected until explicit forget", flush=True)
