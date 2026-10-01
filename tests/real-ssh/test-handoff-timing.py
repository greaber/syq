"""Elapsed time across build handoff, including an optional unchanged old helper."""
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def check(current, helper, *, legacy=False):
    with tempfile.TemporaryDirectory(prefix="syq-handoff-timing-") as tmp:
        root = Path(tmp).resolve()
        (root / "bin").mkdir()
        (root / "source").write_bytes(b"payload")
        ssh = root / "bin/ssh"
        ssh.write_text('#!/bin/sh\nif [ "$1" = -V ]; then echo OpenSSH_9.2p1 >&2; exit 0; fi\nsleep 0.2\nexit 255\n')
        ssh.chmod(0o700)
        env = {key: value for key, value in os.environ.items() if not key.startswith("SYQ_")}
        env.update(HOME=str(root), XDG_CONFIG_HOME=str(root / "config"),
                   XDG_RUNTIME_DIR=str(root / "runtime"), XDG_CACHE_HOME=str(root / "cache"),
                   PATH=str(root / "bin") + ":" + env["PATH"], SYQ_NO_UPDATE_CHECK="1",
                   # A stale ambient value must be ignored outside a handoff.
                   SYQ_RETURN_COPY_START_NS="1")
        identity = subprocess.check_output([helper, "--build-identity"], env=env, text=True).strip()
        registry = root / ".syq-destinations-v3"
        registry.mkdir(mode=0o700)
        registration = registry / "laptop.json"
        registration.write_text(json.dumps(dict(
            version=3, identity=identity, socket=str(root / "receiver.sock"),
            secret="fixture", program=list(os.fsencode(helper)))))
        registration.chmod(0o600)
        errors, messages = [], []
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(root / "receiver.sock"))
            listener.listen()
            listener.settimeout(10)

            def respond():
                try:
                    for expected in ("Ping", "Forward"):
                        conn, _ = listener.accept()
                        with conn:
                            conn.settimeout(5)
                            with conn.makefile("rb") as stream:
                                size, = struct.unpack("!I", stream.read(4))
                                message = json.loads(stream.read(size))["message"]
                            assert message == expected or expected in message, message
                            messages.append(expected)
                            response = "Ready" if expected == "Ping" else {"Error": "denied by timing fixture"}
                            data = json.dumps(response).encode()
                            conn.sendall(struct.pack("!I", len(data)) + data)
                except Exception as error:
                    errors.append(repr(error))

            thread = threading.Thread(target=respond)
            thread.start()
            try:
                started = time.monotonic()
                result = subprocess.run([
                    current, "cp", "source", "--to", "backup", "--results=result.ndjson",
                    "--ignore-from", "/dev/stdin",
                ], cwd=root, env=env, input="*.tmp\n", capture_output=True, text=True, timeout=12)
                wall_ms = (time.monotonic() - started) * 1000
            finally:
                thread.join(11)
            assert not thread.is_alive() and not errors, (messages, errors)
        assert result.returncode == 1 and "denied by timing fixture" in result.stderr, result
        records = [json.loads(line) for line in (root / "result.ndjson").read_text().splitlines()]
        terminal = records[-1]
        assert terminal["status"] == "failed", records
        assert sum(record.get("type") == "result" for record in records) == 1, records
        notice = "registered helper predates handoff timing" in result.stderr
        assert notice == legacy, result.stderr
        assert terminal["elapsed_ms"] <= wall_ms + 50, (terminal, wall_ms)
        if not legacy:
            assert terminal["elapsed_ms"] >= 175, (terminal, wall_ms, result.stderr)
        print(json.dumps(dict(helper=identity, legacy=legacy, wall_ms=round(wall_ms),
                              elapsed_ms=terminal["elapsed_ms"])), flush=True)


if __name__ == "__main__":
    current, helper = (str(Path(shutil.which(arg) or arg).resolve()) for arg in sys.argv[1:3])
    assert subprocess.check_output([current, "--build-identity"]) != subprocess.check_output([helper, "--build-identity"])
    check(current, current)
    check(current, helper, legacy="--legacy-helper" in sys.argv[3:])
