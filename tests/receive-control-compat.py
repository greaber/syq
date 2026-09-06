"""Exercise released/local approval clients against a bounded disposable service.

The old executable must be the verified v0.4.0 release. This checks actual old
serialization and deserialization, independently of the candidate's Rust types.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument("--old", required=True, type=Path)
parser.add_argument("--candidate", required=True, type=Path)
options = parser.parse_args()
old, candidate = options.old.resolve(), options.candidate.resolve()
assert subprocess.check_output([old, "--version"], text=True).strip() == "syq 0.4.0"
fixture = json.loads((Path(__file__).parent / "fixtures/receive-copy-decision-v0.4.0.json").read_text())
request_id = fixture["decision"]["id"]
errors, observed = [], []
stop = threading.Event()

with tempfile.TemporaryDirectory(prefix="syq-old-") as tmp:
    home = Path(tmp)
    runtime = home / "r"
    parent = runtime / f"syq-persist-{os.geteuid()}"
    scope = parent / "global"
    for directory in [runtime, parent, scope]:
        directory.mkdir(mode=0o700)
    (scope / ".syq-persistence").write_text("syq persistence scope\n")

    def service(host):
        key = "cm-" + hashlib.sha256(("@" + host).encode()).hexdigest()[:16]
        record = scope / (key + ".json")
        record.write_text(json.dumps({"host": host, "user": None, "port": None}))
        record.chmod(0o600)
        lock = (scope / (key + ".recv-lock")).open("w")
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(scope / (key + ".recv")))
        listener.listen()
        listener.settimeout(.1)
        return listener, lock

    listener, lock = service("server")
    other_listener, other_lock = service("other-server")
    other_pending = []
    copy = {"id": request_id, "from": '"server"', "destination": '"/tmp/output"',
            "permission": "May create and overwrite matching entries", "max_bytes": 100,
            "max_entries": 10, "max_delete": 0, "preserve_permissions": False,
            "expires_at": int(time.time()) + 300, "notification": "disabled"}
    command = {key: copy[key] for key in ["id", "from", "expires_at", "notification"]}
    command.update(kind="command", argv=['"true"'], cwd='"/tmp"', permission="Runs as your local user")
    pending = [copy]

    def read_exact(peer, length):
        result = b""
        while len(result) < length:
            piece = peer.recv(length - len(result))
            assert piece, "truncated request"
            result += piece
        return result

    def serve():
        deadline = time.monotonic() + 30
        progress = time.monotonic() + 5
        try:
            while not stop.is_set():
                assert time.monotonic() < deadline, ("compatibility service timed out", observed)
                if time.monotonic() > progress:
                    print("Compatibility service waiting; requests:", len(observed), flush=True)
                    progress += 5
                readable, _, _ = select.select([listener, other_listener], [], [], .1)
                if not readable:
                    continue
                selected = readable[0]
                peer, _ = selected.accept()
                with peer:
                    peer.settimeout(2)
                    size = struct.unpack(">I", read_exact(peer, 4))[0]
                    assert 0 < size < 256 * 1024
                    request = json.loads(read_exact(peer, size))
                    observed.append(request)
                    response = {"version": 2, "identity": "compatibility-test", "pid": os.getpid(),
                                "endpoint": "server" if selected is listener else "other-server",
                                "name": "laptop", "approval": "ask",
                                "pending": list(pending if selected is listener else other_pending),
                                "decision_error": None,
                                "connection": {"phase": "online", "error": None, "ssh_pid": None}}
                    data = json.dumps(response).encode()
                    peer.sendall(struct.pack(">I", len(data)) + data)
                    if request.get("stop"):
                        fcntl.flock(lock if selected is listener else other_lock, fcntl.LOCK_UN)
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=serve)
    worker.start()
    env = {**os.environ, "HOME": tmp, "XDG_RUNTIME_DIR": str(runtime),
           "XDG_CONFIG_HOME": str(home / "config"), "SYQ_NO_UPDATE_CHECK": "1"}

    def run(binary, *args, success=True):
        if binary == candidate and args[:1] == ("recv",):
            args = ("persist", "receive", *args[1:])
        result = subprocess.run([binary, *args], env=env, cwd=home, capture_output=True, timeout=5)
        assert (result.returncode == 0) == success, (args, result)
        return result

    try:
        for binary in [old, candidate]:
            result = run(binary, "recv", "pending", "--json")
            assert json.loads(result.stdout) == [copy]
            run(binary, "recv", "approve", request_id)
            assert observed[-1] == fixture, observed[-1]
        print("Released copy status/decision bytes preserved in both directions", flush=True)
        pending[:] = [command]
        before = len([r for r in observed if r.get("decision")])
        run(old, "recv", "approve", request_id, success=False)
        assert len([r for r in observed if r.get("decision")]) == before
        assert json.loads(run(old, "recv", "pending", "--json").stdout) == []
        assert json.loads(run(candidate, "recv", "pending", "--json").stdout) == [command]
        run(candidate, "recv", "approve", request_id)
        assert observed[-1]["decision"]["kind"] == "command", observed[-1]
        print("Old client cannot display/approve a command; new decision identifies command kind", flush=True)
        # Each server connection has its own service and approval queue. A
        # command the old client cannot decode must not hide another server's copy.
        other_copy = {**copy, "id": "2" * 32, "from": '"other-server"'}
        other_pending[:] = [other_copy]
        assert json.loads(run(old, "recv", "pending", "--json").stdout) == [other_copy]
        combined = json.loads(run(candidate, "recv", "pending", "--json").stdout)
        assert sorted(combined, key=lambda item: item["id"]) == [command, other_copy]
        run(old, "recv", "approve", other_copy["id"])
        assert observed[-1]["decision"] == {"id": other_copy["id"], "allow": True}
        print("Old client still lists and approves another server's copy while a command is pending", flush=True)
        run(old, "recv", "off")
        assert any(r.get("stop") for r in observed)
        print("Released client can still stop receiving while a command is pending", flush=True)
    finally:
        stop.set()
        worker.join(timeout=3)
        listener.close()
        other_listener.close()
        lock.close()
        other_lock.close()
        assert not worker.is_alive()
    assert not errors, errors
