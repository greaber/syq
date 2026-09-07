#!/usr/bin/env python3
"""Revoke two active restricted copies in the disposable OpenSSH lab."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time
import uuid


def run(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=45, **kwargs)


def remote(command):
    return run("ssh", "destination", command, stdout=subprocess.PIPE, text=True).stdout.strip()


def enrollment(parent):
    records = [json.loads(path.read_bytes()) for path in
               (Path.home() / ".local/state/syq/restricted").glob("*/metadata.json")]
    matches = [record for record in records if record["requested_parent"] == parent]
    assert len(matches) == 1, matches
    return matches[0]


def wait_for(label, probe, seconds=25):
    deadline = time.monotonic() + seconds
    progress = 0
    last = None
    while time.monotonic() < deadline:
        done, last = probe()
        if done:
            return last
        if time.monotonic() >= progress:
            print(f"Waiting for {label}: {last}", flush=True)
            progress = time.monotonic() + 2
        time.sleep(.1)
    raise AssertionError(f"{label} timed out; last state: {last}")


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)


def main():
    root = "/tmp/syq-real-ssh/revoke-active-" + uuid.uuid4().hex
    source = "/tmp/syq-real-ssh/revoke-source"
    remote("mkdir -p " + shlex.quote(root))
    run("ssh", "source", "python3 -c " + shlex.quote(
        f"from pathlib import Path; Path({source!r}).write_bytes(b'x' * (32 << 20))"))
    run("syq", "receiver", "enroll", f"destination:{root}/one")
    before = enrollment(root)
    # EnrollmentId is serialized as bytes in the private JSON state.
    identifier = bytes(before["id"]).hex()
    state = before["remote_home"] + "/.local/share/syq/restricted/" + identifier
    processes = []
    outputs = []
    try:
        for name in ("one", "two"):
            output = tempfile.TemporaryFile()
            outputs.append(output)
            process = subprocess.Popen([
                "syq", "cp", "--from", "source", source, "--to", "destination",
                "--as", f"{root}/{name}", "--connections", "1", "--bwlimit", "1M", "--no-progress",
            ], stdout=output, stderr=output, start_new_session=True)
            processes.append(process)
        probe = "python3 -c " + shlex.quote(f"""
import json
from pathlib import Path
root = Path({root!r})
print(json.dumps([any(p.open('rb').read(4 << 20) == b'x' * (4 << 20) for p in root.glob('.' + name + '.syq-part.*')) for name in ('one', 'two')]))
""")
        def started():
            assert all(process.poll() is None for process in processes), "copy exited before revocation"
            observed = json.loads(remote(probe))
            return all(observed), observed
        wait_for("two admitted, writing receivers", started)
        run("syq", "receiver", "revoke", identifier)
        remote("test ! -e " + shlex.quote(state))
        for process in processes:
            status = process.wait(timeout=25)
            assert status != 0, "revoked transfer reported success"
        for output in outputs:
            output.seek(0)
            print(output.read().decode(errors="replace"), end="", flush=True)
        remote("test ! -e " + shlex.quote(root + "/one") + " && test ! -e " + shlex.quote(root + "/two"))
        # Copies under a fresh enrollment can resume their partials normally.
        run("syq", "receiver", "enroll", f"destination:{root}/one")
        after = enrollment(root)
        assert after["id"] != before["id"], "revocation reused the old enrollment identity"
        assert after["receipt_public_key"] != before["receipt_public_key"]
        for name in ("one", "two"):
            with tempfile.TemporaryDirectory(prefix="revoke-resume-results-") as temporary:
                results = Path(temporary) / "results.ndjson"
                run("syq", "cp", "--from", "source", source, "--to", "destination",
                    "--as", f"{root}/{name}", "--connections", "2", "--no-progress", "--results", str(results))
                terminal = [json.loads(line) for line in results.read_text().splitlines()][-1]
                assert terminal["type"] == "result" and terminal["status"] == "success", terminal
                assert 0 < terminal["bytes_transferred"] <= 28 << 20, terminal
            actual = remote("sha256sum " + shlex.quote(root + "/" + name)).split()[0]
            assert actual == hashlib.sha256(b'x' * (32 << 20)).hexdigest()
        run("syq", "receiver", "revoke", bytes(after["id"]).hex())
        print("Active receiver revocation and fresh-enrollment resume passed", flush=True)
    finally:
        for process in processes:
            stop(process)
        for output in outputs:
            output.close()


if __name__ == "__main__":
    main()
