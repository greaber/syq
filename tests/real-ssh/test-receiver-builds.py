#!/usr/bin/env python3
"""Exercise independent receiver enrollments through real restricted SSH copies."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import uuid


def run(*args, success=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=90)
    if (result.returncode == 0) != success:
        raise AssertionError(f"{args}: {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def remote(script):
    return run("ssh", "destination", "python3 -c " + shlex.quote(script)).strip()


def enrollments(parent):
    records = []
    for path in (Path.home() / ".local/state/syq/restricted").rglob("metadata.json"):
        record = json.loads(path.read_bytes())
        if record["requested_parent"] == parent:
            records.append((path, record))
    return records


def snapshot(record):
    identifier = bytes(record["id"]).hex()
    state = record["remote_home"] + "/.local/share/syq/restricted/" + identifier
    return json.loads(remote(f"""
import hashlib, json
from pathlib import Path
state = Path({state!r})
print(json.dumps({{str(p.relative_to(state)): hashlib.sha256(p.read_bytes()).hexdigest()
    for p in state.rglob('*') if p.is_file()}}))
"""))


def main():
    programs = sys.argv[1:] or ["syq", "syq-other-build"]
    assert len(programs) == 2
    identities = [run(program, "--build-identity").strip() for program in programs]
    assert identities[0] != identities[1], identities
    root = "/tmp/syq-real-ssh/builds-" + uuid.uuid4().hex
    source = root + "/source"
    run("ssh", "source", "python3 -c " + shlex.quote(
        f"from pathlib import Path; p=Path({source!r}); p.parent.mkdir(); p.write_bytes(b'x' * (4 << 20))"))
    remote(f"from pathlib import Path; Path({root!r}).mkdir()")

    def copy(index, leaf, dry=False):
        return run(programs[index], "cp", "--no-progress", "--no-tcp",
                   "--performance-tuning", "workers=2", "--resource-limits", "bandwidth=2M",
                   "--from", "source", source, "--to", "destination", "--as", root + "/" + leaf,
                   *(["--dry-run"] if dry else []), success=not dry)

    copy(0, "first")
    initial = enrollments(root)
    assert len(initial) == 1, initial
    path_a, record_a = initial[0]
    metadata_a = path_a.read_bytes()
    state_a = snapshot(record_a)
    assert any(name.startswith("replay/") for name in state_a), state_a
    copy(1, "dry", dry=True)
    assert enrollments(root) == initial, "a dry run installed an enrollment"
    copy(1, "second")
    records = enrollments(root)
    assert len(records) == 2, records
    record_b = next(record for _, record in records if record["id"] != record_a["id"])
    assert record_a["receiver_path"] != record_b["receiver_path"]
    assert record_a["receipt_public_key"] != record_b["receipt_public_key"]
    assert path_a.read_bytes() == metadata_a
    assert snapshot(record_a) == state_a, "another build changed existing enrollment state"
    for record, identity in zip([record_a, record_b], identities):
        assert remote("import subprocess; print(subprocess.check_output([" + repr(record["receiver_path"]) + ", '--build-identity'], text=True).strip())") == identity
    # Each build must reuse its own enrollment even after the other installed.
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        list(pool.map(lambda i: copy(i, f"concurrent-{i}"), range(2)))
    assert len(enrollments(root)) == 2
    actual = json.loads(remote(f"""
import hashlib, json
from pathlib import Path
print(json.dumps([hashlib.sha256((Path({root!r})/name).read_bytes()).hexdigest()
    for name in ['first', 'second', 'concurrent-0', 'concurrent-1']]))
"""))
    assert actual == [hashlib.sha256(b'x' * (4 << 20)).hexdigest()] * 4
    # Explicit refresh preserves this build's key and all redeemed grants.
    before = snapshot(record_b)
    run(programs[1], "receiver", "enroll", "destination:" + root + "/second")
    assert snapshot(record_b) == before
    run(programs[0], "receiver", "revoke", bytes(record_a["id"]).hex())
    copy(1, "after-revoke")
    run(programs[1], "receiver", "revoke", bytes(record_b["id"]).hex())
    assert not enrollments(root)
    for record in [record_a, record_b]:
        # Other scopes may share this build's executable. Once none do, the
        # last revoker removes it, including a legacy receiver left by an old client.
        remote(f"""
import json
from pathlib import Path
receiver = Path({record['receiver_path']!r})
state = Path({record['remote_home']!r}) / '.local/share/syq/restricted'
references = [json.loads(p.read_bytes())['receiver_path'] for p in state.glob('*/config.json')]
assert str(receiver) in references or not receiver.exists(), receiver
""")
    print("Receiver build isolation, concurrency, refresh, and revocation passed:", identities, flush=True)


if __name__ == "__main__":
    main()
