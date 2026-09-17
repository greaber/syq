"""Different PATH build, pinned return helper, unchanged streams and arguments."""
import json
from pathlib import Path
import shlex
import subprocess


def run(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=40, **kwargs)
    assert result.returncode == 0, (args, result)
    return result.stdout


print("case: discovery and return copies work from a different server PATH build", flush=True)
identity = run("syq", "--build-identity")
other = run("ssh", "source", "syq-other-build --build-identity")
assert identity != other, (identity, other)
run("syq", "persist", "receive", "on", "--approve", "always", "--notify", "off")
run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
run("ssh", "source", "syq-other-build persist destinations wait laptop --timeout 5")
root = Path("/tmp/syq-real-ssh-receive")
expected = run("ssh", "source", "cat /tmp/syq-real-ssh/return-source/message.txt")
for name in ("@laptop",):
    target = "skew-explicit"
    run("ssh", "source", shlex.join([
        "syq-other-build", "cp", "/tmp/syq-real-ssh/return-source/message.txt",
        "--to", name, "--as", target,
    ]))
    assert (root / target).read_bytes() == expected

print("case: handoff preserves inherited results fd and raw path bytes", flush=True)
script = r'''
import base64, json, os, subprocess, tempfile
base = b'/tmp/syq-real-ssh/handoff-source'
os.mkdir(base)
name = b'raw-\xff\n$(false)'
source = base + b'/' + name
with open(source, 'wb') as f:
    f.write(b'raw handoff\x00\xff')
with tempfile.TemporaryFile() as results:
    argv = ['syq-other-build', 'cp', os.fsdecode(source), '--to', '@laptop',
            '--as', 'skew-argv', '--results-fd', str(results.fileno())]
    result = subprocess.run(argv, capture_output=True,
                            pass_fds=(results.fileno(),), timeout=30)
    assert result.returncode == 0, result
    results.seek(0)
    records = [json.loads(line) for line in results]
    assert sum(record.get('type') == 'result' for record in records) == 1, records
    assert records[-1]['status'] == 'success', records

print('case: mapping stdin and results survive return handoff', flush=True)
manifest = json.dumps({'src': {'encoding': 'base64', 'value': base64.b64encode(name).decode()},
                       'dst': {'encoding': 'utf-8', 'value': 'nested/mapped'}}).encode() + b'\n'
with tempfile.TemporaryFile() as results:
    result = subprocess.run(['syq-other-build', 'cp', '-C', os.fsdecode(base), '--mapping', '-',
                             '--to', '@laptop', '--into', 'skew-mapping',
                             '--results-fd', str(results.fileno())],
                            input=manifest, capture_output=True, pass_fds=(results.fileno(),), timeout=30)
    assert result.returncode == 0, result
    results.seek(0)
    records = [json.loads(line) for line in results]
    assert records[-1]['status'] == 'success', records

print('case: invalid return mappings still settle results after handoff', flush=True)
with tempfile.TemporaryFile() as results:
    result = subprocess.run(['syq-other-build', 'cp', '--mapping', '-', '--to', '@laptop',
                             '--into', 'skew-invalid-mapping', '--results-fd', str(results.fileno())],
                            input=b'invalid JSON\n', capture_output=True,
                            pass_fds=(results.fileno(),), timeout=30)
    assert result.returncode != 0 and b'--mapping' in result.stderr, result
    results.seek(0)
    records = [json.loads(line) for line in results]
    assert records[-1]['status'] == 'failed', records
'''
run("ssh", "source", "python3 -c " + shlex.quote(script))
assert (root / "skew-argv").read_bytes() == b"raw handoff\x00\xff"
assert (root / "skew-mapping" / "nested" / "mapped").read_bytes() == b"raw handoff\x00\xff"
assert not (root / "skew-invalid-mapping").exists()
assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []

print("case: piped and single-writer FIFO ignore rules survive handoff and protect pruning", flush=True)
setup = r'''
from pathlib import Path
base = Path('/tmp/syq-real-ssh/handoff-source')
source = base / 'ignore-source'
source.mkdir()
for name in ['keep.txt', 'drop.tmp', 'allow.tmp', 'skip.log', 'drop.cache', 'keep.cache']:
    (source / name).write_bytes(b'new source contents')
(base / 'extra-rules').write_bytes(b'*.cache\n')
'''
run("ssh", "source", "python3 -c " + shlex.quote(setup))
run("syq", "persist", "receive", "on", "--max-delete", "1", "--notify", "off")
run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
try:
    for binary in ["syq", "syq-other-build"]:
        for kind in ["stdin", "fifo"]:
            target = "ignore-" + binary + "-" + kind
            destination = root / target
            destination.mkdir()
            for name in ["orphan.tmp", "orphan.log", "orphan.cache", "drop.tmp", "stale.txt"]:
                (destination / name).write_bytes(b'protected destination contents')
            script = r'''
import os, subprocess, sys
base = '/tmp/syq-real-ssh/handoff-source'
binary, kind, target = sys.argv[1:]
patterns = b'\xef\xbb\xbf*.tmp\r\n'
path = '/dev/stdin' if kind == 'stdin' else base + '/fifo-' + binary
writer = None
if kind == 'fifo':
    os.mkfifo(path)
    writer = subprocess.Popen([sys.executable, '-c',
        'import sys; f = open(sys.argv[1], "wb"); f.write(bytes.fromhex(sys.argv[2])); f.close()',
        path, patterns.hex()])
try:
    args = [binary, 'cp', '--srcs-in', base + '/ignore-source', '--ignore', '*.log',
            '--ignore', '!drop.tmp', '--ignore-from', path, '--ignore', '!allow.tmp',
            '--ignore-from', base + '/extra-rules', '--ignore', '!keep.cache',
            '--to', '@laptop', '--into', target,
            '--prune', '--max-delete', '1']
    if kind == 'stdin':
        args.append('--follow')  # /dev/stdin is a symlink on Linux.
    result = subprocess.run(args, input=patterns if kind == 'stdin' else None,
                            capture_output=True, timeout=15)
    assert result.returncode == 0, result
    if writer:
        assert writer.wait(timeout=3) == 0
finally:
    if writer and writer.poll() is None:
        writer.kill()
        writer.wait(timeout=3)
'''
            run("ssh", "source", shlex.join(["python3", "-c", script, binary, kind, target]))
            for name in ["keep.txt", "allow.tmp", "keep.cache"]:
                assert (destination / name).read_bytes() == b'new source contents', (target, name)
            for name in ["orphan.tmp", "orphan.log", "orphan.cache", "drop.tmp"]:
                assert (destination / name).read_bytes() == b'protected destination contents', (target, name)
            for name in ["skip.log", "drop.cache", "stale.txt"]:
                assert not (destination / name).exists(), (target, name)
finally:
    run("syq", "persist", "receive", "on", "--max-delete", "0", "--notify", "off")
    run("syq", "persist", "receive", "wait", "source", "--timeout", "30")
print("Return build handoff passed", flush=True)
