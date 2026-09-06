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
for name in ("laptop", "@laptop"):
    target = "skew-explicit" if name.startswith("@") else "skew-bare"
    run("ssh", "source", shlex.join([
        "syq-other-build", "cp", "/tmp/syq-real-ssh/return-source/message.txt",
        "--to", name, "--as", target,
    ]))
    assert (root / target).read_bytes() == expected

print("case: handoff preserves inherited results fd and raw path bytes", flush=True)
script = r'''
import json, os, subprocess, tempfile
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

print('case: unsupported return mappings still settle results after handoff', flush=True)
with tempfile.TemporaryFile() as results:
    result = subprocess.run(['syq-other-build', 'cp', '--mapping', '-', '--to', '@laptop',
                             '--into', 'skew-mapping', '--results-fd', str(results.fileno())],
                            input=b'', capture_output=True, pass_fds=(results.fileno(),), timeout=30)
    assert result.returncode != 0 and b'not yet independently enforceable' in result.stderr, result
    results.seek(0)
    records = [json.loads(line) for line in results]
    assert records[-1]['status'] == 'failed', records
'''
run("ssh", "source", "python3 -c " + shlex.quote(script))
assert (root / "skew-argv").read_bytes() == b"raw handoff\x00\xff"
assert not (root / "skew-mapping").exists()
assert json.loads(run("syq", "persist", "receive", "pending", "--json")) == []
print("Return build handoff passed", flush=True)
