#!/usr/bin/env python3
"""Named copy/removal jobs with an ordinary SSH endpoint."""
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, timeout=45, **kwargs)


def remote(code, host='destination'):
    result = run(['ssh', host, 'python3 -'], input=code.encode())
    assert result.returncode == 0, result.stderr
    return result.stdout


with tempfile.TemporaryDirectory(prefix='syq-ssh-resume-') as tmp:
    root = Path(tmp)
    destination = '/tmp/syq-real-ssh/job-resume'
    env = dict(os.environ, XDG_CACHE_HOME=str(root / 'cache'))
    source = root / 'source'
    source.mkdir()
    (source / 'file').write_bytes(b'copied')
    remote(f'''from pathlib import Path
p = Path({destination!r}); p.mkdir()
(p / 'stale').write_bytes(b'stale')
''')
    identifiers = []
    try:
        first = run(['syq', 'cp', '--srcs-in', str(source), '--to', 'destination',
                     '--into', destination, '--prune', '--max-delete=0',
                     '--if-exists=error', '--results', str(root / 'copy.jsonl')], env=env)
        assert first.returncode == 25, (first.returncode, first.stderr)
        job = json.loads((root / 'copy.jsonl').read_text().splitlines()[0])['job_id']
        identifiers.append(job)
        second = run(['syq', 'cp', '--resume', job, '--max-delete=1'], env=env)
        assert second.returncode == 0, second.stderr
        remote(f'''from pathlib import Path
p = Path({destination!r})
assert (p / 'file').read_bytes() == b'copied'
assert not (p / 'stale').exists()
(p / 'blocked').mkdir(); (p / 'blocked/child').write_bytes(b'child')
(p / 'blocked').chmod(0o500)
''')
        # Explicit local coordination keeps the command and mutation journal
        # on the invoking host while both endpoints use ordinary SSH helpers.
        relay_source = destination + '-source'
        relay_destination = destination + '/relay'
        remote(f"from pathlib import Path; p=Path({relay_source!r}); p.mkdir(); (p/'file').write_bytes(b'relayed')", 'source')
        remote(f"from pathlib import Path; p=Path({relay_destination!r}); p.mkdir(); (p/'stale').write_bytes(b'stale')")
        first = run(['syq', 'cp', '--from', 'source', '--srcs-in', relay_source,
                     '--to', 'destination', '--into', relay_destination,
                     '--coordinate-at', 'local', '--prune', '--max-delete=0',
                     '--if-exists=error', '--results', str(root/'relay.jsonl')], env=env)
        assert first.returncode == 25, first.stderr
        job = json.loads((root/'relay.jsonl').read_text().splitlines()[0])['job_id']
        identifiers.append(job)
        second = run(['syq', 'cp', '--resume', job, '--max-delete=1'], env=env)
        assert second.returncode == 0, second.stderr
        remote(f"from pathlib import Path; import shutil; p=Path({relay_destination!r}); assert (p/'file').read_bytes()==b'relayed'; assert not (p/'stale').exists(); shutil.rmtree(p)")
        first = run(['syq', 'rm', '--on', 'destination', '--srcs-in', destination,
                     '--results', str(root / 'remove.jsonl')], env=env)
        assert first.returncode != 0, first.stderr
        job = json.loads((root / 'remove.jsonl').read_text().splitlines()[0])['job_id']
        identifiers.append(job)
        remote(f'''from pathlib import Path
p = Path({destination!r})
assert not (p / 'file').exists()
(p / 'file').write_bytes(b'replacement')
(p / 'blocked').chmod(0o700)
''')
        second = run(['syq', 'rm', '--resume', job], env=env)
        assert second.returncode == 0, second.stderr
        remote(f'''from pathlib import Path
p = Path({destination!r})
assert (p / 'file').read_bytes() == b'replacement'
assert not (p / 'blocked').exists()
assert not (Path.home() / '.cache/syq/jobs' / {job + '.remove'!r}).exists()
''')
        for job in identifiers:
            assert not (root / 'cache/syq/jobs' / (job + '.command')).exists()
    finally:
        remote(f"from pathlib import Path; import shutil; p=Path({destination + '-source'!r}); shutil.rmtree(p, ignore_errors=True)", 'source')
        remote(f'''from pathlib import Path
import shutil
p = Path({destination!r})
if (p / 'blocked').exists(): (p / 'blocked').chmod(0o700)
shutil.rmtree(p)
for job in {identifiers!r}:
    (Path.home() / '.cache/syq/jobs' / (job + '.remove')).unlink(missing_ok=True)
''')
print('named jobs across ordinary SSH passed', flush=True)
