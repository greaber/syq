#!/usr/bin/env python3
"""Named copy/removal jobs with an ordinary SSH endpoint."""
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, timeout=45, **kwargs)


def remote(code):
    result = run(['ssh', 'destination', 'python3 -'], input=code.encode())
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
        remote(f'''from pathlib import Path
import shutil
p = Path({destination!r})
if (p / 'blocked').exists(): (p / 'blocked').chmod(0o700)
shutil.rmtree(p)
for job in {identifiers!r}:
    (Path.home() / '.cache/syq/jobs' / (job + '.remove')).unlink(missing_ok=True)
''')
print('named jobs across ordinary SSH passed', flush=True)
