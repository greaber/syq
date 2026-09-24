#!/usr/bin/env python3
"""Remote mapping generation and execution against disposable container trees."""
import json
from pathlib import Path
import subprocess
import tempfile


def run(args, *, ok=True, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=45, **kwargs)
    assert (result.returncode == 0) == ok, (args, result.returncode, result.stderr)
    return result


def remote(code):
    return run(['ssh', 'source', 'python3 -'], input=code.encode())


root = '/tmp/syq-real-ssh/map-generation'
remote(f'''from pathlib import Path
import os
p = Path({root!r}); p.mkdir(parents=True)
(p/'photos').mkdir()
(p/'photos'/'line\\n%2F+').write_bytes(b'photo')
(p/'empty').mkdir()
(p/'link').symlink_to('photos/line\\n%2F+')
os.mkfifo(p/'fifo')
os.utime(p/'photos'/'line\\n%2F+', (123,123))
''')
try:
    for extra in [[], ['--include', 'kind,size,mtime'], ['--where', 'src.kind = \"file\" and src.mtime < now']]:
        args = ['--srcs-in', root, *extra]
        # The same walker and ordering run locally on the source or via RPC.
        import shlex
        direct = run(['ssh', 'source', shlex.join(['syq', 'map', *args])])
        invoked = run(['syq', 'map', '--from', 'source', *args])
        assert invoked.stdout == direct.stdout, (invoked.stdout, direct.stdout)
    filtered = run(['syq', 'map', '--from', 'source', '--srcs-in', root,
                    '--where', 'src.kind = "file"'])
    assert len(filtered.stdout.splitlines()) == 1
    for option in ['mtime', '-mtime']:
        destination = '/tmp/syq-real-ssh/mtime-' + option
        run(['syq', 'cp', '--from', 'source', '-C', root, '--src', 'photos/line\n%2F+',
             '--to', 'destination', '--as', destination, '--preserve=' + option])
        observed = run(['ssh', 'destination', 'stat', '-c', '%Y', destination])
        assert (int(observed.stdout) == 123) == (option == 'mtime'), observed.stdout
        run(['ssh', 'destination', 'rm', destination])
    generated = run(['syq', 'map', '--from', 'source', '--srcs-in', root])
    entries = [json.loads(line) for line in generated.stdout.splitlines()]
    assert all(set(entry) == {'src', 'dst'} for entry in entries)
    for entry in entries:
        entry['dst']['value'] = 'renamed/' + entry['dst']['value']
    with tempfile.TemporaryDirectory() as tmp:
        manifest = Path(tmp)/'map.ndjson'
        manifest.write_text(''.join(json.dumps(entry)+'\n' for entry in entries))
        destination = Path(tmp)/'out'
        run(['syq', 'cp', '--from', 'source', '-C', root, '--mapping', str(manifest),
             '--into', str(destination), '--preserve', 'specials', '-q'])
        assert (destination/'renamed/photos/line\n%2F+').read_bytes() == b'photo'
        assert (destination/'renamed/link').is_symlink()
        assert (destination/'renamed/empty').is_dir()
    named = run(['syq', 'map', '--from', 'source', '-C', root, 'photos/line\n%2F+'])
    entry = json.loads(named.stdout)
    assert entry['src']['value'] == 'photos/line\n%2F+'
    assert entry['dst']['value'] == 'line\n%2F+'
    remote(f'''from pathlib import Path
p=Path({root!r})/'unreadable'; p.mkdir(); (p/'hidden').write_text('hidden'); p.chmod(0)
''')
    failed = run(['syq', 'map', '--from', 'source', '--srcs-in', root], ok=False)
    assert failed.stderr
    remote(f'''from pathlib import Path
import os
p=Path({root!r})/'unreadable'; p.chmod(0o700)
fd=os.open(os.fsencode({root!r})+b'/invalid-\\xff',os.O_CREAT|os.O_WRONLY,0o600); os.close(fd)
''')
    failed = run(['syq', 'map', '--from', 'source', '--srcs-in', root], ok=False)
    assert b'UTF-8' in failed.stderr
finally:
    remote(f'''from pathlib import Path
import shutil
p=Path({root!r})/'unreadable'
if p.exists(): p.chmod(0o700)
shutil.rmtree({root!r})
''')
print('remote mapping generation passed', flush=True)
