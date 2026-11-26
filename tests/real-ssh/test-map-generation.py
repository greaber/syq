#!/usr/bin/env python3
"""Remote mapping generation and listing, and mapping execution, against disposable container trees."""
import json
from pathlib import Path
import shlex
import subprocess
import tempfile


def run(args, *, ok=True, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=45, **kwargs)
    assert (result.returncode == 0) == ok, (args, result.returncode, result.stderr)
    return result


def remote(code):
    return run(['ssh', 'source', 'python3 -'], input=code.encode())


def enrollments():
    state = Path.home()/'.local/state/syq/enrollments'
    return {bytes(json.loads(path.read_bytes())['id']).hex() for path in state.glob('*/enrollment.json')}


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
existing = enrollments()
try:
    for extra in [[], ['--include', 'kind,size,mtime'], ['--where', 'src.kind = \"file\" and src.mtime < now']]:
        args = ['--srcs-in', root, *extra]
        # The same walker and ordering run locally on the source or via RPC.
        direct = run(['ssh', 'source', shlex.join(['syq', 'map', *args])])
        invoked = run(['syq', 'map', '--from', 'source', *args])
        assert invoked.stdout == direct.stdout, (invoked.stdout, direct.stdout)
    # syq find and ls walk the same way on the source and over SSH.
    for args in [['find', root], ['ls', '-C', root, '--json'], ['find', root, '--long', '--depth', '1'],
                 ['find', '-C', root, '--null', '--where', 'kind != "dir"']]:
        direct = run(['ssh', 'source', shlex.join(['syq', *args])])
        invoked = run(['syq', args[0], '--on', 'source', *args[1:]])
        assert invoked.stdout == direct.stdout, (args, invoked.stdout, direct.stdout)
    listed = run(['syq', 'find', '--on', 'source', '-C', root, '--null'])
    assert sorted(listed.stdout.split(b'\0')[:-1]) == [b'empty', b'fifo', b'link', b'photos', b'photos/line\n%2F+']
    filtered = run(['syq', 'map', '--from', 'source', '--srcs-in', root,
                    '--where', 'src.kind = "file"'])
    # --where filters the file, link and FIFO records; directories always remain.
    assert sorted(json.loads(line)['src']['value'] for line in filtered.stdout.splitlines()) \
        == ['empty', 'photos', 'photos/line\n%2F+'], filtered.stdout
    for option in ['default', 'mtime']:
        destination = '/tmp/syq-real-ssh/mtime-' + option
        run(['syq', 'cp', '--from', 'source', '-C', root, '--src', 'photos/line\n%2F+',
             '--to', 'destination', '--as', destination, *(['--copy-metadata=mtime'] if option == 'mtime' else [])])
        observed = run(['ssh', 'destination', 'stat', '-c', '%Y', destination])
        assert int(observed.stdout) == 123, observed.stdout
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
             '--into', str(destination), '--copy-metadata', 'specials', '-q'])
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
    # find reports the directory it cannot read, lists the rest, and fails.
    failed = run(['syq', 'find', '--on', 'source', '-C', root], ok=False)
    assert b'cannot read directory unreadable' in failed.stderr, failed.stderr
    assert b'photos\n' in failed.stdout, failed.stdout
    remote(f'''from pathlib import Path
import os
p=Path({root!r})/'unreadable'; p.chmod(0o700)
fd=os.open(os.fsencode({root!r})+b'/invalid-\\xff',os.O_CREAT|os.O_WRONLY,0o600); os.close(fd)
''')
    failed = run(['syq', 'map', '--from', 'source', '--srcs-in', root], ok=False)
    assert b'UTF-8' in failed.stderr
    failed = run(['syq', 'ls', '--on', 'source', '-C', root, '--json'], ok=False)
    assert b'--null' in failed.stderr, failed.stderr
    listed = run(['syq', 'ls', '--on', 'source', '-C', root, '--null'])
    assert b'invalid-\xff' in listed.stdout.split(b'\0')
finally:
    # Copies to destination enroll the destination account. Revoke it so
    # later cases start without receiver state.
    for identifier in enrollments() - existing:
        run(['syq', 'receiver', 'revoke', identifier])
    remote(f'''from pathlib import Path
import shutil
p=Path({root!r})/'unreadable'
if p.exists(): p.chmod(0o700)
shutil.rmtree({root!r})
''')
print('remote mapping generation and listing passed', flush=True)
