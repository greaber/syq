#!/usr/bin/env python3
"""Downloaded directories stay private until their marker metadata is applied.

Each download is held at copy finalization (a debug build's test barrier),
after every object is written and before any directory metadata is applied.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import check as c

UMASK = 0o022


def mode(path):
    return path.stat().st_mode & 0o7777


def held(args, root, observe):
    """Run a download, call observe() at finalization, and return its result."""
    ready = root / 'finalizing'
    continuation = root / 'continue'
    for path in (ready, continuation):
        path.unlink(missing_ok=True)
    command = [c.SYQ, 'cp', '--no-progress']
    for name, value in c.HEADERS.items():
        command += ['--s3-header', name + ': ' + value]
    env = {**os.environ, 'SYQ_TEST_FINALIZATION_READY_FILE': str(ready),
           'SYQ_TEST_FINALIZATION_CONTINUE_FILE': str(continuation)}
    process = subprocess.Popen(command + list(map(str, args)), env=env, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               preexec_fn=lambda: os.umask(UMASK))
    try:
        deadline = time.monotonic() + 60
        next_progress = time.monotonic() + 5
        while not ready.exists():
            if process.poll() is not None:
                raise AssertionError(f'download exited before finalization: {process.communicate()}')
            if time.monotonic() >= deadline:
                raise AssertionError('timed out waiting for the download to reach finalization')
            if time.monotonic() >= next_progress:
                print('Waiting for the download to reach finalization', flush=True)
                next_progress = time.monotonic() + 5
            time.sleep(.01)
        observed = observe()
        continuation.write_text('continue')
        stdout, stderr = process.communicate(timeout=60)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    assert process.returncode == 0, (args, process.returncode, stdout, stderr)
    return observed


def private(observed):
    return all(value & 0o077 == 0 for value in observed.values())


def check():
    remote = 's3://' + c.BUCKET
    with tempfile.TemporaryDirectory(prefix='syq-s3-directories-') as temp:
        root = Path(temp).resolve()
        os.environ['XDG_CACHE_HOME'] = str(root / 'cache')
        source = root / 'source'
        (source / 'private/deep').mkdir(parents=True)
        (source / 'shared').mkdir()
        (source / 'private/deep/file').write_bytes(b'secret')
        (source / 'shared/file').write_bytes(b'shared')
        for path, value in [('private/deep', 0o700), ('private', 0o700), ('shared', 0o750), ('', 0o755)]:
            (source / path).chmod(value)
        prefix = c.PREFIX + '/directories'
        c.run([source, '--to', remote, '--into', prefix, '--copy-metadata=permissions'])
        directories = ['source', 'source/private', 'source/private/deep', 'source/shared']
        expected = {path: mode(source / path.removeprefix('source').lstrip('/')) for path in directories}

        # Every marker directory waits for its metadata while private, with or
        # without -p; its marker's mode, limited by the umask without -p, follows.
        for preserve in [True, False]:
            destination = root / f'download-{preserve}'
            args = ['--from', remote, prefix + '/source', '--into', destination]
            if preserve:
                args.append('--copy-metadata=permissions')
            during = held(args, root, lambda: {path: mode(destination / path) for path in directories})
            assert (destination / 'source/private/deep/file').read_bytes() == b'secret'
            after = {path: mode(destination / path) for path in directories}
            assert after == {path: value & ~UMASK for path, value in expected.items()}, after
            assert private(during), {path: oct(value) for path, value in during.items()}

        # A directory a file's download creates before its own marker's job runs
        # still receives the marker's mode. One object at a time, in mapping order.
        mapping = root / 'mapping.jsonl'
        mapping.write_text(''.join(json.dumps(entry) + '\n' for entry in [
            {'src': {'encoding': 'utf-8', 'value': prefix + '/source/private/deep/file'},
             'dst': {'encoding': 'utf-8', 'value': 'mapped/private/file'}},
            {'src': {'encoding': 'utf-8', 'value': prefix + '/source/private'},
             'dst': {'encoding': 'utf-8', 'value': 'mapped/private'}, 'kind': 'dir'},
        ]))
        destination = root / 'mapped'
        during = held(['--from', remote, '--mapping', mapping, '--into', destination,
                       '--resource-limits=s3-objects=1'], root,
                      lambda: {'private': mode(destination / 'mapped/private')})
        assert (destination / 'mapped/private/file').read_bytes() == b'secret'
        assert mode(destination / 'mapped/private') == 0o700, oct(mode(destination / 'mapped/private'))
        # A parent without a marker keeps its creation mode, as before.
        assert mode(destination / 'mapped') == 0o777 & ~UMASK
        assert private(during), during
        print('S3 download directory privacy checks passed', flush=True)


if __name__ == '__main__':
    try:
        check()
    finally:
        c.clean()
