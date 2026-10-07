#!/usr/bin/env python3
"""Downloaded directories stay private until their marker metadata is applied.

Each download is held at copy finalization (a debug build's test barrier),
after every object is written and before any directory metadata is applied.
"""
import json
import os
from pathlib import Path
import struct
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
    # Every download here, held or not, runs with this umask.
    os.umask(UMASK)
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

        # Without -p, a marker directory ends as creating it there would have
        # left it, as in a local copy: it keeps the setgid bit it inherited,
        # and an inherited default ACL limits its mode instead of the umask,
        # as it limits the files' modes.
        setgid = root / 'setgid'
        setgid.mkdir()
        setgid.chmod(0o2755)
        c.run(['--from', remote, prefix + '/source', '--into', setgid / 'download'])
        after = {path: mode(setgid / 'download' / path) for path in directories}
        assert after == {path: value & ~UMASK | 0o2000 for path, value in expected.items()}, after
        acl = root / 'acl'
        acl.mkdir()
        try:
            # Owner rwx, owning group r-x, others nothing.
            os.setxattr(acl, 'system.posix_acl_default', struct.pack(
                '<I' + 'HHI' * 3, 2, 0x01, 7, 0xffffffff, 0x04, 5, 0xffffffff, 0x20, 0, 0xffffffff))
        except (AttributeError, OSError) as error:
            print(f'Skipping the default ACL download check: {error}', flush=True)
        else:
            c.run(['--from', remote, prefix + '/source', '--into', acl / 'download'])
            after = {path: mode(acl / 'download' / path) for path in directories}
            assert after == {path: value & 0o750 for path, value in expected.items()}, after
            # New files follow the same default ACL: 644 objects give 640.
            files = ['source/private/deep/file', 'source/shared/file']
            assert all(mode(source / path.removeprefix('source/')) == 0o644 for path in files)
            after = {path: mode(acl / 'download' / path) for path in files}
            assert after == {path: 0o640 for path in files}, after

        # Without -p, a read-only marker's directory gets owner access, as a
        # native copy gives every new directory, so a later download can still
        # update what it holds. With -p it gets the marker's mode.
        readonly = root / 'readonly-source'
        (readonly / 'locked').mkdir(parents=True)
        (readonly / 'locked/file').write_bytes(b'first')
        (readonly / 'locked').chmod(0o555)
        upload = [readonly, '--to', remote, '--into', prefix, '--copy-metadata=permissions']
        c.run(upload)
        download = {preserve: ['--from', remote, prefix + '/readonly-source', '--into',
                               root / f'readonly-{preserve}'] for preserve in (False, True)}
        download[True].append('--copy-metadata=permissions')
        for preserve, expected_mode in [(False, 0o755), (True, 0o555)]:
            c.run(download[preserve])
            locked = root / f'readonly-{preserve}/readonly-source/locked'
            assert mode(locked) == expected_mode, (preserve, oct(mode(locked)))
            assert (locked / 'file').read_bytes() == b'first'
        (readonly / 'locked').chmod(0o755)
        (readonly / 'locked/file').write_bytes(b'second')
        (readonly / 'locked').chmod(0o555)
        c.run(upload)
        c.run(download[False])
        assert (root / 'readonly-False/readonly-source/locked/file').read_bytes() == b'second'
        for path in (readonly, root / 'readonly-True/readonly-source'):
            (path / 'locked').chmod(0o755)

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

        # A marker the copy skips leaves its directory, created by a child,
        # with its default mode, even beneath a parent that ends unreadable.
        mapping.write_text(''.join(json.dumps(entry) + '\n' for entry in [
            {'src': {'encoding': 'utf-8', 'value': prefix + '/source'},
             'dst': {'encoding': 'utf-8', 'value': 'parent'}, 'kind': 'dir',
             'metadata': {'mode': 0o400}},
            {'src': {'encoding': 'utf-8', 'value': prefix + '/source/private'},
             'dst': {'encoding': 'utf-8', 'value': 'parent/skipped'}, 'kind': 'dir'},
            {'src': {'encoding': 'utf-8', 'value': prefix + '/source/private/deep/file'},
             'dst': {'encoding': 'utf-8', 'value': 'parent/skipped/file'}},
        ]))
        destination = root / 'skipped'
        c.run(['--from', remote, '--mapping', mapping, '--into', destination,
               '--copy-if', "src.name != 'private' or dst.exists",
               '--resource-limits=s3-objects=1'])
        assert mode(destination / 'parent') == 0o400
        (destination / 'parent').chmod(0o700)
        assert mode(destination / 'parent/skipped') == 0o777 & ~UMASK
        assert (destination / 'parent/skipped/file').read_bytes() == b'secret'
        print('S3 download directory privacy checks passed', flush=True)


if __name__ == '__main__':
    try:
        check()
    finally:
        c.clean()
