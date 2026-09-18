#!/usr/bin/env python3
"""Placement and source confinement against disposable local/SSH helper files."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SYQ = str(Path(sys.argv[1]).resolve())
ENV = {k: v for k, v in os.environ.items() if not k.startswith('SYQ_')}


def cp(args, *, data=None, success=True):
    result = subprocess.run([SYQ, 'cp', *args], input=data, capture_output=True,
                            timeout=15, env=ENV)
    assert (result.returncode == 0) == success, (args, result.stderr)
    return result


with tempfile.TemporaryDirectory(prefix='syq-stream-placement-') as temporary:
    root = Path(temporary).resolve()
    ENV['HOME'] = str(root)
    rsh = root / 'rsh'
    rsh.write_text('#!/bin/sh\nshift\nexec /bin/sh -c "$1"\n')
    rsh.chmod(0o700)
    for ssh in (False, True):
        directory = root / ('ssh' if ssh else 'local')
        directory.mkdir()
        options = ['--rsh', str(rsh), '--syq-path', SYQ] if ssh else []
        to = ['--to', 'fixture'] if ssh else []
        from_ = ['--from', 'fixture'] if ssh else []
        target = directory / 'target'
        for flag in ('--as-new', '--as-existing'):
            if flag == '--as-existing':
                cp([*options, '--src-fd', '0', *to, flag, str(directory / 'missing/file')],
                   data=b'no', success=False)
                assert not (directory / 'missing').exists()
            cp([*options, '--src-fd', '0', *to, flag, str(target)], data=flag.encode())
        cp([*options, '--src-fd', '0', *to, '--as-new', str(target)], data=b'no', success=False)
        assert target.read_bytes() == b'--as-existing'
        link = directory / 'link'
        link.symlink_to(target)
        cp([*options, '--src-fd', '0', *to, '--as-existing', str(link)], data=b'link')
        assert not link.is_symlink() and link.read_bytes() == b'link'
        assert target.read_bytes() == b'--as-existing'
        link.unlink()
        link.symlink_to(directory / 'absent')
        cp([*options, '--src-fd', '0', *to, '--as-new', str(link)], data=b'no', success=False)
        assert link.is_symlink()
        for flag in ('--as', '--as-new', '--as-existing'):
            cp([*options, '--src-fd', '0', *to, flag, str(directory)], data=b'no', success=False)

        source = directory / 'source'
        source.mkdir()
        (source / 'data').write_bytes(b'read me')
        (source / 'inside').symlink_to('data')
        (source / 'escape').symlink_to('../target')
        for base in ('--cwd', '--root'):
            result = cp([*options, *from_, base, str(source), 'data', '--as-fd', '1'])
            assert result.stdout == b'read me'
        cp([*options, *from_, '--root', str(source), '../target', '--as-fd', '1'], success=False)
        cp([*options, *from_, '--root', str(source), str(target), '--as-fd', '1'], success=False)
        cp([*options, *from_, '--root', str(source), '--follow-src', 'escape', '--as-fd', '1'], success=False)
        assert cp([*options, *from_, '--root', str(source), '--follow-src', 'inside', '--as-fd', '1']).stdout == b'read me'
        cp(['--root', str(source), '--src-fd', '0', '--as', str(target)], data=b'no', success=False)
        assert target.read_bytes() == b'--as-existing'

        fifo = source / 'pipe'
        os.mkfifo(fifo)

        def fifo_copy(flag, destination, *, success=True, extra=()):
            writer = subprocess.Popen([sys.executable, '-c',
                                       'import sys; open(sys.argv[1], "wb").write(b"fifo")', str(fifo)])
            try:
                cp([*options, '--root', str(source), '--src-non-dir', 'pipe',
                    *to, *extra, flag, str(destination)], success=success)
                assert writer.wait(timeout=5) == 0
            finally:
                if writer.poll() is None:
                    writer.kill()
                    writer.wait()

        container = directory / 'container'
        fifo_copy('--into-new', container)
        assert (container / 'pipe').read_bytes() == b'fifo'
        fifo_copy('--into-new', container, success=False)
        (container / 'pipe').unlink()
        fifo_copy('--into-existing', container)
        assert (container / 'pipe').read_bytes() == b'fifo'
        fifo_copy('--into-existing', directory / 'missing', success=False)
        assert not (directory / 'missing').exists()
        fifo_copy('--into', target, success=False)
        container_link = directory / 'container-link'
        container_link.symlink_to(container)
        fifo_copy('--into-existing', container_link, success=False)
        fifo_copy('--into-existing', container_link, extra=('--follow-dst',))
        for flag in ('--into', '--into-new', '--into-existing'):
            result = cp(['--src-fd', '0', flag, str(container)], data=b'no', success=False)
            assert b'needs a source name' in result.stderr, result.stderr
        assert not list(directory.rglob('.syq-stream-*'))
        print('stream placement passed:', 'SSH helper' if ssh else 'local', flush=True)
