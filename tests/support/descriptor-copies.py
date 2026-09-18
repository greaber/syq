#!/usr/bin/env python3
"""Raw descriptor semantics against disposable local and helper-backed files."""
import fcntl
import os
from pathlib import Path
import shlex
import select
import stat
import signal
import socket
import subprocess
import sys
import tempfile
import time

SYQ = str(Path(sys.argv[1]).resolve())
DATA = bytes(range(256)) * 80000 + b'last\x00\xff'
ENV = {k: v for k, v in os.environ.items() if not k.startswith('SYQ_')}
CHILDREN = []


def run(args, **kwargs):
    result = subprocess.run([SYQ, 'cp', *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, env=ENV, **kwargs)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    return result.stdout


def fail(args, **kwargs):
    result = subprocess.run([SYQ, 'cp', *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=15, env=ENV, **kwargs)
    assert result.returncode != 0, args
    return result


def wait_for(predicate, description, interval=.05):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise AssertionError('timed out: ' + description)


with tempfile.TemporaryDirectory(prefix='syq-descriptors-') as temporary:
    root = Path(temporary).resolve()
    ENV['HOME'] = str(root)
    remote = root / 'rsh'
    # The real SSH suite separately covers authentication and bootstrap.
    remote.write_text('#!/bin/sh\nshift\nexec /bin/sh -c "$1"\n')
    remote.chmod(0o700)
    try:
        for ssh in (False, True):
            directory = root / ('remote' if ssh else 'local')
            directory.mkdir()
            options = ['--rsh', str(remote), '--syq-path', SYQ] if ssh else []
            source = ['--from', 'test-host'] if ssh else []
            destination = ['--to', 'test-host'] if ssh else []
            target = directory / "nested/file 'with spaces'"
            for data in (b'', DATA):
                run([*options, '--src-fd', '0', *destination, '--as', str(target)], input=data)
                assert target.read_bytes() == data
                assert run([*options, *source, str(target), '--as-fd', '1']) == data
            target.chmod(0o640)
            run([*options, '--src-fd', '0', *destination, '--as', str(target)], input=b'replaced')
            assert target.stat().st_mode & 0o777 == 0o640
            link = directory / 'source-link'
            link.symlink_to(target)
            fail([*options, *source, str(link), '--as-fd', '1'])
            assert run([*options, '--follow-src', *source, str(link), '--as-fd', '1']) == b'replaced'
            # Final destination symlinks are replaced, not followed.
            run([*options, '--src-fd', '0', *destination, '--as', str(link)], input=b'link replacement')
            assert not link.is_symlink() and link.read_bytes() == b'link replacement'
            assert target.read_bytes() == b'replaced'
            parent_link = directory / 'parent-link'
            parent_link.symlink_to(target.parent, target_is_directory=True)
            linked_target = parent_link / 'through-link'
            fail([*options, '--src-fd', '0', *destination, '--as', str(linked_target)], input=b'no')
            run([*options, '--follow-dst', '--src-fd', '0', *destination, '--as', str(linked_target)], input=b'yes')
            assert (target.parent / 'through-link').read_bytes() == b'yes'
            # Caller-owned descriptors use current offsets and retain suffixes.
            input_path = directory / 'input'
            output_path = directory / 'output'
            input_path.write_bytes(b'prefix' + DATA)
            output_path.write_bytes(b'prefix' + b'x' * (len(DATA) + 8))
            with input_path.open('rb') as file:
                file.seek(6)
                before = fcntl.fcntl(file, fcntl.F_GETFL)
                run([*options, '--src-fd', str(file.fileno()), *destination, '--as', str(target)], pass_fds=(file.fileno(),))
                assert file.tell() == len(DATA) + 6
                assert fcntl.fcntl(file, fcntl.F_GETFL) == before
            with output_path.open('r+b') as file:
                # Normalize platform write bookkeeping before recording flags.
                file.write(b'prefix')
                file.flush()
                before = fcntl.fcntl(file, fcntl.F_GETFL)
                assert run([*options, *source, str(target), '--as-fd', str(file.fileno())], pass_fds=(file.fileno(),)) == b''
                assert file.tell() == len(DATA) + 6
                assert fcntl.fcntl(file, fcntl.F_GETFL) == before
            assert output_path.read_bytes() == b'prefix' + DATA + b'x' * 8
            # Cancellation while awaiting input keeps the old destination and
            # removes staging, without changing a shared socket's flags.
            for nonblocking in (False, True):
                a, b = socket.socketpair()
                with a, b:
                    a.setblocking(not nonblocking)
                    before = fcntl.fcntl(a, fcntl.F_GETFL)
                    command = [SYQ, 'cp', *options, '--src-fd', str(a.fileno()), *destination, '--as', str(target)]
                    child = subprocess.Popen(command, pass_fds=(a.fileno(),), stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, env=ENV, start_new_session=True)
                    CHILDREN.append(child)
                    wait_for(lambda: list(target.parent.glob('.syq-stream-*')), 'staging file', interval=.0001)
                    assert target.read_bytes() == DATA
                    child.send_signal(signal.SIGTERM)
                    _, error = child.communicate(timeout=10)
                    assert child.returncode != 0, error
                    assert fcntl.fcntl(a, fcntl.F_GETFL) == before
                    assert target.read_bytes() == DATA
                    wait_for(lambda: not list(target.parent.glob('.syq-stream-*')),
                             f'staging cleanup (remote={ssh}, nonblocking={nonblocking})')
            # Broken consumers fail. Remote path sources remain regular files.
            child = subprocess.Popen([SYQ, 'cp', *options, *source, str(target), '--as-fd', '1'],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, start_new_session=True)
            CHILDREN.append(child)
            child.stdout.close()
            child.stdout = None
            _, error = child.communicate(timeout=10)
            assert child.returncode != 0, error
            fifo = directory / 'fifo'
            os.mkfifo(fifo)
            if ssh:
                fail([*options, *source, str(fifo), '--as-fd', '1'])
            # Explicit local FIFOs work with positional and named selectors,
            # retaining their basename for --into placement.
            for selector in ([], ['--src'], ['--src-non-dir']):
                writer = subprocess.Popen([sys.executable, '-c',
                    'import sys; open(sys.argv[1], "wb").write(b"pipe contents")', str(fifo)],
                    start_new_session=True)
                CHILDREN.append(writer)
                run([*options, *selector, str(fifo), *destination, '--into', str(directory / 'into')])
                assert writer.wait(timeout=5) == 0
                assert (directory / 'into' / 'fifo').read_bytes() == b'pipe contents'
            # A shell descriptor path is consumed locally before starting the
            # SSH helper; its generated number never becomes a destination name.
            command = ['bash', '-c',
                'exec "$1" cp --src <(printf "process substitution") "${@:2}"',
                'descriptor-test', SYQ, *options, *destination, '--as', str(target)]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=ENV, timeout=15)
            assert result.returncode == 0, result.stderr
            assert target.read_bytes() == b'process substitution'
            with input_path.open('rb') as file:
                file.seek(6)
                assert run(['--src-non-dir', f'/dev/fd/{file.fileno()}', '--as-fd', '1'],
                           pass_fds=(file.fileno(),)) == DATA
                result = fail(['--src', f'/dev/fd/{file.fileno()}', '--into', str(directory / 'anonymous')],
                              pass_fds=(file.fileno(),))
                assert b'anonymous input requires --as' in result.stderr
                assert not (directory / 'anonymous').exists()
            # Reject mixed input before copying anything or waiting on the FIFO,
            # and identify the pipe even if a regular file was listed first.
            mixed = directory / 'mixed'
            for inputs in ([str(input_path), str(fifo)],
                           ['--src', str(fifo), '--src', str(input_path)]):
                result = fail([*inputs, '--into', str(mixed)])
                assert result.returncode == 2, result.stderr
                assert os.fsencode(fifo) in result.stderr, result.stderr
                assert b'must be the only source' in result.stderr, result.stderr
                assert not mixed.exists()

            # A reader waiting for the first FIFO writer can be cancelled.
            child = subprocess.Popen([SYQ, 'cp', '--src', str(fifo), *destination,
                                     *options, '--as', str(target)], stderr=subprocess.PIPE,
                                     env=ENV, start_new_session=True)
            CHILDREN.append(child)
            time.sleep(.2)
            child.send_signal(signal.SIGTERM)
            child.communicate(timeout=10)
            assert child.returncode != 0
            assert target.read_bytes() == b'process substitution'
            # Explicit node preservation and recursive scans don't consume FIFOs.
            node = directory / 'node'
            run(['--src-non-dir', str(fifo), '--as', str(node), '--preserve=specials'])
            assert stat.S_ISFIFO(node.stat().st_mode)
            tree = directory / 'tree'
            tree.mkdir()
            os.mkfifo(tree / 'nested-pipe')
            run([str(tree), '--as', str(directory / 'tree-copy')])
            assert not (directory / 'tree-copy' / 'nested-pipe').exists()
            assert not list(target.parent.glob('.syq-stream-*'))
            print('descriptor file copies passed:', 'SSH helper' if ssh else 'local', flush=True)
        # Environment options have the same validation as explicit options.
        # Reject unsupported settings before opening input or mutating output.
        inherited_target = root / 'inherited-options'
        inherited_target.write_bytes(b'old')
        for options, diagnostic in (('--dry-run', b'--dry-run'),
                                    ('--performance-tuning batch-files=1', b'batch-files')):
            result = subprocess.run(
                [SYQ, 'cp', '--src-fd', '0', '--as', str(inherited_target)],
                input=b'new', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=15, env={**ENV, 'SYQ_CP_OPTIONS': options})
            assert result.returncode == 2, result.stderr
            assert diagnostic in result.stderr, result.stderr
            explicit = fail([*shlex.split(options), '--src-fd', '0',
                             '--as', str(inherited_target)], input=b'new')
            assert explicit.returncode == result.returncode
            assert explicit.stderr == result.stderr, (explicit.stderr, result.stderr)
            assert inherited_target.read_bytes() == b'old'
        result = subprocess.run(
            [SYQ, 'cp', '--src-fd', '0', '--as', str(inherited_target)],
            input=b'new', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, env={**ENV, 'SYQ_CP_OPTIONS': '--quiet --no-compress'})
        assert result.returncode == 0, result.stderr
        assert inherited_target.read_bytes() == b'new'
        # A producer can wait for a downstream response without filling a
        # transfer block or closing its output first.
        child = subprocess.Popen([SYQ, 'cp', '--src-fd', '0', '--as-fd', '1'],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=ENV, start_new_session=True)
        CHILDREN.append(child)
        for payload in (b'hello', b'again'):
            child.stdin.write(payload)
            child.stdin.flush()
            assert select.select([child.stdout], [], [], 5)[0], 'small payload waited for EOF'
            assert child.stdout.read(len(payload)) == payload
        child.stdin.close()
        child.stdin = None
        output, error = child.communicate(timeout=10)
        assert child.returncode == 0 and output == b'', error
        assert run(['--src-fd', '0', '--as-fd', '1'], input=DATA) == DATA
        created = root / 'umask-output'
        run(['--src-fd', '0', '--as', str(created)], input=b'new', umask=0o027)
        assert created.stat().st_mode & 0o777 == 0o640
        for option in ('--prune', '--dry-run', '--hash', '--verify-only', '--detach'):
            result = fail(['--src-fd', '0', '--as', str(root / 'forbidden'), option], input=b'')
            assert not (root / 'forbidden').exists(), option
        for args in (['--src-fd', '0'], ['--as-fd', '1'], ['--src-fd', '2', '--as', 'bad'],
                     ['--src-fd', '0', '--as-fd', '0'], ['--src-fd', '0', 'file', '--as', 'bad'],
                     ['file', 'other', '--as-fd', '1'], ['--src-fd', '0', '--to', '@named', '--as', 'bad']):
            fail(args, input=b'')
    finally:
        for child in CHILDREN:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
print('descriptor copy checks passed', flush=True)
