#!/usr/bin/env python3
"""Raw descriptor semantics against disposable local and helper-backed files."""
import fcntl
import os
from pathlib import Path
import shlex
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


def wait_for(predicate, description):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.05)
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
                run([*options, '--read-fd', '0', *destination, '--as', str(target)], input=data)
                assert target.read_bytes() == data
                assert run([*options, *source, str(target), '--write-fd', '1']) == data
            target.chmod(0o640)
            run([*options, '--read-fd', '0', *destination, '--as', str(target)], input=b'replaced')
            assert target.stat().st_mode & 0o777 == 0o640
            link = directory / 'source-link'
            link.symlink_to(target)
            fail([*options, *source, str(link), '--write-fd', '1'])
            assert run([*options, '--follow-src', *source, str(link), '--write-fd', '1']) == b'replaced'
            # Final destination symlinks are replaced, not followed.
            run([*options, '--read-fd', '0', *destination, '--as', str(link)], input=b'link replacement')
            assert not link.is_symlink() and link.read_bytes() == b'link replacement'
            assert target.read_bytes() == b'replaced'
            parent_link = directory / 'parent-link'
            parent_link.symlink_to(target.parent, target_is_directory=True)
            linked_target = parent_link / 'through-link'
            fail([*options, '--read-fd', '0', *destination, '--as', str(linked_target)], input=b'no')
            run([*options, '--follow-dst', '--read-fd', '0', *destination, '--as', str(linked_target)], input=b'yes')
            assert (target.parent / 'through-link').read_bytes() == b'yes'
            # Caller-owned descriptors use current offsets and retain suffixes.
            input_path = directory / 'input'
            output_path = directory / 'output'
            input_path.write_bytes(b'prefix' + DATA)
            output_path.write_bytes(b'prefix' + b'x' * (len(DATA) + 8))
            with input_path.open('rb') as file:
                file.seek(6)
                before = fcntl.fcntl(file, fcntl.F_GETFL)
                run([*options, '--read-fd', str(file.fileno()), *destination, '--as', str(target)], pass_fds=(file.fileno(),))
                assert file.tell() == len(DATA) + 6
                assert fcntl.fcntl(file, fcntl.F_GETFL) == before
            with output_path.open('r+b') as file:
                # Normalize platform write bookkeeping before recording flags.
                file.write(b'prefix')
                file.flush()
                before = fcntl.fcntl(file, fcntl.F_GETFL)
                assert run([*options, *source, str(target), '--write-fd', str(file.fileno())], pass_fds=(file.fileno(),)) == b''
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
                    command = [SYQ, 'cp', *options, '--read-fd', str(a.fileno()), *destination, '--as', str(target)]
                    child = subprocess.Popen(command, pass_fds=(a.fileno(),), stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, env=ENV, start_new_session=True)
                    CHILDREN.append(child)
                    wait_for(lambda: list(target.parent.glob('.syq-stream-*')), 'staging file')
                    assert target.read_bytes() == DATA
                    child.send_signal(signal.SIGTERM)
                    _, error = child.communicate(timeout=10)
                    assert child.returncode != 0, error
                    assert fcntl.fcntl(a, fcntl.F_GETFL) == before
                    assert target.read_bytes() == DATA
                    wait_for(lambda: not list(target.parent.glob('.syq-stream-*')), 'staging cleanup')
            # Broken consumers fail, and named FIFOs must not be opened for I/O.
            child = subprocess.Popen([SYQ, 'cp', *options, *source, str(target), '--write-fd', '1'],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, start_new_session=True)
            CHILDREN.append(child)
            child.stdout.close()
            child.stdout = None
            _, error = child.communicate(timeout=10)
            assert child.returncode != 0, error
            fifo = directory / 'fifo'
            os.mkfifo(fifo)
            fail([*options, *source, str(fifo), '--write-fd', '1'])
            assert not list(target.parent.glob('.syq-stream-*'))
            print('descriptor file copies passed:', 'SSH helper' if ssh else 'local', flush=True)
        assert run(['--read-fd', '0', '--write-fd', '1'], input=DATA) == DATA
        for option in ('--prune', '--dry-run', '--hash', '--verify-only', '--stats', '--detach'):
            result = fail(['--read-fd', '0', '--as', str(root / 'forbidden'), option], input=b'')
            assert not (root / 'forbidden').exists(), option
        for args in (['--read-fd', '0'], ['--write-fd', '1'], ['--read-fd', '2', '--as', 'bad'],
                     ['--read-fd', '0', '--write-fd', '0'], ['--read-fd', '0', 'file', '--as', 'bad'],
                     ['file', 'other', '--write-fd', '1'], ['--read-fd', '0', '--to', '@named', '--as', 'bad']):
            fail(args, input=b'')
    finally:
        for child in CHILDREN:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
print('descriptor copy checks passed', flush=True)
