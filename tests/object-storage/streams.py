#!/usr/bin/env python3
"""Stream interoperability against the disposable bucket selected by test-s3.sh."""
import os
from pathlib import Path
import subprocess
import time
import tempfile
import check


def stream(args, **kwargs):
    success = kwargs.pop("success", True)
    args = list(args)
    if '--to' in args:
        fd = '0'
        if '--src-fd' in args:
            index = args.index('--src-fd')
            fd = args[index + 1]
            del args[index:index + 2]
        args[:0] = ['--src-fd', fd]
    elif '--as-fd' not in args:
        args += ['--as-fd', '1']
    result = subprocess.run([check.SYQ, 'cp', '--s3-region', check.REGION,
                             '--performance-tuning', 's3-part-size=5M,s3-max-concurrent-parts-per-object=3',
                             *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=60, **kwargs)
    assert (result.returncode == 0) == success, result.stderr.decode(errors='replace')
    return result.stdout


def main():
    bucket = 's3://' + check.BUCKET
    try:
        for name, data in [('empty', b''), ('small', b'raw\x00\xff'),
                           ('multipart', bytes(range(256)) * 50000)]:
            key = check.PREFIX + '/' + name
            stream(['--to', bucket, '--as', key], input=data)
            headers, actual = check.request('GET', key)
            assert actual == data, name
            assert not any(k.lower().startswith('x-amz-meta-syq-') for k in headers)
            actual = stream(['--from', bucket, key])
            assert actual == data, name
            print('Stream round trip:', name, flush=True)
        # Placement constraints retain the raw-object upload contract.
        for name, data in [('empty', b''), ('small', b'new'), ('multipart', b'x' * (6 << 20))]:
            key = check.PREFIX + '/placement-' + name
            stream(['--to', bucket, '--as-existing', key], input=data, success=False)
            stream(['--to', bucket, '--as-new', key], input=data)
            stream(['--to', bucket, '--as-new', key], input=b'no', success=False)
            assert check.request('GET', key)[1] == data
            stream(['--to', bucket, '--as-existing', key], input=b'updated')
            assert stream(['--from', bucket, '--root', check.PREFIX, 'placement-' + name]) == b'updated'
            assert stream(['--from', bucket, '--cwd', check.PREFIX, 'placement-' + name]) == b'updated'
        stream(['--from', bucket, '--root', check.PREFIX, '../outside'], success=False)
        prefix = check.PREFIX + '/prefix'
        check.request('PUT', prefix + '/child', b'child')
        stream(['--to', bucket, '--as-new', prefix], input=b'no', success=False)
        stream(['--to', bucket, '--as-existing', prefix], input=b'no', success=False)
        with tempfile.TemporaryDirectory(prefix='syq-s3-placement-') as temporary:
            fifo = Path(temporary).resolve() / 'pipe'
            os.mkfifo(fifo)
            for flag, target, success in [('--into-new', prefix, False),
                                          ('--into-existing', prefix, True),
                                          ('--into-existing', prefix + '-missing', False),
                                          ('--into-new', prefix + '-new', True)]:
                writer = subprocess.Popen(['python3', '-c',
                    'import sys; open(sys.argv[1], "wb").write(b"fifo")', str(fifo)]) if success else None
                try:
                    result = subprocess.run([check.SYQ, 'cp', '--src', str(fifo),
                        '--s3-region', check.REGION, '--to', bucket, flag, target],
                        capture_output=True, timeout=30)
                    assert (result.returncode == 0) == success, result.stderr
                    if writer is not None:
                        assert writer.wait(timeout=5) == 0
                    if success:
                        assert check.request('GET', target + '/pipe')[1] == b'fifo'
                finally:
                    if writer is not None and writer.poll() is None:
                        writer.kill()
                        writer.wait()
        # A destination created after preparation must survive --as-new.
        key = check.PREFIX + '/publication-race'
        commit_r, commit_w = os.pipe()
        child = subprocess.Popen([check.SYQ, 'cp', '--src-fd', '0',
            '--stream-commit-fd', str(commit_r), '--s3-region', check.REGION,
            '--performance-tuning', 's3-part-size=5M', '--to', bucket, '--as-new', key],
            pass_fds=(commit_r,), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(commit_r)
        try:
            child.stdin.write(b'x' * (6 << 20))
            child.stdin.close()
            child.stdin = None
            deadline = time.monotonic() + 15
            # The pinned MinIO omits this upload from prefix-filtered listings.
            # Match our exact key locally so the race and cleanup checks see it.
            def pending_uploads():
                return [upload for upload in check.listing(prefix='', uploads=True)
                        if upload[0] == key]

            while not pending_uploads():
                assert time.monotonic() < deadline, f'no pending upload for {key}'
                assert child.poll() is None, child.stderr.read()
                print('Waiting for conditional multipart preparation', flush=True)
                time.sleep(.2)
            check.request('PUT', key, b'concurrent')
            os.write(commit_w, b'C')
            os.close(commit_w)
            commit_w = None
            _, error = child.communicate(timeout=30)
            assert child.returncode != 0, error
            assert check.request('GET', key)[1] == b'concurrent'
            assert not pending_uploads(), 'failed conditional upload was not aborted'
        finally:
            if commit_w is not None:
                os.close(commit_w)
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
        print('Stream placement and source prefixes passed', flush=True)
        key = check.PREFIX + '/literal/key *%'
        # Read an ordinary object written independently, including literal key spelling.
        check.request('PUT', key, b'ordinary object')
        assert stream(['--from', bucket, key]) == b'ordinary object'
        with tempfile.TemporaryDirectory(prefix='syq-stream-fds-') as temp:
            data = b'FD input\x00' * 1000000
            source = Path(temp) / 'input'
            source.write_bytes(b'prefix' + data)
            key = check.PREFIX + '/descriptors'
            with source.open('rb') as file:
                file.seek(6)
                stream(['--to', bucket, '--as', key, '--src-fd', str(file.fileno())],
                       pass_fds=(file.fileno(),))
            with (Path(temp) / 'output').open('w+b') as file:
                file.write(b'prefix')
                file.flush()
                assert stream(['--from', bucket, key, '--as-fd', str(file.fileno())],
                              pass_fds=(file.fileno(),)) == b''
                file.seek(0)
                assert file.read() == b'prefix' + data
        assert not check.listing(uploads=True), 'stream left unfinished multipart uploads'
        print('S3 stream interoperability passed', flush=True)
    finally:
        check.clean()


if __name__ == '__main__':
    main()
