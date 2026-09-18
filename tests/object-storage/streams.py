#!/usr/bin/env python3
"""Stream interoperability against the disposable bucket selected by test-s3.sh."""
import os
from pathlib import Path
import subprocess
import tempfile
import check


def stream(args, **kwargs):
    args = list(args)
    if '--to' in args:
        fd = '0'
        if '--read-fd' in args:
            index = args.index('--read-fd')
            fd = args[index + 1]
            del args[index:index + 2]
        args[:0] = ['--read-fd', fd]
    elif '--write-fd' not in args:
        args += ['--write-fd', '1']
    result = subprocess.run([check.SYQ, 'cp', '--s3-region', check.REGION,
                             '--performance-tuning', 's3-part-size=5M,s3-max-concurrent-parts-per-object=3',
                             *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=60, **kwargs)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
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
                stream(['--to', bucket, '--as', key, '--read-fd', str(file.fileno())],
                       pass_fds=(file.fileno(),))
            with (Path(temp) / 'output').open('w+b') as file:
                file.write(b'prefix')
                file.flush()
                assert stream(['--from', bucket, key, '--write-fd', str(file.fileno())],
                              pass_fds=(file.fileno(),)) == b''
                file.seek(0)
                assert file.read() == b'prefix' + data
        assert not check.listing(uploads=True), 'stream left unfinished multipart uploads'
        print('S3 stream interoperability passed', flush=True)
    finally:
        check.clean()


if __name__ == '__main__':
    main()
