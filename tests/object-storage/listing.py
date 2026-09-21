#!/usr/bin/env python3
"""Check experimental listing against an independently seeded S3 key set."""
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess

import check as checks


def check():
    prefix = checks.PREFIX + '/listing'
    keys = {f'{prefix}/day{day:02}/type{kind}/file{i:03}'
            for day in range(8) for kind in range(2) for i in range(100)}
    keys.update({prefix + '/', prefix + '/file', prefix + '/day00/',
                 prefix + '/day00/nested/file', prefix + '/line\nbreak%2F',
                 prefix + '/a b', prefix + '/a+b', prefix + '/a%2Bb',
                 prefix + '/sp dir/x', prefix + '/sp+dir/x', prefix + '/sp%2Bdir/x',
                 prefix + '/[literal]{braces}', prefix + '/文', prefix + '-other/file'})
    with ThreadPoolExecutor(max_workers=16) as workers:
        list(workers.map(lambda key: checks.request('PUT', key, b'' if key.endswith('/') else b'x'), keys))
    # MinIO cannot reliably expose an object and descendants with the same
    # name. That collision is covered by the in-memory S3 fixture instead.
    assert set(checks.listing(prefix)) == keys, 'independent listing must see the complete fixture'
    cases = [
        (prefix, set()),
        (prefix + '/file', {prefix + '/file'}),
        (prefix + '/', {prefix + '/'}),
        (prefix + '/**', {key for key in keys if key.startswith(prefix + '/')}),
        (prefix + '*', set()),
        (prefix + '/day*/type0/*', {key for key in keys if '/type0/' in key}),
        (prefix + '/**/file', {prefix + '/day00/nested/file'}),
        (prefix + '/[literal]{braces}', {prefix + '/[literal]{braces}'}),
        (prefix + '/?', {prefix + '/文'}),
        (prefix + '/missing/**', set()),
        (prefix + '/a b', {prefix + '/a b'}),
        (prefix + '/a+b', {prefix + '/a+b'}),
        (prefix + '/a%2Bb', {prefix + '/a%2Bb'}),
        (prefix + '/sp dir/**', {prefix + '/sp dir/x'}),
        (prefix + '/sp*/**', {prefix + '/sp dir/x', prefix + '/sp+dir/x', prefix + '/sp%2Bdir/x'}),
    ]
    for concurrency in [1, 4]:
        for pattern, expected in cases:
            command = [checks.SYQ, '_ls', 's3://' + checks.BUCKET + '/' + pattern,
                       '--concurrency', str(concurrency), '--s3-region', checks.REGION]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            assert result.returncode == 0, result.stderr
            records = [json.loads(line) for line in result.stdout.splitlines()]
            assert len(records) == len(expected), (pattern, len(records), len(expected))
            assert {entry['key'] for entry in records} == expected, pattern
            assert all(entry['bucket'] == checks.BUCKET and entry['size'] == (0 if entry['key'].endswith('/') else 1) for entry in records)
    print('Experimental S3 listing passed: patterns, pagination, metadata, and encoded keys', flush=True)


if __name__ == '__main__':
    try:
        check()
    finally:
        checks.clean()
