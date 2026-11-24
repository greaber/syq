#!/usr/bin/env python3
"""Check syq find and ls against an independently seeded S3 key set."""
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess

import check as checks


def find(*args, ok=True):
    command = [checks.SYQ, *args, '--on', 's3://' + checks.BUCKET,
               '--s3-region', checks.REGION, *checks.header_args()]
    result = subprocess.run(command, capture_output=True, timeout=120)
    assert (result.returncode == 0) == ok, (args, result.stderr)
    return result


def paths(*args):
    """The paths a listing prints, which may hold newlines."""
    output = find(*args, '--null').stdout.decode()
    found = output.split('\0')[:-1]
    assert len(found) == len(set(found)), ('a path printed twice', args)
    return set(found)


def expected(keys, root):
    """What find prints beneath `root`: every object, and every directory
    its keys imply or a directory marker names, without a trailing slash."""
    base = root + '/'
    found = set()
    for key in keys:
        if not key.startswith(base) or key == base:
            continue
        parts = key[len(base):].split('/')
        found.update(base + '/'.join(parts[:i]) for i in range(1, len(parts)))
        if not key.endswith('/'):
            found.add(key)
    return found


def depth(path, root):
    return path[len(root) + 1:].count('/') + 1


def check():
    prefix = checks.PREFIX + '/listing'
    keys = {f'{prefix}/day{day:02}/type{kind}/file{i:03}'
            for day in range(8) for kind in range(2) for i in range(100)}
    keys.update({prefix + '/', prefix + '/file', prefix + '/day00/',
                 prefix + '/day00/nested/file', prefix + '/line\nbreak%2F',
                 prefix + '/a b', prefix + '/a+b', prefix + '/a%2Bb',
                 prefix + '/sp dir/x', prefix + '/sp+dir/x', prefix + '/sp%2Bdir/x',
                 prefix + '/[literal]{braces}', prefix + '/文', prefix + '/empty/',
                 prefix + '-other/file'})
    with ThreadPoolExecutor(max_workers=16) as workers:
        list(workers.map(lambda key: checks.request('PUT', key, b'' if key.endswith('/') else b'x'), keys))
    # MinIO cannot reliably expose an object and descendants with the same
    # name. That collision is covered by the in-memory S3 fixture instead.
    assert set(checks.listing(prefix)) == keys, 'independent listing must see the complete fixture'
    everything = expected(keys, prefix)
    assert prefix + '/empty' in everything and prefix + '/day00' in everything
    for requests in ['1', '4']:
        tuning = ['--performance-tuning', 's3-requests=' + requests]
        assert paths('find', prefix, *tuning) == everything, requests
        for limit in [1, 2, 3]:
            listed = paths('find', prefix, '--depth', str(limit), *tuning)
            assert listed == {path for path in everything if depth(path, prefix) <= limit}, (requests, limit)
        assert paths('ls', prefix + '/', *tuning) == {path for path in everything if depth(path, prefix) == 1}
        # A glob joined with `and` narrows the requests; under `or` it
        # cannot. Both print the same.
        for glob in [prefix + '/day*/type0/*', prefix + '/**/file', prefix + '/day0[0-3]/**',
                     prefix + '/{day01,sp dir}/**', prefix + '/sp*/**', prefix + '/day*',
                     prefix + r'/\[literal\]\{braces\}', prefix + '/?', prefix + '/missing/**',
                     checks.PREFIX + '/*/a b', '*']:
            # The expression's string literal escapes the glob's backslashes.
            quoted = "'" + glob.replace('\\', '\\\\') + "'"
            narrowed = paths('find', prefix, '--where', 'path glob ' + quoted, *tuning)
            whole = paths('find', prefix, '--where', 'path glob ' + quoted + ' or false', *tuning)
            assert narrowed == whole, (glob, narrowed ^ whole)
            for limit in ['1', '2']:
                narrowed = paths('find', prefix, '--depth', limit, '--where', 'path glob ' + quoted, *tuning)
                whole = paths('find', prefix, '--depth', limit, '--where', 'path glob ' + quoted + ' or false', *tuning)
                assert narrowed == whole, (glob, limit, narrowed ^ whole)
    assert paths('find', prefix, '--where', "path glob '" + prefix + "/day*/type0/*'") == \
        {key for key in keys if '/type0/' in key}
    assert paths('find', prefix + '/file') == {prefix + '/file'}
    assert paths('find', prefix, '--where', "path glob '" + prefix + "/\\\\[literal\\\\]*'") == \
        {prefix + '/[literal]{braces}'}
    assert paths('ls', '-C', prefix, 'sp dir', 'a b') == {'sp dir/x', 'a b'}
    assert paths('find', prefix, '--where', "path = '" + prefix + "/a+b'") == {prefix + '/a+b'}
    find('find', prefix + '/missing', ok=False)
    records = [json.loads(line) for line in find('ls', prefix, '--json').stdout.splitlines()]
    by_path = {record['path']: record for record in records}
    assert by_path[prefix + '/day00'] == {'path': prefix + '/day00', 'kind': 'dir'}
    assert by_path[prefix + '/a b']['kind'] == 'file' and by_path[prefix + '/a b']['size'] == 1
    assert isinstance(by_path[prefix + '/a b']['s3_last_modified'], int)
    print('S3 find and ls passed: depths, globs, pagination, directories, and encoded keys', flush=True)


if __name__ == '__main__':
    try:
        check()
    finally:
        checks.clean()
