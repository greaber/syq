#!/usr/bin/env python3
"""Verify existing commands across parallel S3 listing branches and pages."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import tempfile

import check as c


def check():
    prefix = c.PREFIX + '/literal*?[x]'
    objects = {f'{prefix}/day{day:02}/file{i:03}': f'{day}:{i}'.encode()
               for day in range(2) for i in range(1200)}
    objects.update({prefix + '/': b'', prefix + '/day00/': b'',
                    prefix + '/empty/': b'', prefix + '/root': b'root',
                    prefix + '/percent%2F': b'percent'})
    outside = prefix + '-other/file'
    remote = 's3://' + c.BUCKET
    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(lambda item: c.request('PUT', item[0], item[1]),
                      [*objects.items(), (outside, b'outside')]))
    with tempfile.TemporaryDirectory(prefix='syq-enumeration-') as temp:
        root = Path(temp).resolve()
        destination = root / 'download'
        c.run(['--from', remote, '--srcs-in', prefix, '--into', destination])
        expected = {key[len(prefix) + 1:]: data for key, data in objects.items()
                    if not key.endswith('/')}
        actual = {str(path.relative_to(destination)): path.read_bytes()
                  for path in destination.rglob('*') if path.is_file()}
        assert actual == expected
        assert (destination / 'empty').is_dir()
        copied = c.PREFIX + '/copied'
        c.run(['--from', remote, '--srcs-in', prefix, '--to', remote, '--into', copied])
        copied_keys = {copied + key[len(prefix):] for key in objects if key != prefix + '/'}
        assert set(c.listing(copied + '/')) == copied_keys
        with ThreadPoolExecutor(max_workers=16) as pool:
            copied_data = dict(pool.map(lambda key: (key[len(copied) + 1:], c.request('GET', key)[1]),
                                        [key for key in copied_keys if not key.endswith('/')]))
        assert copied_data == expected
        # Pruning scans a multi-page destination and must preserve only uploads.
        source = root / 'source'
        source.mkdir()
        (source / 'one').write_bytes(b'one')
        (source / 'two').write_bytes(b'two')
        c.run(['--srcs-in', source, '--to', remote, '--into', copied, '--prune'])
        assert set(c.listing(copied + '/')) == {copied + '/one', copied + '/two'}
        subprocess.run([c.SYQ, 'rm', '--on', remote, '--srcs-in', prefix, '--no-progress'],
                       check=True, timeout=120)
        assert c.listing(prefix + '/') == [prefix + '/']
        assert c.request('GET', outside)[1] == b'outside'
    check_parts()
    print('Parallel S3 enumeration passed: download bytes, server copy, prune, removal, literal selectors, listing in parts', flush=True)


def check_parts():
    """A prefix wide enough that its listing is handed to several listings.

    Objects sit beside the directories, start with their names, and need URL
    encoding, and the last directory is ignored. Only endpoints that document
    key order divide a listing; a test hook of debug builds lets this server
    divide too, and the same checks run without it.
    """
    prefix = c.PREFIX + '/wide'
    objects = {f'{prefix}/shard {shard:03}/f{i:03}': b'x'
               for shard in range(120) for i in range(100)}
    objects.update({f'{prefix}/zz ignored/f{i:04}': b'x' for i in range(1500)})
    # MinIO cannot hold an object and a directory of the same name; the
    # in-memory fixture of the unit tests covers that.
    objects.update({key: b'beside' for key in (
        prefix + '/shard 050.txt', prefix + '/shard 1', prefix + '/shard 119+',
        prefix + '/zz', prefix + '/文')})
    objects.update({prefix + '/shard 010/': b'', prefix + '/zz ignored/': b''})
    remote = 's3://' + c.BUCKET
    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda item: c.request('PUT', item[0], item[1]), objects.items()))
    assert set(c.listing(prefix + '/')) == set(objects), 'independent listing must see the fixture'
    for divide in ('1', None):
        env = {key: value for key, value in os.environ.items()
               if key != 'SYQ_TEST_S3_DIVIDE_LISTINGS'}
        if divide:
            env['SYQ_TEST_S3_DIVIDE_LISTINGS'] = divide
        listed = subprocess.run([c.SYQ, '_ls', f'{remote}/{prefix}/**', '--s3-region', c.REGION],
                                capture_output=True, text=True, timeout=120, env=env)
        assert listed.returncode == 0, listed.stderr
        keys = [json.loads(line)['key'] for line in listed.stdout.splitlines()]
        assert len(keys) == len(objects) and set(keys) == set(objects)
        with tempfile.TemporaryDirectory(prefix='syq-enumeration-') as temp:
            destination = Path(temp).resolve() / 'download'
            c.run(['--from', remote, '--srcs-in', prefix, '--into', destination,
                   '--ignore', 'zz ignored/'], env=env)
            expected = {key[len(prefix) + 1:] for key in objects
                        if not key.endswith('/') and '/zz ignored/' not in key}
            actual = {str(path.relative_to(destination))
                      for path in destination.rglob('*') if path.is_file()}
            assert actual == expected


if __name__ == '__main__':
    try:
        check()
    finally:
        c.clean()
