#!/usr/bin/env python3
"""Exercise filtered, paginated S3 downloads against the configured test service."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile

import check as checks


def check():
    prefix = checks.PREFIX + '/selection'
    remote = 's3://' + checks.BUCKET
    objects = {f'{prefix}/archive/{i:04}.tmp': b'ignored' for i in range(1001)}
    objects.update({
        f'{prefix}/root-file': b'root',
        f'{prefix}/keep/': b'',
        f'{prefix}/keep/file': b'kept',
        f'{prefix}/keep/sub/file': b'nested',
        f'{prefix}/keep/empty/': b'',
    })
    with ThreadPoolExecutor(max_workers=16) as workers:
        list(workers.map(lambda item: checks.request('PUT', item[0], item[1]), objects.items()))
    with tempfile.TemporaryDirectory(prefix='syq-s3-selection-') as temp:
        root = Path(temp)
        for name, rules, archive in [
            ('pruned', ['--ignore', 'archive/'], False),
            ('reincluded', ['--ignore', 'archive/*', '--ignore', '!archive/0000.tmp'], True),
            ('last-rule', ['--ignore', '!archive/0000.tmp', '--ignore', 'archive/'], False),
        ]:
            destination = root / name
            checks.run(['--from', remote, '--srcs-in', prefix, '--into', destination, *rules])
            expected = {'root-file': b'root', 'keep/file': b'kept', 'keep/sub/file': b'nested'}
            if archive:
                expected['archive/0000.tmp'] = b'ignored'
            actual = {str(p.relative_to(destination)): p.read_bytes()
                      for p in destination.rglob('*') if p.is_file()}
            assert actual == expected, (name, actual)
            assert (destination / 'keep/empty').is_dir()
        checks.run(['--from', remote, '--srcs-in', prefix, '--into', root / 'excluded',
                    '--ignore', '*'])
        assert not list((root / 'excluded').rglob('*'))
        checks.run(['--from', remote, '--srcs-in', prefix + '/missing',
                    '--into', root / 'missing'], ok=False)
    print('Paginated S3 selection, directory markers, ordered negations, and empty selection passed', flush=True)


if __name__ == '__main__':
    try:
        check()
    finally:
        checks.clean()
