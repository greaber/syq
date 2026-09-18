#!/usr/bin/env python3
"""Exercise filtered, paginated S3 downloads against the configured test service."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import tempfile

import check as checks


def check():
    prefix = checks.PREFIX + '/selection'
    remote = 's3://' + checks.BUCKET
    objects = {f'{prefix}/archive/{i:04}.tmp': b'ignored' for i in range(1001)}
    objects.update({
        f'{prefix}/root-file': b'root',
        f'{checks.PREFIX}/zz-outside': b'outside',
        f'{prefix}/archive/': b'',
        f'{prefix}/keep/': b'',
        f'{prefix}/keep/file': b'kept',
        f'{prefix}/keep/sub/file': b'nested',
        f'{prefix}/keep/empty/': b'',
    })
    with ThreadPoolExecutor(max_workers=16) as workers:
        list(workers.map(lambda item: checks.request('PUT', item[0], item[1]), objects.items()))
    with tempfile.TemporaryDirectory(prefix='syq-s3-selection-') as temp:
        root = Path(temp).resolve()
        for name, rules, archive, selected, excluded in [
            ('pruned', ['--ignore', 'archive/'], False, prefix, 1),
            ('flat', ['--ignore', 'archive/'], False, prefix, 1),
            ('nested', ['--ignore', 'archive/'], False, checks.PREFIX, 1),
            ('reincluded', ['--ignore', '**/archive/*', '--ignore', '!**/archive/0000.tmp'], True, prefix, 1000),
            ('last-rule', ['--ignore', '!**/archive/0000.tmp', '--ignore', 'archive/'], False, prefix, 1),
        ]:
            destination = root / name
            if name == 'flat':
                request_key = prefix + '/000-leading'
                checks.request('PUT', request_key, b'leading')
            prune = []
            if name == 'pruned':
                (destination / 'archive').mkdir(parents=True)
                (destination / 'archive/local').write_bytes(b'protected')
                (destination / 'extra').write_bytes(b'remove')
                prune = ['--prune']
            results = root / (name + '.jsonl')
            checks.run(['--from', remote, '--srcs-in', selected, '--into', destination, *rules, *prune, '--results', results])
            terminal = json.loads(results.read_text().splitlines()[-1])
            assert terminal['files_excluded'] == excluded, (name, terminal)
            expected = {'root-file': b'root', 'keep/file': b'kept', 'keep/sub/file': b'nested'}
            if name == 'pruned':
                expected['archive/local'] = b'protected'
            if archive:
                expected['archive/0000.tmp'] = b'ignored'
            if name == 'flat':
                expected['000-leading'] = b'leading'
            selected_tree = destination
            if selected == checks.PREFIX:
                expected = {'selection/' + path: data for path, data in expected.items()}
                expected['zz-outside'] = b'outside'
                selected_tree = destination / 'selection'
            actual = {str(p.relative_to(destination)): p.read_bytes()
                      for p in destination.rglob('*') if p.is_file()}
            assert actual == expected, (name, sorted(actual), sorted(expected))
            assert (selected_tree / 'keep/empty').is_dir()
            if not archive and name != 'pruned':
                assert not (selected_tree / 'archive').exists()
            if name == 'flat':
                checks.request('DELETE', request_key)
        checks.run(['--from', remote, '--srcs-in', prefix, '--into', root / 'excluded',
                    '--ignore', '*'])
        assert not list((root / 'excluded').rglob('*'))
        checks.run(['--from', remote, '--srcs-in', prefix + '/missing',
                    '--into', root / 'missing'], ok=False)
        # A two-file upload would stop discovery after one page without pruning.
        # Pruning must instead enumerate and delete every old destination object.
        source = root / 'upload'
        source.mkdir()
        (source / 'one').write_bytes(b'one')
        (source / 'two').write_bytes(b'two')
        checks.run(['--srcs-in', source, '--to', remote, '--into', prefix, '--prune'])
        assert set(checks.listing(prefix + '/')) == {prefix + '/one', prefix + '/two'}
    print('Paginated S3 selection, directory markers, ordered negations, and empty selection passed', flush=True)


if __name__ == '__main__':
    try:
        check()
    finally:
        checks.clean()
