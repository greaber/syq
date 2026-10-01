#!/usr/bin/env python3
"""Exercise filtered, paginated S3 downloads against the configured test service."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import subprocess
import tempfile

import check as checks


def check_source_roots():
    remote = 's3://' + checks.BUCKET
    prefix = checks.PREFIX + '/roots'
    source_files = {
        'build/secret': b'excluded',
        'logs/drop': b'excluded',
        'logs/keep/file': b'included',
        'nested/build/file': b'nested',
        'src/file': b'source',
    }
    names = ['project-a', 'project-b']
    protected = {'build/old': b'protected build', 'logs/old': b'protected logs'}
    expected = {f'{name}/{path}': data for name in names
                for path, data in {**{p: d for p, d in source_files.items()
                                      if p not in ('build/secret', 'logs/drop')}, **protected}.items()}
    with tempfile.TemporaryDirectory(prefix='syq-ignore-roots-') as temp:
        root = Path(temp).resolve()
        source = root / 'ignored-parent'
        for name in names:
            for path, data in source_files.items():
                file = source / name / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(data)
        rules = root / 'rules'
        rules.write_text('/build/\nlogs/*\n!logs/keep/\nproject-a/\nignored-parent/\n')
        selectors = ['--src-dirs', *[source / name for name in names]]
        options = ['--ignore-from', rules, '--prune']

        def seed_local(destination):
            for name in names:
                for path, data in {**protected, 'extra': b'delete'}.items():
                    file = destination / name / path
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_bytes(data)

        def check_local(destination):
            actual = {str(p.relative_to(destination)): p.read_bytes()
                      for p in destination.rglob('*') if p.is_file()}
            assert actual == expected, (destination, actual, expected)

        def seed_remote(destination):
            for name in names:
                for path, data in {**protected, 'extra': b'delete'}.items():
                    checks.request('PUT', f'{destination}/{name}/{path}', data)

        def check_remote(destination):
            actual = {key[len(destination) + 1:]: checks.request('GET', key)[1]
                      for key in checks.listing(destination + '/') if not key.endswith('/')}
            assert actual == expected, (destination, actual, expected)

        # The same roots and rule file must select and protect the same paths
        # locally, on upload, on download, and between buckets/prefixes.
        local = root / 'local'
        seed_local(local)
        subprocess.run([checks.SYQ, 'cp', '--no-progress',
                        *map(str, [*selectors, '--into', local, *options])],
                       check=True, timeout=180)
        check_local(local)
        uploaded = prefix + '/uploaded'
        seed_remote(uploaded)
        checks.run([*selectors, '--to', remote, '--into', uploaded, *options])
        check_remote(uploaded)

        original = prefix + '/ignored-parent'
        checks.run([*selectors, '--to', remote, '--into', original])
        remote_sources = ['--from', remote, '-C', original, '--src-dirs', *names]
        downloaded = root / 'downloaded'
        seed_local(downloaded)
        checks.run([*remote_sources, '--into', downloaded, *options])
        check_local(downloaded)
        copied = prefix + '/copied'
        seed_remote(copied)
        checks.run([*remote_sources, '--to', remote, '--into', copied, *options])
        check_remote(copied)

        # An excluded subtree becomes an included root when selected separately.
        overlap = root / 'overlap'
        checks.run(['--from', remote, '-C', original, '--src-dirs',
                    'project-a', 'project-a/build', '--into', overlap, '--ignore', '/build/'])
        assert not (overlap / 'project-a/build').exists()
        assert (overlap / 'build/secret').read_bytes() == b'excluded'
        # Explicit leaves use the source basename on every route, including
        # when the target is renamed and the source has an ignored parent name.
        for case, rules, included in [
            ('all', ['*'], False), ('anchored', ['/secret'], False),
            ('parent', ['build/'], True), ('negated', ['*', '!secret'], True),
            ('destination', ['renamed'], True),
        ]:
            options = ['--if-exists=update']
            for rule in rules:
                options += ['--ignore', rule]
            expected_file = b'excluded' if included else b'old'
            for route in ['local', 'uploaded', 'downloaded', 'copied']:
                destination = root / case / route / 'renamed'
                key = f'{prefix}/files/{case}/{route}/renamed'
                to_s3 = route in ('uploaded', 'copied')
                if to_s3:
                    checks.request('PUT', key, b'old')
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(b'old')
                if route in ('downloaded', 'copied'):
                    args = ['--from', remote, '-C', original, 'project-a/build/secret']
                else:
                    args = [source / 'project-a/build/secret']
                args += ['--to', remote, '--as', key] if to_s3 else ['--as', destination]
                args += options
                if route == 'local':
                    subprocess.run([checks.SYQ, 'cp', '--no-progress', *map(str, args)],
                                   check=True, timeout=180)
                else:
                    checks.run(args)
                actual = checks.request('GET', key)[1] if to_s3 else destination.read_bytes()
                assert actual == expected_file, (case, route, actual, expected_file)
    print('Ignore roots and prune protection agree across local and S3 routes', flush=True)


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
    check_source_roots()
    print('Paginated S3 selection, directory markers, ordered negations, and empty selection passed', flush=True)


if __name__ == '__main__':
    try:
        check()
    finally:
        checks.clean()
