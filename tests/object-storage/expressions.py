#!/usr/bin/env python3
"""Expression selection and destination conditions in all three S3 directions."""
from pathlib import Path
import tempfile
import json
import check as checks


def check():
    remote = 's3://' + checks.BUCKET
    with tempfile.TemporaryDirectory(prefix='syq-expressions-') as temporary:
        root = Path(temporary).resolve()
        source = root / 'source'
        (source / 'nested').mkdir(parents=True)
        (source / 'nested' / 'keep').write_bytes(b'longer source')
        (source / 'nested' / 'tiny').write_bytes(b'x')
        prefix = checks.PREFIX + '/source'
        checks.run(['--srcs-in', source, '--to', remote, '--into', prefix,
                    '--where', "src.kind = 'file' and src.size > 1B and src.path glob 'nested/*'",
                    '--copy-if', "not dst.exists and dst.path = 'nested/keep'"])
        assert set(checks.listing(prefix + '/')) == {prefix + '/nested/keep'}
        checks.request('PUT', prefix + '/nested/tiny', b'protected')
        checks.request('PUT', prefix + '/extra', b'remove')
        checks.run(['--srcs-in', source, '--to', remote, '--into', prefix, '--prune',
                    '--where', "src.kind = 'file' and src.size > 1B", '--copy-if', 'not dst.exists'])
        assert checks.request('GET', prefix + '/nested/tiny')[1] == b'protected'
        assert prefix + '/extra' not in checks.listing(prefix + '/')
        destination = root / 'download'
        (destination / 'nested').mkdir(parents=True)
        (destination / 'nested/keep').write_bytes(b'x')
        checks.run(['--from', remote, '--srcs-in', prefix, '--into', destination,
                    '--where', "src.path = 'nested/keep' and src.size > 1B",
                    '--copy-if', 'not dst.exists or src.size > dst.size'])
        assert (destination / 'nested/keep').read_bytes() == b'longer source'
        assert not (destination / 'nested/tiny').exists()
        copied = checks.PREFIX + '/copy'
        checks.run(['--from', remote, '--srcs-in', prefix, '--to', remote, '--into', copied,
                    '--where', "src.path = 'nested/keep'", '--copy-if', "not dst.exists and dst.path = 'nested/keep'"])
        assert checks.request('GET', copied + '/nested/keep')[1] == b'longer source'
        assert set(checks.listing(copied + '/')) == {copied + '/nested/keep'}
        renamed = checks.PREFIX + '/renamed'
        checks.run([source, '--to', remote, '--as', renamed,
                    '--where', "src.path = 'nested/keep'",
                    '--copy-if', "dst.path = 'nested/keep'"])
        fresh = root / 'fresh'
        checks.run(['--from', remote, '--srcs-in', renamed, '--into', fresh,
                    '--copy-if', "dst.path = 'nested/keep'"])
        assert (fresh / 'nested/keep').read_bytes() == b'longer source'
        mapping = root / 'mapping.jsonl'
        mapping.write_text(json.dumps({'src': {'encoding': 'utf-8', 'value': 'nested/keep'},
                                       'dst': {'encoding': 'utf-8', 'value': 'mapped'}, 'kind': 'file'}) + '\n')
        predicate = "src.path = 'nested/keep'"
        mapped = checks.PREFIX + '/mapped-upload'
        checks.run(['-C', source, '--mapping', mapping, '--to', remote, '--into', mapped,
                    '--where', predicate, '--copy-if', predicate])
        assert checks.request('GET', mapped + '/mapped')[1] == b'longer source'
        checks.run(['--from', remote, '-C', prefix, '--mapping', mapping, '--into', root / 'mapped-download',
                    '--where', predicate, '--copy-if', predicate])
        assert (root / 'mapped-download/mapped').read_bytes() == b'longer source'
        mapped_copy = checks.PREFIX + '/mapped-copy'
        checks.run(['--from', remote, '-C', prefix, '--mapping', mapping, '--to', remote, '--into', mapped_copy,
                    '--where', predicate, '--copy-if', predicate])
        assert checks.request('GET', mapped_copy + '/mapped')[1] == b'longer source'
        checks.request('PUT', prefix + '/nested/', b'')
        marker_copy = checks.PREFIX + '/markers'
        marker_predicate = "src.kind = 'dir' and src.name = 'nested' and src.path = 'nested'"
        checks.run(['--from', remote, '--srcs-in', prefix, '--to', remote, '--into', marker_copy,
                    '--where', marker_predicate])
        assert set(checks.listing(marker_copy + '/')) == {marker_copy + '/nested/'}
        checks.run(['--from', remote, '--srcs-in', prefix, '--into', root / 'marker-download',
                    '--where', marker_predicate])
        assert (root / 'marker-download/nested').is_dir()
        assert not (root / 'marker-download/nested/keep').exists()
        # Provider objects have no Unix owner metadata; test null deliberately.
        raw = checks.PREFIX + '/raw'
        checks.request('PUT', raw, b'raw object')
        checks.run(['--from', remote, raw, '--as', root / 'raw', '--where', 'src.uid is null'])
        assert (root / 'raw').read_bytes() == b'raw object'
        checks.run(['--from', remote, raw, '--as', root / 'invalid', '--where', 'src.uid > 0'], ok=False)
        assert not (root / 'invalid').exists()
    print('S3 expression upload, download, server copy, pruning, and unavailable metadata passed', flush=True)


if __name__ == '__main__':
    try:
        check()
    finally:
        checks.clean()
