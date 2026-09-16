#!/usr/bin/env python3
"""Pruning checks in a disposable prefix, using independent signed S3 requests."""
import json
import os
from pathlib import Path
import tempfile
import check as c


def check():
    remote = 's3://' + c.BUCKET
    with tempfile.TemporaryDirectory(prefix='syq-s3-prune-') as temp:
        root = Path(temp)
        os.environ['XDG_CACHE_HOME'] = str(root / 'cache')
        source = root / 'source'
        source.mkdir()
        (source / 'keep').write_bytes(b'keep')
        (source / 'small').write_bytes(b'x')
        prefix = c.PREFIX + '/mirror'
        for key in ['extra', 'old/', 'old/child', 'ignored/child', 'small', '.syq-s3-test.partial']:
            c.request('PUT', prefix + '/' + key)
        c.request('PUT', c.PREFIX + '/sibling')
        args = ['--srcs-in', source, '--to', remote, '--into', prefix,
                '--prune', '--ignore', 'ignored/', '--min-size', '2']
        before = set(c.listing())
        c.run(args + ['--dry-run', '-v'])
        assert set(c.listing()) == before
        results = root / 'results.ndjson'
        limited = c.run(args + ['--max-delete', '2', '--results', results], ok=False, capture=True)
        assert limited.returncode == 25, limited.stderr
        records = [json.loads(line) for line in results.read_text().splitlines()]
        assert records[-1]['deletions_planned'] == 3, records[-1]
        assert records[-1]['deletions_blocked'] == 3
        assert before <= set(c.listing())
        c.run(args + ['--max-delete', '3'])
        assert set(c.listing()) == {prefix + '/' + k for k in ['keep', 'small', 'ignored/child', '.syq-s3-test.partial']} | {c.PREFIX + '/sibling'}

        # Named directory scope must leave siblings in the placement container alone.
        named = c.PREFIX + '/named'
        c.request('PUT', named + '/source/extra')
        c.request('PUT', named + '/other/extra')
        c.run([source, '--to', remote, '--into', named, '--prune'])
        assert named + '/source/extra' not in c.listing()
        assert named + '/other/extra' in c.listing()

        # Empty local trees can empty a prefix; a single file never prunes its siblings.
        empty = root / 'empty'
        empty.mkdir()
        c.run(['--srcs-in', empty, '--to', remote, '--into', named + '/source', '--prune'])
        assert c.listing(named + '/source/') == [named + '/source/']
        c.run([source / 'keep', '--to', remote, '--into', named + '/other', '--prune'])
        assert named + '/other/extra' in c.listing()

        dst = root / 'dst'
        dst.mkdir()
        for name in ['extra', 'small', '.syq-s3-test.partial']:
            (dst / name).write_bytes(b'original')
        (dst / 'old').mkdir()
        (dst / 'old/child').write_bytes(b'old')
        (dst / 'ignored').mkdir()
        (dst / 'ignored/child').write_bytes(b'ignored')
        (dst / 'recovery').mkdir()
        (dst / 'recovery/.syq-swap-123-4').mkdir()
        (dst / 'recovery/.syq-swap-123-4/data').write_bytes(b'recover')
        download = ['--from', remote, '--srcs-in', prefix, '--into', dst,
                    '--prune', '--ignore', 'ignored/', '--min-size', '2']
        c.run(download + ['--dry-run'])
        assert (dst / 'extra').exists() and not (dst / 'keep').exists()
        limited = c.run(download + ['--max-delete', '2'], ok=False, capture=True)
        assert limited.returncode == 25, limited.stderr
        assert (dst / 'extra').exists()
        c.run(download + ['--max-delete', '3'])
        assert not (dst / 'extra').exists() and not (dst / 'old').exists()
        assert (dst / 'keep').read_bytes() == b'keep'
        assert (dst / 'small').read_bytes() == b'original'
        assert (dst / 'ignored/child').read_bytes() == b'ignored'
        assert (dst / 'recovery/.syq-swap-123-4/data').read_bytes() == b'recover'

        # A dry run into missing ancestors must not create anything or fail pruning.
        missing = root / 'missing/deep/destination'
        c.run(['--from', remote, '--srcs-in', prefix, '--into', missing, '--prune', '--dry-run'])
        assert not (root / 'missing').exists()
        # Named downloads prune only their mapped directory, including non-UTF-8 extras.
        named_dst = root / 'named-dst'
        (named_dst / 'mirror').mkdir(parents=True)
        (named_dst / 'other').write_bytes(b'outside scope')
        raw_extra = os.fsencode(named_dst / 'mirror') + b'/extra-\xff'
        with open(raw_extra, 'wb') as f:
            f.write(b'extra')
        c.run(['--from', remote, prefix, '--into', named_dst, '--prune'])
        assert not os.path.exists(raw_extra)
        assert (named_dst / 'other').exists()

        # A non-directory destination blocks copying and therefore all pruning.
        (dst / 'keep').unlink()
        (dst / 'keep').mkdir()
        (dst / 'keep/obstacle').write_bytes(b'cannot replace')
        (dst / 'extra').write_bytes(b'must stay')
        c.run(download, ok=False)
        assert (dst / 'extra').exists()
        # --only-new protects the entire skipped destination entry.
        c.run(download + ['--only-new'])
        assert (dst / 'keep/obstacle').exists()
        (dst / 'extra').write_bytes(b'must stay')
        # A missing S3 prefix also must never empty a local tree.
        c.run(['--from', remote, '--srcs-in', c.PREFIX + '/absent', '--into', dst, '--prune'], ok=False)
        assert (dst / 'extra').exists()
        print('S3 prune checks passed', flush=True)


if __name__ == '__main__':
    try:
        check()
    finally:
        c.clean()
