#!/usr/bin/env python3
"""Server-side copies in a disposable prefix, independently read back and checked."""
import json
import os
from pathlib import Path
import tempfile
import check as c


def check():
    remote = 's3://' + c.BUCKET
    with tempfile.TemporaryDirectory(prefix='syq-server-copy-') as temp:
        root = Path(temp)
        os.environ['XDG_CACHE_HOME'] = str(root / 'cache')
        source = root / 'source'
        source.mkdir()
        (source / 'small + %.txt').write_bytes(b'small contents')
        (source / 'large').write_bytes(os.urandom(11 * 1024 * 1024))
        (source / 'empty').mkdir()
        (source / 'link').symlink_to('small + %.txt')
        src = c.PREFIX + '/source'
        dst = c.PREFIX + '/copy'
        c.run([source, '--to', remote, '--as', src, '--integrity-checking=transfer=sha256'])
        c.request('PUT', dst + '/extra', b'extra')
        c.request('PUT', dst + '/ignored/keep', b'ignored')
        args = ['--from', remote, '--srcs-in', src, '--to', remote, '--into', dst,
                '--prune', '--ignore', 'ignored/']
        before = set(c.listing())
        c.run(args + ['--dry-run'])
        assert set(c.listing()) == before
        limited = c.run(args + ['--max-delete=0'], ok=False, capture=True)
        assert limited.returncode == 25, limited.stderr
        assert dst + '/extra' in c.listing()
        results = root / 'results.jsonl'
        c.run(args + ['--results', results])
        records = [json.loads(line) for line in results.read_text().splitlines()]
        assert all(e['kind'] == 's3' for e in records[0]['endpoints'])
        assert records[-1]['deletions_completed'] == 1
        assert dst + '/extra' not in c.listing()
        assert dst + '/ignored/keep' in c.listing()
        for name in ['small + %.txt', 'large', 'link', 'empty/']:
            before_headers, before_body = c.request('GET', src + '/' + name)
            after_headers, after_body = c.request('GET', dst + '/' + name)
            assert before_body == after_body, name
            metadata = lambda h: {k.lower(): v for k, v in h.items() if k.lower().startswith('x-amz-meta-')}
            assert metadata(before_headers) == metadata(after_headers), name
        c.run(['--from', remote, dst, '--into', root / 'restored', '--integrity-checking=transfer=sha256'])
        assert (root / 'restored/copy/large').read_bytes() == (source / 'large').read_bytes()
        assert (root / 'restored/copy/link').is_symlink()
        # Explicit hash policies cannot quietly turn into local reads.
        for option in ['--hash', '--verify-only', '--integrity-checking=transfer=sha256',
                       '--expected-hash=sha256:' + '0' * 64]:
            out = c.run(['--from', remote, src + '/large', '--to', remote,
                         '--as', c.PREFIX + '/refused', option], ok=False, capture=True)
            assert 'server-side' in out.stderr, out.stderr
        assert c.PREFIX + '/refused' not in c.listing()
        # Reject overlap before any copy or deletion, including a destination above source.
        for target in [src, src + '/nested', c.PREFIX]:
            before = set(c.listing())
            out = c.run(['--from', remote, '--srcs-in', src, '--to', remote,
                         '--into', target, '--prune'], ok=False, capture=True)
            assert 'overlap' in out.stderr, out.stderr
            assert set(c.listing()) == before
        # Foreign metadata, tags and content headers survive both copy paths.
        for size in [13, 6 * 1024 * 1024]:
            name = c.PREFIX + '/foreign-' + str(size)
            data = b'x' * size
            c.request('PUT', name, data, headers={'Content-Type': 'text/plain',
                      'Cache-Control': 'max-age=17', 'x-amz-meta-owner': 'test',
                      'x-amz-website-redirect-location': '/new-location',
                      'x-amz-tagging': 'purpose=server-copy'})
            c.run(['--from', remote, name, '--to', remote, '--as', name + '-copy'])
            headers, actual = c.request('GET', name + '-copy')
            headers = {k.lower(): v for k, v in headers.items()}
            assert actual == data and headers['content-type'] == 'text/plain'
            assert headers['cache-control'] == 'max-age=17'
            assert headers['x-amz-meta-owner'] == 'test'
            source_headers, _ = c.request('HEAD', name)
            source_headers = {k.lower(): v for k, v in source_headers.items()}
            assert headers.get('x-amz-website-redirect-location') == source_headers.get('x-amz-website-redirect-location')
            _, tags = c.request('GET', name + '-copy', query={'tagging': ''})
            assert b'server-copy' in tags
        assert not c.listing(uploads=True), 'unfinished server copies remain'
        print('S3 server-copy checks passed', flush=True)


if __name__ == '__main__':
    try:
        check()
    finally:
        c.clean()
