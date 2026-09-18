#!/usr/bin/env python3
"""Server-side copies in a disposable prefix, independently read back and checked."""
import json
import os
from pathlib import Path
import tempfile
import subprocess
import urllib.error
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
        # Metadata-only changes must propagate even with matching body ETags.
        name = c.PREFIX + '/metadata-change'
        args = ['--from', remote, name, '--to', remote, '--as', name + '-copy']
        c.request('PUT', name, b'same body', headers={'x-amz-meta-owner': 'before'})
        c.run(args)
        c.request('PUT', name, b'same body', headers={'x-amz-meta-owner': 'after'})
        c.run(args)
        headers, _ = c.request('HEAD', name + '-copy')
        assert {k.lower(): v for k, v in headers.items()}['x-amz-meta-owner'] == 'after'
        # An existing destination prefix does not prohibit its exact object key.
        target = c.PREFIX + '/coexisting'
        c.request('PUT', target + '/child', b'keep')
        refused = c.run(['--from', remote, name, '--to', remote,
                         '--as-existing', target], ok=False, capture=True)
        assert 'prefix, not an object' in refused.stderr, refused.stderr
        c.run(['--from', remote, name, '--to', remote, '--as', target])
        c.run(['--from', remote, name, '--to', remote, '--as-existing', target])
        assert c.request('GET', target)[1] == b'same body'
        assert c.request('GET', target + '/child')[1] == b'keep'
        # Remove these exact keys before listing-based teardown: this MinIO
        # fixture can hide a child in LIST while its parent key exists.
        c.request('DELETE', target)
        c.request('DELETE', target + '/child')
        # An empty prefix requires a marker to satisfy into-existing.
        empty = c.PREFIX + '/existing-empty'
        c.run(['--from', remote, name, '--to', remote, '--into-existing', empty],
              ok=False, capture=True)
        c.request('PUT', empty + '/', b'')
        c.run(['--from', remote, name, '--to', remote, '--into-existing', empty])
        # A source prefix without a directory marker is still a directory.
        foreign_prefix = c.PREFIX + '/foreign-prefix'
        c.request('PUT', foreign_prefix + '/a', b'a')
        c.request('PUT', foreign_prefix + '/b', b'b')
        c.run(['--from', remote, foreign_prefix, '--to', remote,
               '--as-existing', empty, '--dry-run'])
        # Prefix existence cannot be supplied by a bare object of the same name.
        bare = c.PREFIX + '/bare-object'
        c.request('PUT', bare, b'not a prefix')
        c.run(['--from', remote, name, '--to', remote, '--into-existing', bare],
              ok=False, capture=True)
        # Ordinary uploads follow the same existence rules.
        for local_source, placement in [(source / 'small + %.txt', '--into-existing'),
                                        (source, '--as-existing')]:
            refused = c.run([local_source, '--to', remote, placement, bare],
                            ok=False, capture=True)
            assert 'existence condition failed' in refused.stderr, refused.stderr
            assert c.request('GET', bare)[1] == b'not a prefix'
        refused = c.run([source / 'link', '--to', remote, '--as-existing', empty],
                        ok=False, capture=True)
        assert 'prefix, not an object' in refused.stderr, refused.stderr
        c.run([source / 'link', '--to', remote, '--as-existing', bare])
        assert c.request('GET', bare)[1] == b'small + %.txt'
        mirror = c.PREFIX + '/prune-file-descendants'
        stale = mirror + '/a/stale'
        c.request('PUT', stale, b'extra')
        c.run(['--from', remote, '--srcs-in', foreign_prefix, '--to', remote,
               '--into', mirror, '--prune'])
        assert c.request('GET', mirror + '/a')[1] == b'a'
        try:
            c.request('HEAD', stale)
        except urllib.error.HTTPError as error:
            assert error.code == 404, error
        else:
            raise AssertionError('foreign descendant survived prune')
        # Filtering every source must not turn --as-existing into a directory check.
        c.run(['--from', remote, name, '--to', remote, '--as-existing', name + '-copy',
               '--max-size=0'])
        local_file = root / 'filtered-file'
        local_file.write_bytes(b'filtered')
        c.run([local_file, '--to', remote, '--as-existing', name + '-copy', '--max-size=0'])
        assert c.request('GET', name + '-copy')[1] == b'same body'
        # Exact target keys may prefix another source key without overwriting it.
        mapped = c.PREFIX + '/exact-map'
        c.request('PUT', mapped + '/source', b'first')
        c.request('PUT', mapped + '/parent/child', b'second')
        manifest = root / 'exact-map.jsonl'
        entries = [{'src': {'encoding': 'utf-8', 'value': mapped + '/' + src},
                    'dst': {'encoding': 'utf-8', 'value': dst}, 'kind': 'file'}
                   for src, dst in [('source', 'parent'), ('parent/child', 'out')]]
        manifest.write_text(''.join(json.dumps(entry) + '\n' for entry in entries))
        c.run(['--from', remote, '--mapping', manifest, '--to', remote, '--into', mapped])
        assert c.request('GET', mapped + '/parent')[1] == b'first'
        assert c.request('GET', mapped + '/out')[1] == b'second'
        assert c.request('GET', mapped + '/parent/child')[1] == b'second'
        c.request('DELETE', mapped + '/parent')
        c.request('DELETE', mapped + '/parent/child')
        # Default sizing must not turn a modest foreign object into multipart data
        # whose ETag differs on every subsequent copy.
        automatic = c.PREFIX + '/automatic'
        c.request('PUT', automatic, b'x' * (32 * 1024 * 1024))
        results = root / 'automatic-results.jsonl'
        command = [str(c.SYQ), 'cp', '--no-progress', '--from', remote, automatic,
                   '--to', remote, '--as', automatic + '-copy', '--results', str(results)]
        for copied in [1, 0]:
            subprocess.run(command, check=True, timeout=180)
            terminal = json.loads(results.read_text().splitlines()[-1])
            assert terminal['files_transferred'] == copied, terminal
            results.unlink()
        assert not c.listing(uploads=True), 'unfinished server copies remain'
        print('S3 server-copy checks passed', flush=True)


if __name__ == '__main__':
    try:
        check()
    finally:
        c.clean()
