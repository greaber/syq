#!/usr/bin/env python3
"""S3 removal interoperability in an exclusively owned versioned bucket."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
import check as c



def versions(prefix=''):
    query = {'versions': '', 'prefix': prefix}
    entries = []
    while True:
        _, body = c.request('GET', query=query)
        tree = ET.fromstring(body)
        for node in tree.iter():
            node.tag = node.tag.rsplit('}', 1)[-1]
        for node in tree:
            if node.tag in ('Version', 'DeleteMarker'):
                entries.append((node.findtext('Key'), node.findtext('VersionId'), node.tag == 'DeleteMarker'))
        if tree.findtext('IsTruncated') != 'true':
            return entries
        query['key-marker'] = tree.findtext('NextKeyMarker')
        query['version-id-marker'] = tree.findtext('NextVersionIdMarker')


def run(args, ok=True):
    command = [c.SYQ, 'rm', '--on', 's3://' + c.BUCKET, '--no-progress']
    for name, value in c.HEADERS.items():
        command += ['--s3-header', name + ': ' + value]
    completed = subprocess.run([*command, *map(str, args)], capture_output=True, text=True, timeout=120)
    assert (completed.returncode == 0) == ok, completed.stderr
    return completed


def check():
    with tempfile.TemporaryDirectory(prefix='syq-s3-remove-') as temp:
        root = Path(temp)
        os.environ['XDG_CACHE_HOME'] = str(root / 'cache')
        c.request('PUT', 'file', b'old')
        c.request('PUT', 'file', b'new')
        initial = versions('file')
        assert len(initial) == 2
        run(['file'])
        hidden = versions('file')
        assert len(hidden) == 3 and sum(e[2] for e in hidden) == 1
        assert not c.listing('file')
        results = root / 'preview.ndjson'
        preview = run(['file', '--s3-all-versions', '--dry-run', '-v', '--results', results])
        assert sorted(versions('file')) == sorted(hidden)
        records = [json.loads(line) for line in results.read_text().splitlines()]
        traces = [r for r in records if r['type'] == 'removal_trace']
        assert len(traces) == 3 and {r['s3_version_id'] for r in traces} == {e[1] for e in hidden}
        assert sum(r['s3_delete_marker'] for r in traces) == 1
        assert all(e[1] in preview.stdout for e in hidden)
        # Removing just a delete marker reveals the latest data version.
        marker = next(e[1] for e in hidden if e[2])
        run(['file', '--s3-version-id', marker])
        assert c.request('GET', 'file')[1] == b'new'
        run(['file', '--s3-version-id', initial[0][1]])
        assert len(versions('file')) == 1
        run(['file', '--s3-all-versions'])
        assert not versions('file')
        run(['file', '--s3-all-versions'])  # Missing is successful.

        for key in ['tree/', 'tree/child', 'tree/nested/child', 'tree-other/child']:
            c.request('PUT', key, b'')
        c.request('DELETE', 'tree/child')
        run(['--src-non-dir', 'tree', '--s3-all-versions'], ok=False)
        run(['--srcs-in', 'tree', '--s3-all-versions'])
        assert {e[0] for e in versions()} == {'tree/', 'tree-other/child'}
        run(['--src-dir', 'tree', '--s3-all-versions'])
        assert {e[0] for e in versions()} == {'tree-other/child'}
        # Validate all selectors before deleting any selected key.
        c.request('PUT', 'conflict', b'data')
        run(['tree-other/child', '--src-dir', 'conflict', '--s3-all-versions'], ok=False)
        assert versions('tree-other/child')
        run(['--root', 'tree-other', '--srcs-in', '.', '--s3-all-versions'])
        assert not versions('tree-other/')

        # Overlaps charge each version only once and preserve encoded names.
        c.request('PUT', 'overlap/a + & %.txt', b'one')
        c.request('PUT', 'overlap/a + & %.txt', b'two')
        results = root / 'removed.ndjson'
        run(['overlap', 'overlap/a + & %.txt', '--s3-all-versions', '--results', results])
        records = [json.loads(line) for line in results.read_text().splitlines()]
        assert records[-1]['entries_removed'] == 2
        removals = [r for r in records if r['type'] == 'removal_result']
        assert len(removals) == 2 and all(r['s3_version_id'] and r['s3_delete_marker'] is False for r in removals)
        assert not versions('overlap/')

        # Multiple pages for a single key require both continuation markers.
        with ThreadPoolExecutor(max_workers=16) as workers:
            list(workers.map(lambda _: c.request('PUT', 'many', b'x'), range(1002)))
        c.request('DELETE', 'many')
        assert len(versions('many')) == 1003
        run(['many', '--s3-all-versions'])
        assert not versions('many')
        # The literal null version ID remains usable after versioning is suspended.
        c.request('PUT', query={'versioning': ''}, data=b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Suspended</Status></VersioningConfiguration>')
        c.request('PUT', 'null-version', b'x')
        run(['null-version', '--s3-version-id', 'null'])
        assert not versions('null-version')
        run(['--srcs-in', '.', '--s3-all-versions'])
        assert not versions()
        print('Versioned S3 removal, pagination, dry run, selectors, and results passed', flush=True)


if __name__ == '__main__':
    c.BUCKET = 'syq-remove-' + uuid.uuid4().hex
    c.request('PUT')
    try:
        c.request('PUT', query={'versioning': ''}, data=b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>')
        check()
    finally:
        for key, version, _ in versions():
            c.request('DELETE', key, query={'versionId': version})
        assert not versions()
        c.request('DELETE')
        print('Owned versioned test bucket removed', flush=True)
