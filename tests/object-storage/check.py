#!/usr/bin/env python3
"""Opt-in S3 interoperability checks against a disposable unique key prefix.

Uses only Python's standard library. Administrative requests are signed here
independently of syq, so the checks do not validate a writer against itself.
Credentials come from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY; the caller
selects an existing bucket with SYQ_TEST_BUCKET. Never changes bucket policy.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import signal
import selectors
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

ENDPOINT = os.environ['AWS_ENDPOINT_URL_S3'].rstrip('/')
BUCKET = os.environ['SYQ_TEST_BUCKET']
REGION = os.environ.get('AWS_REGION', 'us-east-1')
PREFIX = 'syq-tests/' + uuid.uuid4().hex
SYQ = str(Path(sys.argv[1]).resolve())
HEADERS = json.loads(os.environ.get('SYQ_TEST_HEADERS', '{}'))
OWNED_UPLOADS = set()


def request(method, key='', data=b'', query=None, headers=None):
    path = '/' + urllib.parse.quote(BUCKET, safe='') + '/' + urllib.parse.quote(key, safe='/~')
    query = urllib.parse.urlencode(sorted((query or {}).items()), quote_via=urllib.parse.quote)
    now = datetime.datetime.now(datetime.timezone.utc)
    date = now.strftime('%Y%m%d')
    stamp = now.strftime('%Y%m%dT%H%M%SZ')
    digest = hashlib.sha256(data).hexdigest()
    hdr = {'host': urllib.parse.urlsplit(ENDPOINT).netloc, 'x-amz-date': stamp, 'x-amz-content-sha256': digest}
    hdr.update({k.lower(): v for k, v in HEADERS.items()})
    hdr.update({k.lower(): v for k, v in (headers or {}).items()})
    if os.environ.get('AWS_SESSION_TOKEN'):
        hdr['x-amz-security-token'] = os.environ['AWS_SESSION_TOKEN']
    names = ';'.join(sorted(hdr))
    canonical = '\n'.join([method, path, query, ''.join(k + ':' + ' '.join(hdr[k].split()) + '\n' for k in sorted(hdr)), names, digest])
    scope = date + '/' + REGION + '/s3/aws4_request'
    signed = '\n'.join(['AWS4-HMAC-SHA256', stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    secret = ('AWS4' + os.environ['AWS_SECRET_ACCESS_KEY']).encode()
    for item in [date, REGION, 's3', 'aws4_request']:
        secret = hmac.new(secret, item.encode(), hashlib.sha256).digest()
    signature = hmac.new(secret, signed.encode(), hashlib.sha256).hexdigest()
    hdr['authorization'] = f'AWS4-HMAC-SHA256 Credential={os.environ["AWS_ACCESS_KEY_ID"]}/{scope}, SignedHeaders={names}, Signature={signature}'
    url = ENDPOINT + path + ('?' + query if query else '')
    req = urllib.request.Request(url, method=method, headers=hdr, data=data if method in ('PUT', 'POST') else None)
    with urllib.request.urlopen(req, timeout=60) as response:
        return dict(response.headers.items()), response.read()


def listing(prefix=PREFIX + '/', uploads=False):
    query = {'prefix': prefix, 'uploads': ''} if uploads else {'prefix': prefix, 'list-type': '2'}
    result = []
    while True:
        _, data = request('GET', query=query)
        tree = ET.fromstring(data)
        for node in tree.iter():
            node.tag = node.tag.rsplit('}', 1)[-1]
        for node in tree.findall('Upload' if uploads else 'Contents'):
            result.append((node.findtext('Key'), node.findtext('UploadId')) if uploads else node.findtext('Key'))
        if tree.findtext('IsTruncated') != 'true':
            return result
        if uploads:
            query['key-marker'] = tree.findtext('NextKeyMarker')
            query['upload-id-marker'] = tree.findtext('NextUploadIdMarker')
        else:
            query['continuation-token'] = tree.findtext('NextContinuationToken')


def clean():
    for key, upload in OWNED_UPLOADS:
        assert key.startswith(PREFIX + '/')
        try: request('DELETE', key, query={'uploadId': upload})
        except urllib.error.HTTPError as error:
            if error.code != 404: raise
    for key, upload in listing(uploads=True):
        assert key.startswith(PREFIX + '/')
        request('DELETE', key, query={'uploadId': upload})
    keys = listing()
    print(f'Removing {len(keys)} owned objects', flush=True)
    def remove(key):
        assert key.startswith(PREFIX + '/')
        request('DELETE', key)
    with ThreadPoolExecutor(max_workers=16) as workers:
        for count, _ in enumerate(workers.map(remove, keys), 1):
            if count % 100 == 0: print(f'Removed {count}/{len(keys)} owned objects', flush=True)
    assert not listing(), 'owned test objects remain'
    assert not listing(uploads=True), 'owned multipart uploads remain'


def run(args, *, ok=True, env=None, capture=False):
    command = [SYQ, 'cp', '--no-progress', '-p', '5', '-c', '3', '--s3-retries', '1']
    for name, value in HEADERS.items():
        command += ['--s3-header', name + ': ' + value]
    completed = subprocess.run(command + list(map(str, args)), env=env, text=True, capture_output=capture, timeout=180)
    assert (completed.returncode == 0) == ok, (args, completed.returncode, completed.stderr if capture else '')
    return completed


def interrupted(args, threshold=5*1024*1024):
    command=[SYQ,'cp','--no-progress','--progress-json','-p','5','-c','1','--bwlimit','1MiB','--s3-retries','1']
    for name,value in HEADERS.items(): command+=['--s3-header',name+': '+value]
    process=subprocess.Popen(command+list(map(str,args)),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,start_new_session=True)
    deadline=time.monotonic()+60
    observed=0
    selector=selectors.DefaultSelector();selector.register(process.stderr,selectors.EVENT_READ)
    pending=b''
    try:
        while observed<threshold and time.monotonic()<deadline:
            for _,_ in selector.select(timeout=1):
                block=os.read(process.stderr.fileno(),65536)
                if not block: raise AssertionError('copy exited before interruption point')
                pending+=block
                while b'\n' in pending:
                    line,pending=pending.split(b'\n',1)
                    try: event=json.loads(line)
                    except ValueError: continue
                    observed=max(observed,event.get('bytes_done',0))
            if process.poll() is not None: raise AssertionError('copy exited before interruption point')
        assert observed>=threshold, f'interruption deadline expired; last progress {observed}'
        os.killpg(process.pid,signal.SIGINT)
        process.wait(timeout=15)
        assert process.returncode!=0
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=15)
        process.stderr.close()
        try: os.killpg(process.pid,0)
        except ProcessLookupError: pass
        else: raise AssertionError('copy process group survived interruption')
    return observed


def check():
    with tempfile.TemporaryDirectory(prefix='syq-s3-check-') as temp:
        root = Path(temp)
        os.environ['XDG_CACHE_HOME'] = str(root / 'cache')
        src = root / 'source'
        src.mkdir()
        (src / 'empty').mkdir()
        (src / 'script').write_bytes(b'#!/bin/sh\nprintf hello\n')
        (src / 'script').chmod(0o751)
        (src / 'link').symlink_to('script')
        (src / 'zero').write_bytes(b'')
        (src / 'space + & %.txt').write_bytes(b'encoded key')
        (src / 'large').write_bytes(os.urandom(13 * 1024 * 1024))
        os.utime(src / 'script', ns=(1_600_000_001_123456789, 1_600_000_001_123456789))
        remote = 's3://' + BUCKET
        placement = PREFIX + '/roundtrip'
        run([src, '--to', remote, '--into', placement, '--preserve=permissions'])
        dst = root / 'download'
        run(['--from', remote, placement + '/source', '--into', dst, '--preserve=permissions'])
        restored = dst / 'source'
        for path in src.iterdir():
            actual = restored / path.name
            if path.is_symlink():
                assert actual.is_symlink() and os.readlink(actual) == os.readlink(path)
            elif path.is_dir():
                assert actual.is_dir()
            else:
                assert actual.read_bytes() == path.read_bytes(), path.name
                assert actual.stat().st_mode & 0o7777 == path.stat().st_mode & 0o7777
                assert actual.stat().st_mtime_ns == path.stat().st_mtime_ns
        run(['--from', remote, placement + '/source', '--into', dst, '--verify-only'])
        owned = root / 'owned'
        owned.mkdir()
        run(['--from', remote, placement + '/source', '--as', owned, '--preserve=ownership'])
        assert owned.stat().st_uid == src.stat().st_uid
        assert owned.stat().st_gid == src.stat().st_gid

        # The independent reader sees ordinary object bytes and metadata.
        hdr, body = request('GET', placement + '/source/script')
        assert body == (src / 'script').read_bytes()
        assert {k.lower(): v for k, v in hdr.items()}['x-amz-meta-syq-format'] == '1'
        # Existing outputs remain intact on a dry run and no recovery data is created.
        (restored / 'script').write_bytes(b'local edits')
        run(['--from', remote, placement + '/source/script', '--as', restored / 'script', '--dry-run'])
        assert (restored / 'script').read_bytes() == b'local edits'
        run(['--from', remote, placement + '/source/script', '--as', restored / 'script', '--only-new'])
        assert (restored / 'script').read_bytes() == b'local edits'
        run(['--from', remote, placement + '/source/script', '--as', restored / 'script', '--verify-only'], ok=False)
        run(['--from', remote, placement + '/source/script', '--as-new', restored / 'script'], ok=False)
        run(['--from', remote, placement + '/source/script', '--as', root / 'absent', '--only-existing'])
        assert not (root / 'absent').exists()
        # A foreign writer's object, without syq metadata, is readable and verifiable.
        foreign = PREFIX + '/foreign'
        request('PUT', foreign, b'foreign contents')
        run(['--from', remote, foreign, '--as', root / 'foreign'])
        assert (root / 'foreign').read_bytes() == b'foreign contents'
        run(['--from', remote, foreign, '--as', root / 'foreign', '--hash'])
        # Future metadata versions cannot be silently reinterpreted.
        request('PUT', PREFIX + '/future', b'x', headers={'x-amz-meta-syq-format': '999'})
        run(['--from', remote, PREFIX + '/future', '--as', root / 'future'], ok=False)
        assert not (root / 'future').exists()
        # Destination ancestors are never followed through symlinks.
        outside = root / 'outside'
        outside.mkdir()
        guarded = root / 'guarded'
        guarded.mkdir()
        (guarded / 'source').symlink_to(outside, target_is_directory=True)
        run(['--from', remote, placement + '/source', '--into', guarded], ok=False)
        assert not list(outside.iterdir())
        # Only explicitly selected mappings are copied, including empty directories.
        mapping = root / 'mapping.jsonl'
        script_md5 = hashlib.md5((src / 'script').read_bytes()).hexdigest()
        entries = [{'src': {'encoding': 'utf-8', 'value': 'script'}, 'dst': {'encoding': 'utf-8', 'value': 'renamed'}, 'kind': 'file', 'expected_digest': {'algorithm': 'md5', 'value': script_md5}}]
        mapping.write_text(''.join(json.dumps(e) + '\n' for e in entries))
        run(['-C', src, '--mapping', mapping, '--to', remote, '--into', PREFIX + '/mapping'])
        _, body = request('GET', PREFIX + '/mapping/renamed')
        assert body == (src / 'script').read_bytes()
        run(['--from', remote, PREFIX + '/mapping/renamed', '--as', root / 'expected',
             '--expected-hash', 'md5:' + script_md5, '--transfer-integrity'])
        assert (root / 'expected').read_bytes() == body
        (root / 'expected').write_bytes(b'keep on mismatch')
        run(['--from', remote, PREFIX + '/mapping/renamed', '--as', root / 'expected',
             '--expected-hash', 'md5:' + '0' * 32], ok=False)
        assert (root / 'expected').read_bytes() == b'keep on mismatch'
        # Directory entries in a mapping are explicit, not recursive selectors.
        manifest = root / 'tree-map.jsonl'
        manifest.write_text('\n'.join(json.dumps(entry) for entry in [
            {'src': {'encoding':'utf-8','value':placement+'/source'}, 'dst':{'encoding':'utf-8','value':'renamed'}, 'kind':'dir'},
            {'src': {'encoding':'utf-8','value':placement+'/source/script'}, 'dst':{'encoding':'utf-8','value':'renamed/program'}, 'kind':'file'},
        ]) + '\n')
        mapped_tree = root / 'mapped-tree'
        run(['--from', remote, '--mapping', manifest, '--into', mapped_tree])
        assert sorted(p.name for p in (mapped_tree / 'renamed').iterdir()) == ['program']
        assert (mapped_tree / 'renamed/program').read_bytes() == (src / 'script').read_bytes()

        # Retrying a partial multipart upload/download must reuse completed work.
        upload_key=PREFIX+'/resume-upload'
        interrupted([src/'large','--to',remote,'--as',upload_key])
        records=[json.loads(path.read_text()) for path in (root/'cache/syq/s3').glob('*.json')]
        uploads=[record for record in records if 'upload_id' in record]
        assert len(uploads)==1, 'interrupted upload lost its recovery handle'
        upload_id=uploads[0]['upload_id']
        OWNED_UPLOADS.add((upload_key,upload_id))
        _, parts=request('GET', upload_key, query={'uploadId': upload_id})
        assert b'<Part>' in parts, 'interrupted upload has no completed parts'
        result_file=root/'upload-result.jsonl'
        run([src/'large','--to',remote,'--as',upload_key,'--results',result_file])
        terminal=json.loads(result_file.read_text().splitlines()[-1])
        assert terminal['bytes_transferred'] < (src/'large').stat().st_size, terminal
        _, body=request('GET',upload_key)
        assert body==(src/'large').read_bytes()
        download_path=root/'resume-download'
        interrupted(['--from',remote,upload_key,'--as',download_path])
        assert not download_path.exists(), 'partial download became visible at final name'
        result_file=root/'download-result.jsonl'
        run(['--from',remote,upload_key,'--as',download_path,'--results',result_file])
        terminal=json.loads(result_file.read_text().splitlines()[-1])
        assert terminal['bytes_transferred'] < (src/'large').stat().st_size, terminal
        assert download_path.read_bytes()==(src/'large').read_bytes()
        # Provider lifecycle expiry must not strand a changed-source retry.
        expired_key = PREFIX + '/expired-upload'
        interrupted([src / 'large', '--to', remote, '--as', expired_key])
        records = [json.loads(path.read_text()) for path in (root / 'cache/syq/s3').glob('*.json')]
        expired_id = next(record['upload_id'] for record in records if 'upload_id' in record)
        OWNED_UPLOADS.add((expired_key, expired_id))
        request('DELETE', expired_key, query={'uploadId': expired_id})
        os.utime(src / 'large', ns=(1_500_000_000_000000000, 1_500_000_000_000000000))
        run([src / 'large', '--to', remote, '--as', expired_key])
        _, body = request('GET', expired_key)
        assert body == (src / 'large').read_bytes()
        print('S3 roundtrip, interoperability, metadata, mapping, policies, path confinement, and resume passed', flush=True)


if __name__ == '__main__':
    print('Disposable S3 test prefix:', PREFIX, flush=True)
    try:
        check()
    finally:
        clean()
        print('Owned S3 test objects and multipart uploads removed', flush=True)
