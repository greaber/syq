"""Real return-channel approval and detached-authorizer storage transfers."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request


def run(*argv, timeout=40):
    return subprocess.check_output(argv, text=True, timeout=timeout)


def absent(key):
    try:
        checks.request('HEAD', key)
    except urllib.error.HTTPError as error:
        assert error.code == 404, error
    else:
        raise AssertionError('unexpected published object: '+key)


def connect():
    run('syq', 'persist', 'receive', 'on', '--name', 'laptop', '--notify', 'off',
        '--auto-approve-root', str(Path.home()))
    run('syq', 'persist', 'connect', 'source')
    run('syq', 'persist', 'receive', 'wait', 'source', '--timeout', '30')


def copy(arguments, *, allow=True, disconnect=True, interrupt=False, ok=None, redirection='', pipe_input=False, mapping=None, removal=False):
    if ok is None:
        ok = allow and not interrupt
    connect()
    command = ['syq', 'cp', '--auth-from', '@laptop', '--s3-profile', 'storage-test',
               '--s3-endpoint', endpoint, '--s3-region', 'us-east-1', '--no-progress',
               '--performance-tuning=s3-part-size=5M,s3-max-concurrent-parts-per-object=1,s3-retries=0',
               '--resource-limits=bandwidth=2MiB', '--results', '/tmp/syq-storage-authorization/progress', *arguments]
    if removal:
        command[1] = 'rm'
        command = [item for item in command if not item.startswith(('--performance-tuning=', '--resource-limits='))]
    if mapping:
        command = ['python3', '/usr/local/libexec/syq-storage-streams.py', mapping, *command]
    remote = 'rm -f /tmp/syq-storage-authorization/progress && test ! -e ~/.aws/credentials && test -z "${AWS_ACCESS_KEY_ID:-}" && echo $$ > /tmp/syq-storage-authorization/copy.pid && ' + ('cat /tmp/syq-storage-authorization/source | ' if pipe_input else '') + 'exec ' + shlex.join(command) + redirection
    process = subprocess.Popen(['ssh', 'source', remote], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    errors = []
    def read_errors():
        for line in process.stderr:
            errors.append(line)
    reader = threading.Thread(target=read_errors)
    reader.start()
    try:
        try:
            pending = json.loads(run('syq', 'persist', 'receive', 'pending', '--json', '--wait', '--timeout', '15'))
        except subprocess.CalledProcessError as error:
            raise AssertionError(f'approval unavailable; worker exit {process.poll()}: '+''.join(errors)) from error
        assert len(pending) == 1 and pending[0]['kind'] == 'storage', pending
        description = pending[0]['description']
        assert '604800 seconds' in description and 'receiver receipts do not apply' in description, description
        run('syq', 'persist', 'receive', 'approve' if allow else 'deny', pending[0]['id'])
        if allow and disconnect:
            # Data progress proves preparation has finished without parsing a
            # human diagnostic as the readiness protocol. Check that diagnostic
            # separately, since it tells the person when disconnection is safe.
            deadline = time.monotonic() + 45
            next_notice = 0
            last = 'no data transferred'
            while time.monotonic() < deadline:
                raw = run('ssh', 'source', 'cat /tmp/syq-storage-authorization/progress')
                events = [json.loads(line) for line in raw.split('\n')[:-1] if line]
                completed = max((e['bytes_done'] for e in events if e['type'] == 'progress'), default=0)
                last = f'{completed} bytes completed; exit status {process.poll()}'
                if completed > 0:
                    break
                assert process.poll() is None, (last, ''.join(errors))
                if time.monotonic() >= next_notice:
                    print('Waiting for data progress:', last, flush=True)
                    next_notice = time.monotonic() + 2
                time.sleep(.2)
            else:
                raise AssertionError('authorization preparation deadline: ' + last + ''.join(errors))
            assert 'storage authorization ready;' in ''.join(errors), ''.join(errors)
            run('syq', 'persist', 'receive', 'off')
            assert process.poll() is None, ('copy ended before disconnection check', process.returncode, ''.join(errors))
        if interrupt:
            deadline = time.monotonic() + 20
            last = 'no completed parts'
            while time.monotonic() < deadline:
                raw = run('ssh', 'source', 'cat /tmp/syq-storage-authorization/progress')
                events = [json.loads(line) for line in raw.split('\n')[:-1] if line]
                completed = max((e['bytes_done'] for e in events if e['type'] == 'progress'), default=0)
                last = f'{completed} bytes completed; exit status {process.poll()}'
                if completed >= 5*1024*1024:
                    break
                assert process.poll() is None, (last, ''.join(errors))
                print('Waiting for interruption point:', last, flush=True)
                time.sleep(.5)
            else:
                raise AssertionError('interruption deadline: ' + last)
            pid = run('ssh', 'source', 'cat /tmp/syq-storage-authorization/copy.pid').strip()
            assert pid.isdecimal()
            run('ssh', 'source', 'kill -TERM ' + pid)
        status = process.wait(timeout=60)
        reader.join(timeout=5)
        out = process.stdout.read()
        assert (status == 0) == ok, (status, out, ''.join(errors))
        assert 'X-Amz-Signature' not in ''.join(errors), 'signed URL leaked to diagnostics'
        print(''.join(errors), end='', flush=True)
        return out
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        reader.join(timeout=5)


with tempfile.TemporaryDirectory(prefix='syq-storage-authorization-') as directory:
    root = Path(directory)
    address = socket.gethostbyname(socket.gethostname())
    endpoint = f'http://{address}:9100'
    os.environ.update(AWS_ACCESS_KEY_ID='syq-test-user', AWS_SECRET_ACCESS_KEY='syq-test-password',
                      AWS_REGION='us-east-1', AWS_ENDPOINT_URL_S3=endpoint, SYQ_TEST_BUCKET='syq-storage-test',
                      AWS_EC2_METADATA_DISABLED='true')
    os.environ.pop('AWS_SESSION_TOKEN', None)
    environment = dict(os.environ, MINIO_ROOT_USER='syq-test-user', MINIO_ROOT_PASSWORD='syq-test-password')
    with (root/'minio.log').open('w+') as log:
        minio = subprocess.Popen(['/usr/local/libexec/syq-test-minio', 'server', '--address', ':9100',
                                  '--console-address', ':9101', str(root/'data')],
                                 env=environment, stdout=log, stderr=log, start_new_session=True)
        credentials = Path.home()/'.aws'/'credentials'
        assert not credentials.exists(), 'fixture must not overwrite credentials'
        credentials.parent.mkdir(mode=0o700, exist_ok=True)
        credentials.write_text('[storage-test]\naws_access_key_id = syq-test-user\naws_secret_access_key = syq-test-password\n')
        credentials.chmod(0o600)
        checks = None
        try:
            deadline = time.monotonic() + 30
            last = 'not checked'
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen(endpoint+'/minio/health/ready', timeout=1) as response:
                        if response.status == 200:
                            break
                        last = f'HTTP {response.status}'
                except OSError as error:
                    last = type(error).__name__
                print('Waiting for storage fixture:', last, flush=True)
                time.sleep(1)
            else:
                raise AssertionError('MinIO readiness deadline: '+last)
            sys.argv = [sys.argv[0], '/usr/local/bin/syq']
            spec = importlib.util.spec_from_file_location('storage_checks', '/usr/local/libexec/syq-storage-check.py')
            checks = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(checks)
            checks.request('PUT')
            prefix = checks.PREFIX
            remote_root = '/tmp/syq-storage-authorization'
            script = "from pathlib import Path; p=Path(%r); p.mkdir(); (p/'source').write_bytes(b'storage-fixture!'*(1024*1024))" % remote_root
            run('ssh', 'source', shlex.join(['python3', '-c', script]))
            expected = hashlib.sha256(b'storage-fixture!'*(1024*1024)).hexdigest()
            print('case: denied storage request never uploads', flush=True)
            copy([remote_root+'/source', '--to', 's3://syq-storage-test', '--as', prefix+'/denied'], allow=False)
            assert not checks.listing()
            print('case: a different build refuses storage authorization before requesting approval', flush=True)
            skew = subprocess.run(['ssh', 'source', shlex.join(['syq-other-build', 'cp', remote_root+'/source',
                                  '--to', 's3://syq-storage-test', '--as', prefix+'/skew', '--auth-from', '@laptop'])],
                                  text=True, capture_output=True, timeout=20)
            assert skew.returncode != 0 and 'requires matching syq builds' in skew.stderr, skew.stderr
            assert json.loads(run('syq', 'persist', 'receive', 'pending', '--json')) == []
            print('case: multipart upload finishes after authorizer disconnects', flush=True)
            copy([remote_root+'/source', '--to', 's3://syq-storage-test', '--as', prefix+'/large'])
            assert hashlib.sha256(checks.request('GET', prefix+'/large')[1]).hexdigest() == expected
            print('case: descriptor upload and download continue without the authorizer', flush=True)
            copy(['--src-fd', '0', '--to', 's3://syq-storage-test', '--as', prefix+'/descriptor'],
                 redirection=' < /tmp/syq-storage-authorization/source')
            assert hashlib.sha256(checks.request('GET', prefix+'/descriptor')[1]).hexdigest() == expected
            copy([prefix+'/descriptor', '--from', 's3://syq-storage-test', '--as-fd', '1'],
                 redirection=' > /tmp/syq-storage-authorization/descriptor-download')
            assert run('ssh', 'source', 'sha256sum /tmp/syq-storage-authorization/descriptor-download').split()[0] == expected
            print('case: unknown-length input signs parts before reading the pipe', flush=True)
            copy(['--src-fd', '0', '--to', 's3://syq-storage-test', '--as', prefix+'/pipe'],
                 pipe_input=True)
            assert hashlib.sha256(checks.request('GET', prefix+'/pipe')[1]).hexdigest() == expected
            print('case: prepared multipart server-side copy', flush=True)
            copy([prefix+'/large', '--from', 's3://syq-storage-test', '--to', 's3://syq-storage-test',
                  '--as', prefix+'/server-copy'], disconnect=False)
            assert hashlib.sha256(checks.request('GET', prefix+'/server-copy')[1]).hexdigest() == expected
            print('case: single-request copy preserves object metadata', flush=True)
            checks.request('PUT', prefix+'/small-source', b'small copy', headers={'x-amz-meta-example': 'kept', 'content-type': 'text/plain'})
            copy([prefix+'/small-source', '--from', 's3://syq-storage-test', '--to', 's3://syq-storage-test',
                  '--as', prefix+'/small-copy'], disconnect=False)
            headers, body = checks.request('GET', prefix+'/small-copy')
            assert body == b'small copy'
            assert {k.lower(): v for k, v in headers.items()}['x-amz-meta-example'] == 'kept'
            print('case: mixed paths and callbacks share one offline approval', flush=True)
            copy(['--to', 's3://syq-storage-test', '--into', prefix+'/mixed'], mapping='upload')
            for name in ['ordinary', 'known', 'unknown']:
                assert hashlib.sha256(checks.request('GET', prefix+'/mixed/'+name)[1]).hexdigest() == expected
            copy(['--from', 's3://syq-storage-test', '--cwd', prefix+'/mixed',
                  '--into', remote_root+'/mixed-download'], mapping='download')
            assert run('ssh', 'source', 'sha256sum '+remote_root+'/mixed-download/ordinary').split()[0] == expected
            print('case: failed producer cannot publish after authorization disconnects', flush=True)
            copy(['--to', 's3://syq-storage-test', '--into', prefix+'/failed-mixed'], mapping='abort', ok=False)
            absent(prefix+'/failed-mixed/known')
            print('case: storage removal honors previews and approval', flush=True)
            remove = ['--on', 's3://syq-storage-test', prefix+'/server-copy']
            copy([*remove, '--dry-run'], removal=True, disconnect=False)
            assert hashlib.sha256(checks.request('GET', prefix+'/server-copy')[1]).hexdigest() == expected
            copy(remove, removal=True, disconnect=False)
            absent(prefix+'/server-copy')
            print('case: trailing-slash directory and contents removal use the approved base', flush=True)
            for selector, name in [('--src-dir', 'slash-directory'), ('--srcs-in', 'slash-contents')]:
                marker = prefix+'/'+name+'/'
                child = marker+'child'
                neighbor = prefix+'/'+name+'-neighbor'
                checks.request('PUT', marker, b'')
                checks.request('PUT', child, b'child')
                checks.request('PUT', neighbor, b'keep')
                remove = ['--on', 's3://syq-storage-test', '--cwd', prefix, selector, name+'/']
                copy([*remove, '--dry-run'], removal=True, disconnect=False)
                assert checks.request('GET', marker)[1] == b''
                assert checks.request('GET', child)[1] == b'child'
                copy(remove, removal=True, disconnect=False)
                absent(child)
                if selector == '--src-dir':
                    absent(marker)
                else:
                    assert checks.request('GET', marker)[1] == b''
                assert checks.request('GET', neighbor)[1] == b'keep'
            print('case: interrupted multipart work resumes after a fresh approval', flush=True)
            resumed = [remote_root+'/source', '--to', 's3://syq-storage-test', '--as', prefix+'/resumed']
            copy(resumed, interrupt=True)
            # Inspect the known recovery upload directly. Bucket-wide unfinished
            # upload listings are not consistent across S3-compatible providers.
            script = "from pathlib import Path; import json; records=[json.loads(p.read_text()) for p in (Path.home()/'.cache/syq/s3').glob('*.json')]; print(json.dumps([r['upload_id'] for r in records if 'upload_id' in r]))"
            uploads = json.loads(run('ssh', 'source', shlex.join(['python3', '-c', script])))
            assert len(uploads) == 1, uploads
            checks.OWNED_UPLOADS.add((prefix+'/resumed', uploads[0]))
            _, parts = checks.request('GET', prefix+'/resumed', query={'uploadId': uploads[0]})
            assert any(node.tag.rsplit('}', 1)[-1] == 'Part' for node in checks.ET.fromstring(parts).iter()), 'no completed parts to resume'
            copy(resumed)
            events = [json.loads(line) for line in run('ssh', 'source', 'cat /tmp/syq-storage-authorization/progress').splitlines()]
            assert events[-1]['bytes_unchanged'] > 0, events[-1]
            assert hashlib.sha256(checks.request('GET', prefix+'/resumed')[1]).hexdigest() == expected
            assert not checks.listing(uploads=True)
            print('case: multipart download finishes after authorizer disconnects', flush=True)
            copy([prefix+'/large', '--from', 's3://syq-storage-test', '--as', remote_root+'/downloaded'])
            assert run('ssh', 'source', shlex.join(['sha256sum', remote_root+'/downloaded'])).split()[0] == expected
            print('case: tree metadata and special key bytes survive authorization', flush=True)
            script = "from pathlib import Path; p=Path(%r)/'tree'; p.mkdir(); (p/'a +?#雪').write_bytes(b'small'); (p/'empty').mkdir(); (p/'link').symlink_to('a +?#雪')" % remote_root
            run('ssh', 'source', shlex.join(['python3', '-c', script]))
            copy(['--srcs-in', remote_root+'/tree', '--to', 's3://syq-storage-test', '--into', prefix+'/tree'], disconnect=False)
            copy(['--srcs-in', prefix+'/tree', '--from', 's3://syq-storage-test', '--into', remote_root+'/tree-copy'], disconnect=False)
            run('ssh', 'source', shlex.join(['diff', '-r', remote_root+'/tree', remote_root+'/tree-copy']))
            print('case: conditional create and overwrite refusal', flush=True)
            copy([remote_root+'/tree/a +?#雪', '--to', 's3://syq-storage-test', '--as-new', prefix+'/new'], disconnect=False)
            copy([remote_root+'/source', '--to', 's3://syq-storage-test', '--as-new', prefix+'/new'], disconnect=False, ok=False)
            assert checks.request('GET', prefix+'/new')[1] == b'small'
            print('case: pruning plans and deletions need no authorizer after preparation', flush=True)
            checks.request('PUT', prefix+'/tree/stale', b'remove')
            prune = ['--srcs-in', remote_root+'/tree', '--to', 's3://syq-storage-test', '--into', prefix+'/tree', '--prune']
            copy([*prune, '--dry-run'], disconnect=False)
            assert prefix+'/tree/stale' in checks.listing()
            copy(prune, disconnect=False)
            assert prefix+'/tree/stale' not in checks.listing()
            print('case: mapping downloads use the approved source base', flush=True)
            mapping = [{'src': {'encoding': 'utf-8', 'value': 'new'},
                        'dst': {'encoding': 'utf-8', 'value': 'mapped'}, 'kind': 'file'}]
            script = "from pathlib import Path; Path(%r).write_text(%r)" % (remote_root+'/mapping', '\n'.join(json.dumps(item) for item in mapping)+'\n')
            run('ssh', 'source', shlex.join(['python3', '-c', script]))
            copy(['--mapping', remote_root+'/mapping', '--cwd', prefix, '--from', 's3://syq-storage-test', '--into', remote_root+'/mapping-copy'], disconnect=False)
            assert run('ssh', 'source', shlex.join(['cat', remote_root+'/mapping-copy/mapped'])) == 'small'
            if endpoint.startswith('http://'):
                # Only the disposable MinIO fixture owns bucket configuration.
                # Live-provider runs leave existing bucket settings untouched.
                print('case: cross-bucket copies and permanent version removal', flush=True)
                original_bucket = checks.BUCKET
                other_bucket = 'syq-storage-versions'
                checks.BUCKET = other_bucket
                checks.request('PUT')
                try:
                    copy([prefix+'/large', '--from', 's3://syq-storage-test', '--to', 's3://'+other_bucket,
                          '--as', prefix+'/copied'], disconnect=False)
                    assert hashlib.sha256(checks.request('GET', prefix+'/copied')[1]).hexdigest() == expected
                    checks.request('DELETE', prefix+'/copied')
                    checks.request('PUT', data=b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>', query={'versioning': ''})
                    print('case: exact directory-marker version removal preserves its trailing slash', flush=True)
                    marker = prefix+'/marker/'
                    # Pinned MinIO exposes directory markers as the null
                    # version even when the bucket has versioning enabled.
                    checks.request('PUT', marker, b'')
                    marker_version = 'null'
                    checks.request('PUT', marker+'child', b'keep child')
                    checks.request('PUT', prefix+'/marker-neighbor', b'keep separate key')
                    remove = ['--on', 's3://'+other_bucket, '--cwd', prefix,
                              '--s3-version-id', marker_version, 'marker/']
                    copy([*remove, '--dry-run'], removal=True, disconnect=False)
                    assert checks.request('GET', marker, query={'versionId': marker_version})[1] == b''
                    copy(remove, removal=True, disconnect=False)
                    try:
                        checks.request('HEAD', marker, query={'versionId': marker_version})
                    except urllib.error.HTTPError as error:
                        assert error.code == 404, error
                    else:
                        raise AssertionError('selected directory-marker version was not removed')
                    absent(marker)
                    assert checks.request('GET', marker+'child')[1] == b'keep child'
                    assert checks.request('GET', prefix+'/marker-neighbor')[1] == b'keep separate key'
                    key = prefix+'/versioned'
                    headers, _ = checks.request('PUT', key, b'old')
                    old = {k.lower(): v for k, v in headers.items()}['x-amz-version-id']
                    checks.request('PUT', key, b'new')
                    checks.request('PUT', key+'-neighbor', b'outside selected key')
                    remove = ['--on', 's3://'+other_bucket, key]
                    copy([*remove, '--s3-version-id', old], removal=True, disconnect=False)
                    assert checks.request('GET', key)[1] == b'new'
                    _, listing = checks.request('GET', query={'versions': '', 'prefix': key})
                    assert old not in listing.decode(), listing
                    copy(remove, removal=True, disconnect=False)
                    absent(key)
                    copy([*remove, '--s3-all-versions'], removal=True, disconnect=False)
                    _, listing = checks.request('GET', query={'versions': '', 'prefix': key})
                    tree = checks.ET.fromstring(listing)
                    keys = [node.text for node in tree.iter() if node.tag.rsplit('}', 1)[-1] == 'Key']
                    assert keys == [key+'-neighbor'], keys
                finally:
                    _, listing = checks.request('GET', query={'versions': '', 'prefix': prefix+'/'})
                    tree = checks.ET.fromstring(listing)
                    for node in tree.iter():
                        node.tag = node.tag.rsplit('}', 1)[-1]
                    for node in list(tree.findall('Version')) + list(tree.findall('DeleteMarker')):
                        checks.request('DELETE', node.findtext('Key'), query={'versionId': node.findtext('VersionId')})
                    checks.request('DELETE')
                    checks.BUCKET = original_bucket
        finally:
            try:
                run('syq', 'persist', 'receive', 'off')
                if checks is not None:
                    checks.clean()
            finally:
                credentials.unlink(missing_ok=True)
                os.killpg(minio.pid, signal.SIGTERM)
                try:
                    minio.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(minio.pid, signal.SIGKILL)
                    minio.wait(timeout=5)
                if minio.returncode not in (0, -signal.SIGTERM):
                    log.seek(0)
                    print(log.read(), flush=True)
    connect()
print('Storage authorization over real SSH passed', flush=True)
