"""Real return-channel approval and detached-authorizer storage transfers."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


def run(*argv, timeout=40):
    return subprocess.check_output(argv, text=True, timeout=timeout)


def connect():
    run('syq', 'persist', 'receive', 'on', '--name', 'laptop', '--notify', 'off',
        '--auto-approve-root', str(Path.home()))
    run('syq', 'persist', 'connect', 'source')
    run('syq', 'persist', 'receive', 'wait', 'source', '--timeout', '30')


def copy(arguments, *, allow=True, disconnect=True, interrupt=False, ok=None):
    if ok is None:
        ok = allow and not interrupt
    connect()
    command = ['syq', 'cp', '--auth-from', '@laptop', '--s3-profile', 'storage-test',
               '--s3-endpoint', endpoint, '--s3-region', 'us-east-1', '--no-progress',
               '--performance-tuning=s3-part-size=5M,s3-max-concurrent-parts-per-object=1,s3-retries=0',
               '--resource-limits=bandwidth=2MiB', '--results', '/tmp/syq-storage-authorization/progress', *arguments]
    remote = 'test ! -e ~/.aws/credentials && test -z "${AWS_ACCESS_KEY_ID:-}" && echo $$ > /tmp/syq-storage-authorization/copy.pid && exec ' + shlex.join(command)
    process = subprocess.Popen(['ssh', 'source', remote], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    messages = queue.Queue()
    errors = []
    def read_errors():
        for line in process.stderr:
            errors.append(line)
            messages.put(line)
    reader = threading.Thread(target=read_errors)
    reader.start()
    try:
        pending = json.loads(run('syq', 'persist', 'receive', 'pending', '--json', '--wait', '--timeout', '15'))
        assert len(pending) == 1 and pending[0]['kind'] == 'storage', pending
        description = pending[0]['description']
        assert '604800 seconds' in description and 'receiver receipts do not apply' in description, description
        run('syq', 'persist', 'receive', 'approve' if allow else 'deny', pending[0]['id'])
        if allow and disconnect:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                try:
                    line = messages.get(timeout=1)
                    if 'storage authorization ready;' in line:
                        break
                except queue.Empty:
                    if process.poll() is not None:
                        raise AssertionError('copy ended before authorization finished: ' + ''.join(errors))
            else:
                raise AssertionError('authorization preparation deadline: ' + ''.join(errors))
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
            print('case: multipart upload finishes after authorizer disconnects', flush=True)
            copy([remote_root+'/source', '--to', 's3://syq-storage-test', '--as', prefix+'/large'])
            assert hashlib.sha256(checks.request('GET', prefix+'/large')[1]).hexdigest() == expected
            print('case: interrupted multipart work resumes after a fresh approval', flush=True)
            resumed = [remote_root+'/source', '--to', 's3://syq-storage-test', '--as', prefix+'/resumed']
            copy(resumed, interrupt=True)
            assert checks.listing(uploads=True), 'interrupted upload lost its recoverable parts'
            copy(resumed)
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
