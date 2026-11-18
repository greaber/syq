"""Copies between a server and a bucket, started from another machine.

The runner holds the storage credentials and types the command. The source
server holds none: it runs the copy with URLs the runner signs over the SSH
session, and exchanges file data with the storage fixture directly.

In the last cases the command is typed on the source about files on the
destination, and the runner, as the source's receiving machine, approves the
request and signs: the source only passes the signing messages on.
"""
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
import urllib.error
import urllib.request

import syq_real_ssh_lab as lab

BUCKET = 'syq-server-storage-test'
REMOTE = '/tmp/syq-server-storage'
PAYLOAD = b'server-storage!!' * (1024 * 1024)


def syq(arguments, *, ok=True, endpoint=None, timeout=120):
    """Run `syq cp` on the runner, which signs with the fixture's profile."""
    command = ['syq', 'cp', '--s3-profile', 'server-storage-test', '--s3-endpoint', endpoint or ENDPOINT,
               '--s3-region', 'us-east-1', '--no-progress', '--s3-retries=0', *arguments]
    result = subprocess.run(command, text=True, capture_output=True, timeout=timeout, env=profile_only())
    assert (result.returncode == 0) == ok, (command, result)
    assert 'X-Amz-Signature' not in result.stdout + result.stderr, 'a signed URL reached the output'
    return result


def profile_only():
    """The runner's environment for syq: its storage credentials are in the
    profile alone, and nothing but the command names the endpoint."""
    return {name: value for name, value in os.environ.items()
            if name not in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_ENDPOINT_URL_S3')}


def absent(key):
    try:
        checks.request('HEAD', key)
    except urllib.error.HTTPError as error:
        assert error.code == 404, error
    else:
        raise AssertionError('unexpected object: ' + key)


def server_copies():
    """The processes of storage copies on the source server: the copy and
    the shell that started it."""
    return lab.remote('source', "pgrep -u syq -f -- 'cp --delegated-operands-b6[4]' || true").split()


with tempfile.TemporaryDirectory(prefix='syq-server-storage-') as directory:
    root = Path(directory)
    address = socket.gethostbyname(socket.gethostname())
    ENDPOINT = f'http://{address}:9110'
    os.environ.update(AWS_REGION='us-east-1', AWS_ENDPOINT_URL_S3=ENDPOINT, SYQ_TEST_BUCKET=BUCKET,
                      AWS_ACCESS_KEY_ID='syq-test-user', AWS_SECRET_ACCESS_KEY='syq-test-password',
                      AWS_EC2_METADATA_DISABLED='true')
    os.environ.pop('AWS_SESSION_TOKEN', None)
    environment = dict(os.environ, MINIO_ROOT_USER='syq-test-user', MINIO_ROOT_PASSWORD='syq-test-password')
    with (root / 's3-server.log').open('w+') as log:
        s3_server = subprocess.Popen(['/usr/local/libexec/syq-test-s3-server', 'server', '--address', ':9110',
                                      '--console-address', ':9111', str(root / 'data')],
                                     env=environment, stdout=log, stderr=log, start_new_session=True)
        credentials = Path.home() / '.aws' / 'credentials'
        assert not credentials.exists(), 'fixture must not overwrite credentials'
        checks = None
        try:
            def ready():
                try:
                    with urllib.request.urlopen(ENDPOINT + '/minio/health/ready', timeout=1) as response:
                        return response.status == 200
                except OSError:
                    return False
            lab.wait_for('the storage fixture', ready, 30)
            sys.argv = [sys.argv[0], '/usr/local/bin/syq']
            spec = importlib.util.spec_from_file_location('storage_checks', '/usr/local/libexec/syq-storage-check.py')
            checks = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(checks)
            checks.request('PUT')
            prefix = checks.PREFIX
            # The environment's credentials are for this script's own checks.
            # syq gets them from the profile, and only on the runner.
            credentials.parent.mkdir(mode=0o700, exist_ok=True)
            credentials.write_text('[server-storage-test]\naws_access_key_id = syq-test-user\n'
                                   'aws_secret_access_key = syq-test-password\n')
            credentials.chmod(0o600)
            script = ("from pathlib import Path; p=Path(%r); (p/'dataset/sub').mkdir(parents=True); "
                      "(p/'dataset/large').write_bytes(%r*(1024*1024)); (p/'dataset/sub/small').write_text('small\\n')"
                      % (REMOTE, PAYLOAD[:16]))
            lab.remote('source', shlex.join(['python3', '-c', script]))
            lab.remote('source', 'test ! -e ~/.aws/credentials && test -z "${AWS_ACCESS_KEY_ID:-}"')
            expected = hashlib.sha256(PAYLOAD).hexdigest()
            upload = ['--from', 'source', '--srcs-in', REMOTE + '/dataset', '--to', 's3://' + BUCKET,
                      '--into', prefix + '/dataset']

            print('case: a dry run from a server changes nothing in the bucket', flush=True)
            result = syq([*upload, '--dry-run'])
            assert 'Would copy 2 files' in result.stdout, result
            assert not checks.listing()

            print('case: upload from a server with requests the runner signs', flush=True)
            results = root / 'upload.ndjson'
            result = syq([*upload, '--performance-tuning=s3-part-size=5M', '--results', str(results)])
            assert 'this machine signs its storage requests' in result.stderr, result
            assert hashlib.sha256(checks.request('GET', prefix + '/dataset/large')[1]).hexdigest() == expected
            assert checks.request('GET', prefix + '/dataset/sub/small')[1] == b'small\n'
            records = [json.loads(line) for line in results.read_text().splitlines()]
            assert {(e['kind'], e['host']) for e in records[0]['endpoints']} == {
                ('ssh', 'source'), ('s3', 's3://' + BUCKET)}, records[0]
            assert records[-1]['type'] == 'result' and records[-1]['status'] == 'success', records[-1]
            assert records[-1]['files_transferred'] == 2, records[-1]
            assert 'Copied 0 files' in syq(upload).stdout, 'a second run copied again'

            print('case: download to a server with requests the runner signs', flush=True)
            syq(['--from', 's3://' + BUCKET, '--srcs-in', prefix + '/dataset', '--to', 'source',
                 '--into', REMOTE + '/restored'])
            assert lab.remote('source', f'sha256sum {REMOTE}/restored/large').split()[0] == expected
            assert lab.remote('source', f'cat {REMOTE}/restored/sub/small') == 'small\n'
            assert not Path(REMOTE).exists(), 'the runner received file data'

            print('case: a server asking for another prefix gets nothing signed', flush=True)
            # A server whose syq copies into "other" in place of the last
            # word of its command, the destination the runner named.
            wrapper = REMOTE + '/other-prefix'
            lab.remote('source', 'cat > %s && chmod +x %s' % (wrapper, wrapper), stdin=(
                '#!/bin/sh\ncount=$#\nindex=0\nfor word do\n  index=$((index + 1))\n'
                '  if [ "$index" -eq "$count" ]; then set -- "$@" %s; else set -- "$@" "$word"; fi\n'
                '  shift\ndone\nexec syq "$@"\n' % 'b3RoZXI'))
            checks.request('PUT', 'other/kept', b'kept')
            try:
                result = syq([*upload, '--prune', '--syq-path', wrapper], ok=False)
                assert 'refused to sign a storage request from the server' in result.stderr, result
                assert checks.request('GET', 'other/kept')[1] == b'kept'
                assert not checks.listing('other/dataset'), 'the server wrote outside the command'
            finally:
                checks.request('DELETE', 'other/kept')

            print('case: a server that cannot reach storage says what to check', flush=True)
            result = syq(upload, ok=False, endpoint=f'http://{address}:9119')
            assert 'this server got no answer from the storage service' in result.stderr, result
            assert 'never through the machine that started the copy' in result.stderr, result

            print('case: interrupting the runner stops the copy on the server', flush=True)
            progress = root / 'interrupted.ndjson'
            interrupted = ['--from', 'source', REMOTE + '/dataset/large', '--to', 's3://' + BUCKET,
                           '--as', prefix + '/interrupted', '--performance-tuning=s3-part-size=5M,s3-parts-per-object=1',
                           '--resource-limits=bandwidth=2MiB', '--results', str(progress)]
            process = subprocess.Popen(['syq', 'cp', '--s3-profile', 'server-storage-test', '--s3-endpoint', ENDPOINT,
                                        '--s3-region', 'us-east-1', '--no-progress', *interrupted],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                                       start_new_session=True, env=profile_only())
            try:
                def uploaded():
                    assert process.poll() is None, ('the copy ended early', process.stderr.read())
                    if not progress.exists():
                        return 0
                    events = [json.loads(line) for line in progress.read_text().splitlines() if line]
                    return max((e['bytes_done'] for e in events if e['type'] == 'progress'), default=0)
                lab.wait_for('uploaded bytes', uploaded, 45)
                assert server_copies(), 'no copy is running on the server'
                # The runner ends with no chance to tell the server anything.
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
                lab.wait_for('the copy on the server to stop', server_copies, 20, done=lambda found: not found)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            absent(prefix + '/interrupted')
            print('case: running the interrupted copy again finishes it', flush=True)
            interrupted[-1] = str(root / 'resumed.ndjson')
            syq([argument for argument in interrupted if not argument.startswith('--resource-limits')])
            assert hashlib.sha256(checks.request('GET', prefix + '/interrupted')[1]).hexdigest() == expected

            print('case: named sources are signed for at their own names only', flush=True)
            named = ['--from', 'source', REMOTE + '/dataset', '--to', 's3://' + BUCKET, '--into', prefix + '/named']
            checks.request('PUT', prefix + '/named/kept', b'kept')
            syq([*named, '--prune'])
            assert checks.request('GET', prefix + '/named/dataset/sub/small')[1] == b'small\n'
            assert checks.request('GET', prefix + '/named/kept')[1] == b'kept', 'pruning left the named source'

            print('case: more deletions than --max-delete are refused together, unsigned', flush=True)
            for name in ('extra-1', 'extra-2'):
                checks.request('PUT', f'{prefix}/named/dataset/{name}', b'extra')
            result = syq([*named, '--prune', '--max-delete=1'], ok=False)
            assert 'planned deletions exceed --max-delete' in result.stdout + result.stderr, result
            assert 'refused to sign' not in result.stderr, result
            for name in ('extra-1', 'extra-2'):
                assert checks.request('GET', f'{prefix}/named/dataset/{name}')[1] == b'extra'
            syq([*named, '--prune', '--max-delete=2'])
            absent(prefix + '/named/dataset/extra-1')
            absent(prefix + '/named/dataset/extra-2')

            print('case: a receiving machine signs for a copy typed on one server about files on another', flush=True)
            # The source types the command and holds nothing: the files are
            # on the destination, and the storage credentials on the runner,
            # which is the source's receiving machine @laptop.
            there = '/tmp/syq-real-ssh/server-storage'
            script = ("from pathlib import Path; p=Path(%r); (p/'tree/sub').mkdir(parents=True); "
                      "(p/'tree/a').write_text('first\\n'); (p/'tree/sub/b').write_text('second\\n')" % there)
            lab.remote('destination', shlex.join(['python3', '-c', script]))
            for host in ('source', 'destination'):
                lab.remote(host, 'test ! -e ~/.aws/credentials && test -z "${AWS_ACCESS_KEY_ID:-}"')
            # The source logs in to the destination with the runner's
            # forwarded agent, and trusts the host key the runner trusts.
            trusted = lab.run('ssh-keygen', '-F', 'destination', '-f', str(Path.home() / '.ssh/known_hosts'))
            lab.remote('source', 'umask 077; cat >> ~/.ssh/known_hosts', stdin=trusted)
            lab.run('syq', 'persist', 'receive', 'on', '--name', 'laptop', '--notify', 'off',
                    '--auto-approve-root', str(Path.home()))
            try:
                lab.run('syq', 'persist', 'connect', 'source')
                lab.run('syq', 'persist', 'receive', 'wait', 'source', '--timeout', '30')

                def typed_on_source(into, approve):
                    command = ['syq', 'cp', '--from', 'destination', there + '/tree', '--to', 's3://' + BUCKET,
                               '--into', into, '--auth-from', '@laptop', '--s3-profile', 'server-storage-test',
                               '--s3-endpoint', ENDPOINT, '--s3-region', 'us-east-1', '--no-progress',
                               '--s3-retries=0']
                    process = subprocess.Popen(['ssh', '-A', 'source', 'exec ' + shlex.join(command)],
                                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, text=True, start_new_session=True)
                    try:
                        pending = json.loads(lab.run('syq', 'persist', 'receive', 'pending', '--json', '--wait',
                                                     '--timeout', '30'))
                        assert len(pending) == 1 and pending[0]['kind'] == 'storage', pending
                        shown = json.dumps(pending[0])
                        # The prompt shows the command, the one path its named
                        # source produces, and today's lifetime.
                        assert pending[0]['command'][2:5] == ['--from', 'destination', there + '/tree'], shown
                        assert f'"{into}/tree" and descendants' in pending[0]['description'], shown
                        assert '604800 seconds' in pending[0]['description'], shown
                        lab.run('syq', 'persist', 'receive', 'approve' if approve else 'deny', pending[0]['id'])
                        out, err = process.communicate(timeout=90)
                    finally:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait(timeout=5)
                    assert (process.returncode == 0) == approve, (process.returncode, out, err)
                    assert 'X-Amz-Signature' not in out + err, 'a signed URL reached the output'
                    return err

                err = typed_on_source(prefix + '/relayed', True)
                assert '@laptop signs its storage requests' in err, err
                assert 'storage authorization ready; @laptop may disconnect' in err, err
                assert checks.request('GET', prefix + '/relayed/tree/a')[1] == b'first\n'
                assert checks.request('GET', prefix + '/relayed/tree/sub/b')[1] == b'second\n'
                lab.remote('source', 'test ! -e ' + shlex.quote(there))

                print('case: a receiving machine that denies the request leaves the bucket alone', flush=True)
                typed_on_source(prefix + '/denied', False)
                assert not checks.listing(prefix + '/denied')
            finally:
                lab.run('syq', 'persist', 'receive', 'off')
                subprocess.run(['ssh', 'destination', 'rm -rf ' + there], timeout=30)
        finally:
            try:
                subprocess.run(['ssh', 'source', 'rm -rf ' + REMOTE], timeout=30)
                if checks is not None:
                    checks.clean()
                    checks.request('DELETE')
            finally:
                credentials.unlink(missing_ok=True)
                os.killpg(s3_server.pid, signal.SIGTERM)
                try:
                    s3_server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(s3_server.pid, signal.SIGKILL)
                    s3_server.wait(timeout=5)
                if s3_server.returncode not in (0, -signal.SIGTERM):
                    log.seek(0)
                    print(log.read(), flush=True)
print('Copies between a server and a bucket over real SSH passed', flush=True)
