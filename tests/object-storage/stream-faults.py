#!/usr/bin/env python3
"""Independent HTTP fixture; no credentials, packages or remote services needed."""
import base64
import hashlib
import fcntl
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import shlex
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

SYQ = sys.argv[1]
CASE = sys.argv[2]
PART = 5 * 1024 * 1024
DATA = bytes(range(256)) * (PART // 256) + b'last part\x00\xff'
STATE = {'requests': 0, 'gets': {}, 'parts': {}, 'aborts': 0, 'completed': False}
LOCK = threading.Lock()
LATER = threading.Event()
PART_UPLOADED = threading.Event()
CHILDREN = []


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_):
        pass

    def reply(self, code, data=b'', headers=None, length=None):
        self.send_response(code)
        self.send_header('Content-Length', str(len(data) if length is None else length))
        self.send_header('Connection', 'close')
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers()
        try: self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError): pass
        self.close_connection = True

    def do_HEAD(self):
        STATE['requests'] += 1
        if ((CASE == 'preview-results' and self.path.endswith('/missing'))
                or (CASE == 'file-metadata' and STATE.get('missing_object'))):
            self.reply(404)
            return
        headers = {'ETag': '"original"', 'x-amz-version-id': 'v1',
                   'Last-Modified': 'Sun, 13 Sep 2020 12:26:40 GMT'}
        if CASE == 'file-metadata':
            headers.update(STATE.get('metadata', {}))
        self.reply(200, headers=headers, length=len(DATA))

    def do_GET(self):
        STATE['requests'] += 1
        if CASE in ('preview-results', 'file-metadata') and 'list-type=2' in self.path:
            STATE['lists'] = STATE.get('lists', 0) + 1
            child = b'<Contents><Key>object/child</Key><Size>1</Size></Contents>' if STATE.get('prefix_exists') else b''
            self.reply(200, b'<ListBucketResult><IsTruncated>false</IsTruncated>' + child + b'</ListBucketResult>')
            return
        assert self.headers['If-Match'] == '"original"'
        assert urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)['versionId'] == ['v1']
        start, end = map(int, self.headers['Range'].removeprefix('bytes=').split('-'))
        with LOCK:
            attempt = STATE['gets'].get(start, 0)
            STATE['gets'][start] = attempt + 1
        if start == 0 and CASE == 'download':
            assert LATER.wait(5), 'range requests were not parallel'
        elif start: LATER.set()
        body = DATA[start:end+1]
        etag = '"changed"' if CASE == 'bad-range' and STATE.get('bad') == 'etag' else '"original"'
        headers = {'ETag': etag, 'x-amz-version-id': 'v1', 'Content-Range': f'bytes {start}-{end}/{len(DATA)}'}
        if CASE == 'bad-range' and STATE.get('bad') == 'range':
            headers['Content-Range'] = f'bytes {start+1}-{end}/{len(DATA)}'
        if CASE == 'truncated' or (CASE == 'retry' and not attempt):
            self.reply(206, body[:100], headers, length=len(body))
        else: self.reply(206, body, headers)

    def body(self):
        return self.rfile.read(int(self.headers.get('Content-Length', '0')))

    def do_PUT(self):
        data = self.body()
        # Validate the checksum independently of syq's code.
        assert self.headers['x-amz-checksum-sha256'] == base64.b64encode(hashlib.sha256(data).digest()).decode()
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if 'partNumber' in query:
            if CASE == 'upload-error':
                self.reply(403, b'<Error><Code>AccessDenied</Code></Error>')
                return
            number = int(query['partNumber'][0])
            if CASE == 'upload-retry':
                with LOCK:
                    attempts = STATE.setdefault('attempts', {})
                    attempt = attempts.get(number, 0)
                    attempts[number] = attempt + 1
                if not attempt:
                    self.reply(503, b'<Error><Code>SlowDown</Code></Error>')
                    return
            with LOCK: STATE['parts'][number] = data
            PART_UPLOADED.set()
        else:
            STATE['published'] = data
            STATE['completed'] = True
            STATE['metadata'] = {k.lower(): v for k, v in self.headers.items() if k.lower().startswith('x-amz-meta-')}
        self.reply(200, headers={'ETag': '"part"', 'x-amz-checksum-sha256': self.headers['x-amz-checksum-sha256']})

    def do_POST(self):
        body = self.body()
        if 'uploadId=' in self.path:
            STATE['published'] = b''.join(STATE['parts'][n] for n in sorted(STATE['parts']))
            STATE['completed'] = True
            self.reply(200, b'<CompleteMultipartUploadResult><ETag>"done"</ETag></CompleteMultipartUploadResult>')
        else:
            STATE['metadata'] = {k.lower(): v for k, v in self.headers.items() if k.lower().startswith('x-amz-meta-')}
            self.reply(200, b'<InitiateMultipartUploadResult><UploadId>owned</UploadId></InitiateMultipartUploadResult>')

    def do_DELETE(self):
        STATE['aborts'] += 1
        self.reply(204)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def descriptor_command(command):
    command = list(command)
    if '--to' in command and any(flag in command for flag in ('--src', '--src-non-dir')):
        return command
    if '--to' in command:
        if '--src-fd' in command:
            index = command.index('--src-fd')
            fd = command[index + 1]
            del command[index:index + 2]
        else:
            fd = '0'
        command[2:2] = ['--src-fd', fd]
    elif '--as-fd' not in command:
        command += ['--as-fd', '1']
    return command


def run(command, **kwargs):
    return subprocess.run(descriptor_command(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, **kwargs)


def success(result):
    assert result.returncode == 0, result.stderr.decode(errors='replace')


def failure(result):
    assert result.returncode != 0, result


def spawn(*args, **kwargs):
    child = subprocess.Popen(descriptor_command(args[0]), *args[1:], **kwargs, start_new_session=True)
    CHILDREN.append(child)
    return child


def stop(child):
    child.send_signal(signal.SIGTERM)
    try:
        _, error = child.communicate(timeout=8)
        assert child.returncode != 0, error
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        raise AssertionError('stream failed to cancel')


with tempfile.TemporaryDirectory(prefix='syq-stream-') as temp, Server(('127.0.0.1', 0), Handler) as server:
    # macOS TMPDIR may traverse /var, which native source paths reject.
    temp = str(Path(temp).resolve())
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    env = {k: v for k, v in os.environ.items() if not k.startswith(('AWS_', 'SYQ_'))}
    env.update(AWS_ACCESS_KEY_ID='test-access', AWS_SECRET_ACCESS_KEY='test-secret',
               AWS_EC2_METADATA_DISABLED='true', AWS_CONFIG_FILE=os.devnull,
               AWS_SHARED_CREDENTIALS_FILE=os.devnull, HOME=temp)
    base = [SYQ, 'cp', '--s3-endpoint', f'http://127.0.0.1:{server.server_port}',
            '--s3-region', 'us-east-1', '--performance-tuning',
            's3-part-size=5M,s3-parts-per-object=2,s3-retries=1']
    get = base + ['--from', 's3://bucket', 'object']
    put = base + ['--to', 's3://bucket', '--as', 'object']
    try:
        if CASE == 'mapping-callbacks':
            import syq
            sdk = syq.Client(executable=SYQ, env=env, timeout=15)
            options = dict(s3_endpoint=f'http://127.0.0.1:{server.server_port}', s3_region='us-east-1',
                           performance_tuning='s3-part-size=5M,s3-parts-per-object=2,s3-retries=0',
                           resource_limits='s3-requests=1')
            def produce(out):
                out.write(DATA)
            for payload in (b'', b'bytes', DATA):
                result = sdk.cp(mapping=[syq.MappingEntry(syq.StreamSource(lambda out: out.write(payload), size=len(payload)), 'object',
                    metadata=syq.DestinationMetadata(mode=0o640, mtime=123, mtime_nsec=456))], to='s3://bucket', into='.', **options)
                assert result.bytes_transferred == len(payload), result
                assert STATE['published'] == payload
                assert STATE['metadata']['x-amz-meta-syq-mode'] == str(0o640), STATE['metadata']
            values = []
            result = sdk.cp(mapping=[syq.MappingEntry('object', syq.StreamDestination(lambda inp: values.append(inp.read()))) for _ in range(4)],
                            from_='s3://bucket', stream_concurrency=4, **options)
            assert values == [DATA] * 4, [len(v) for v in values]
            assert result.bytes_transferred == len(DATA) * 4
            before = STATE['aborts']
            result = sdk.cp(mapping=[syq.MappingEntry(syq.StreamSource(produce), 'object', expected_hash=syq.Hash('sha256', '0' * 64))],
                            to='s3://bucket', into='.', check=False, **options)
            assert result.exit_code == 23 and STATE['aborts'] == before + 1, result
            assert STATE['published'] == DATA
            def late_failure(out):
                out.write(DATA)
                raise ValueError('archive producer failed')
            try:
                sdk.cp(mapping=[syq.MappingEntry(syq.StreamSource(late_failure), 'object')], to='s3://bucket', into='.', **options)
            except ValueError as error:
                assert str(error) == 'archive producer failed'
            else:
                raise AssertionError('callback failure disappeared')
            assert STATE['published'] == DATA
            CASE = 'truncated'
            values = []
            result = sdk.cp(mapping=[syq.MappingEntry('object', syq.StreamDestination(lambda inp: values.append(inp.read())))],
                            from_='s3://bucket', check=False, **options)
            assert result.exit_code == 23 and values == [], result
            CASE = 'mapping-callbacks'

        elif CASE == 'preview-results':
            results = Path(temp) / 'download.json'
            response = run(get + ['--dry-run', '--results', str(results)], env=env)
            success(response)
            assert not response.stdout
            assert not STATE['gets']
            records = [json.loads(line) for line in results.read_text().splitlines()]
            assert records[-1]['bytes_transferred'] == len(DATA)
            assert records[-1]['bytes_total_known'] is True
            fifo = Path(temp) / 'pipe'
            os.mkfifo(fifo)
            results = Path(temp) / 'upload.json'
            response = run(base + ['--src', str(fifo), '--to', 's3://bucket', '--as', 'object',
                                  '--dry-run', '--results', str(results)], env=env)
            success(response)
            records = [json.loads(line) for line in results.read_text().splitlines()]
            assert records[-1]['bytes_total_known'] is False
            assert not STATE['completed'] and not STATE['parts']
            for flag, key in [('--only-new', 'object'), ('--only-existing', 'missing')]:
                results = Path(temp) / (flag + '.json')
                response = run(base + ['--src', str(fifo), '--to', 's3://bucket', '--as', key,
                                      flag, '--results', str(results)], env=env)
                success(response)
                records = [json.loads(line) for line in results.read_text().splitlines()]
                assert records[-1]['files_excluded'] == 1
                assert not STATE['completed'] and not STATE['parts']
            response = run(put + ['--only-existing'], input=b'updated', env=env)
            success(response)
            assert STATE['published'] == b'updated'
            response = run(base + ['--to', 's3://bucket', '--as', 'missing', '--only-new'],
                           input=b'created', env=env)
            success(response)
            assert STATE['published'] == b'created'

        elif CASE == 'file-metadata':
            source = Path(temp) / 'source'
            stamp = 1_600_000_000_123_456_789
            for payload in (b'short', DATA):
                source.write_bytes(payload)
                source.chmod(0o751)
                os.utime(source, ns=(stamp, stamp))
                with source.open('rb') as stream:
                    response = run(put, stdin=stream, env=env)
                success(response)
                assert STATE['published'] == payload
                # A file can inherit its directory's group, independently of
                # the process's effective group (for example on macOS).
                source_meta = source.stat()
                # Existing version-1 format; no digest or new metadata fields.
                stored = {'x-amz-meta-syq-format': '1', 'x-amz-meta-syq-kind': 'file',
                          'x-amz-meta-syq-mode': str(0o751),
                          'x-amz-meta-syq-uid': str(source_meta.st_uid),
                          'x-amz-meta-syq-gid': str(source_meta.st_gid),
                          'x-amz-meta-syq-mtime': '1600000000',
                          'x-amz-meta-syq-mtime-nsec': '123456789'}
                assert STATE['metadata'] == stored, STATE['metadata']
            output_path = Path(temp) / 'output'
            with output_path.open('w+b') as output:
                for preserve in ([], ['--preserve=permissions,ownership'], ['--preserve=times']):
                    output.seek(0)
                    os.fchmod(output.fileno(), 0o600)
                    os.utime(output.fileno(), ns=(stamp, stamp))
                    response = run(get + ['--as-fd', str(output.fileno()), *preserve],
                                   pass_fds=(output.fileno(),), env=env)
                    success(response)
                    assert output_path.read_bytes() == DATA
                    meta = os.fstat(output.fileno())
                    if preserve == ['--preserve=times']:
                        assert meta.st_mtime_ns == stamp, meta.st_mtime_ns
                    else:
                        assert meta.st_mtime_ns > stamp, meta.st_mtime_ns
                    expected_mode = 0o751 if preserve == ['--preserve=permissions,ownership'] else 0o600
                    assert meta.st_mode & 0o7777 == expected_mode
                output.seek(0)
                os.utime(output.fileno(), ns=(stamp, stamp + 2_000_000_000))
                before = dict(STATE['gets'])
                requests = STATE['requests']
                response = run(get + ['--as-fd', str(output.fileno()), '--skip-newer'],
                               pass_fds=(output.fileno(),), env=env)
                assert response.returncode == 2, response.stderr
                assert b'--skip-newer cannot be used with --as-fd' in response.stderr
                assert b'use --as PATH' in response.stderr
                assert output.tell() == 0 and STATE['gets'] == before
                assert STATE['requests'] == requests and output_path.read_bytes() == DATA
            STATE['metadata']['x-amz-meta-syq-mtime'] = '1600000002'
            for preview in ([], ['--dry-run']):
                with source.open('rb') as stream:
                    response = run(put + ['--skip-newer', *preview], stdin=stream, env=env)
                    success(response)
                    assert b'Skipped' in response.stderr and stream.tell() == 0
            # Timestamp selection concerns the exact object. A sibling prefix
            # must neither add a LIST nor prevent creation of that object.
            source.write_bytes(b'prefix can coexist')
            STATE.update(missing_object=True, prefix_exists=True)
            for options in ([], ['--skip-newer']):
                requests = STATE['requests']
                lists = STATE.get('lists', 0)
                with source.open('rb') as stream:
                    response = run(put + options, stdin=stream, env=env)
                success(response)
                assert STATE['published'] == b'prefix can coexist'
                assert STATE['requests'] - requests == int(bool(options))
                assert STATE.get('lists', 0) == lists
            # An explicit placement condition still checks the prefix and
            # fails without consuming the source.
            with source.open('rb') as stream:
                response = run(base + ['--to', 's3://bucket', '--as-new', 'object', '--skip-newer'], stdin=stream, env=env)
                failure(response)
                assert b'existence condition failed' in response.stderr
                assert stream.tell() == 0
            STATE.update(missing_object=False, prefix_exists=False)
            # Plain output ignores metadata, including unfamiliar formats,
            # whether stdout is a pipe or an already-open regular file.
            for metadata in ({}, {'x-amz-meta-syq-format': 'unknown'}):
                STATE['metadata'] = metadata
                response = run(get, env=env)
                success(response)
                assert response.stdout == DATA
                with output_path.open('w+b') as output:
                    response = run(get + ['--as-fd', str(output.fileno())],
                                   pass_fds=(output.fileno(),), env=env)
                    success(response)
                    assert output_path.read_bytes() == DATA
                    assert os.fstat(output.fileno()).st_mtime_ns > stamp
            with output_path.open('w+b') as output:
                before = dict(STATE['gets'])
                response = run(get + ['--as-fd', str(output.fileno()), '--preserve=times'],
                               pass_fds=(output.fileno(),), env=env)
                failure(response)
                assert not output_path.read_bytes() and STATE['gets'] == before
            # Explicit time preservation falls back to Last-Modified for objects
            # without syq attributes.
            STATE['metadata'] = {}
            with output_path.open('w+b') as output:
                response = run(get + ['--as-fd', str(output.fileno()), '--preserve=times'],
                               pass_fds=(output.fileno(),), env=env)
                success(response)
                assert os.fstat(output.fileno()).st_mtime_ns == 1_600_000_000_000_000_000
            fifo = Path(temp) / 'pipe'
            os.mkfifo(fifo)
            before = STATE['requests']
            response = run(base + ['--src', str(fifo), '--to', 's3://bucket', '--as', 'object', '--skip-newer'], env=env)
            failure(response)
            assert b'regular-file source timestamp' in response.stderr
            assert STATE['requests'] == before

        elif CASE == 'size-filters':
            # Removed native options must fail before reading payload or contacting S3.
            for command in (get, put):
                for option in ('--min-size=1', '--max-size=1'):
                    before = STATE['requests']
                    response = run(command + [option], input=b'unread', env=env)
                    assert response.returncode == 2, response.stderr
                    assert b'unexpected argument' in response.stderr
                    assert STATE['requests'] == before

        elif CASE in ('download', 'retry', 'bad-range', 'truncated'):
            STATE['bad'] = 'etag'
            result = run(get, env=env)
            if CASE in ('bad-range', 'truncated'):
                failure(result)
                assert not result.stdout
                if CASE == 'bad-range':
                    STATE['bad'] = 'range'
                    failure(run(get, env=env))
                else:
                    assert STATE['gets'][0] == 2
            else:
                success(result)
                assert result.stdout == DATA
                if CASE == 'retry': assert STATE['gets'] == {0: 2, PART: 1}, STATE['gets']
                with open(Path(temp) / 'output', 'w+b') as output:
                    output.write(b'prefix')
                    output.flush()
                    result = run(get + ['--as-fd', str(output.fileno())], env=env, pass_fds=(output.fileno(),))
                    success(result)
                    assert result.stdout == b''
                    output.seek(0)
                    assert output.read() == b'prefix' + DATA
        elif CASE in ('upload', 'upload-retry'):
            for data in (b'', b'binary\x00\xff', DATA, DATA[:PART]):
                STATE['parts'] = {}
                STATE['attempts'] = {}
                STATE['completed'] = False
                result = run(put, input=data, env=env)
                success(result)
                assert result.stdout == b''
                assert STATE['published'] == data
            with open(Path(temp) / 'input', 'w+b') as source:
                source.write(b'skip' + DATA)
                source.seek(4)
                result = run(put + ['--src-fd', str(source.fileno())], env=env, pass_fds=(source.fileno(),))
                success(result)
                assert STATE['published'] == DATA
        elif CASE == 'upload-error':
            result = run(put, input=DATA, env=env)
            failure(result)
            assert STATE['aborts'] == 1
            assert not STATE['completed']
        elif CASE == 'cancel':
            child = spawn(put, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            # Leave the pipe open after a full part; upload must progress without EOF.
            writer = threading.Thread(target=lambda: (child.stdin.write(DATA[:PART]), child.stdin.flush()), daemon=True)
            writer.start()
            assert PART_UPLOADED.wait(10), 'upload did not overlap input production'
            assert not STATE['completed']
            # communicate() would close stdin and turn cancellation into ordinary EOF.
            held_input = child.stdin
            child.stdin = None
            stop(child)
            held_input.close()
            writer.join(2)
            assert STATE['aborts'] == 1
            child = spawn(get, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            assert child.stdout.read(1) == DATA[:1]
            held_output = child.stdout
            child.stdout = None
            stop(child)
            held_output.close()
        elif CASE == 'descriptor-flags':
            for upload in (True, False):
                for nonblocking in (False, True):
                    for sig in (signal.SIGTERM, signal.SIGKILL):
                        shared, peer = socket.socketpair()
                        with shared, peer:
                            shared.setblocking(not nonblocking)
                            peer.settimeout(15)
                            # Darwin exposes its kernel FWASWRITTEN bookkeeping
                            # bit through F_GETFL after write(2) returns. Prime it
                            # before the snapshot, retaining the full comparison.
                            os.write(shared.fileno(), b'x')
                            assert peer.recv(1) == b'x'
                            original = fcntl.fcntl(shared, fcntl.F_GETFL)
                            PART_UPLOADED.clear()
                            child = spawn(put if upload else get,
                                          stdin=shared if upload else subprocess.DEVNULL,
                                          stdout=subprocess.DEVNULL if upload else shared,
                                          stderr=subprocess.PIPE, env=env)
                            if upload:
                                peer.sendall(DATA[:PART])
                                assert PART_UPLOADED.wait(10), 'upload did not start'
                            else:
                                assert peer.recv(1) == DATA[:1], 'download did not start'
                            actual = fcntl.fcntl(shared, fcntl.F_GETFL)
                            assert actual == original, (upload, nonblocking, sig, hex(original), hex(actual))
                            aborts = STATE['aborts']
                            child.send_signal(sig)
                            _, error = child.communicate(timeout=8)
                            assert child.returncode != 0, error
                            if upload and sig == signal.SIGTERM:
                                assert STATE['aborts'] == aborts + 1
                            actual = fcntl.fcntl(shared, fcntl.F_GETFL)
                            assert actual == original, (upload, nonblocking, sig, hex(original), hex(actual))
        elif CASE == 'environment-options':
            # Quoted keys and endpoint options must reach the stream parser.
            configured = env | {'SYQ_CP_OPTIONS': shlex.join(base[2:] + ['--src-fd', '0', '--to', 's3://bucket', '--as', 'key with spaces'])}
            result = subprocess.run([SYQ, 'cp'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, input=b'from environment', env=configured)
            success(result)
            assert STATE['published'] == b'from environment'
            configured['SYQ_CP_OPTIONS'] = "--as 'unterminated"
            result = run(put, input=b'', env=configured)
            assert result.returncode == 2
            assert b'SYQ_CP_OPTIONS is not a valid shell word list' in result.stderr
            # Existing commands reject duplicate scalar options; stream does too.
            configured['SYQ_CP_OPTIONS'] = '--as other'
            result = run(put, input=b'', env=configured)
            assert result.returncode == 2
        elif CASE == 'managed-commit':
            for data in (b'', b'small', DATA):
                for commit in (b'', b'X', b'C'):
                    STATE.pop('published', None)
                    STATE['completed'] = False
                    read_fd, write_fd = os.pipe()
                    os.write(write_fd, commit)
                    os.close(write_fd)
                    try:
                        result = run(put + ['--stream-commit-fd', str(read_fd)],
                                     input=data, pass_fds=(read_fd,), env=env)
                    finally:
                        os.close(read_fd)
                    if commit == b'C':
                        success(result)
                        assert STATE.get('published') == data
                    else:
                        failure(result)
                        assert 'published' not in STATE
                        assert not STATE['completed']
            assert STATE['aborts'] >= 2
        elif CASE == 'pipe-sources':
            for selector in ('--src', '--src-non-dir'):
                fifo = Path(temp) / ('fifo' + selector)
                os.mkfifo(fifo)
                writer = subprocess.Popen([sys.executable, '-c',
                    'import sys; open(sys.argv[1], "wb").write(b"named pipe")', str(fifo)],
                    start_new_session=True)
                CHILDREN.append(writer)
                success(run(base + [selector, str(fifo), '--to', 's3://bucket', '--into', 'prefix'], env=env))
                assert writer.wait(timeout=5) == 0
                assert STATE['published'] == b'named pipe'
            result = subprocess.run(['bash', '-c',
                'exec "$@" --src <(printf "substitution") --to s3://bucket --as object',
                'pipe-source-test', *base], env=env, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=15)
            success(result)
            assert STATE['published'] == b'substitution'
            before = STATE['requests']
            child = spawn(base + ['--src', str(fifo), '--to', 's3://bucket', '--as', 'object'],
                          stderr=subprocess.PIPE, env=env)
            time.sleep(.2)
            child.send_signal(signal.SIGTERM)
            child.communicate(timeout=10)
            assert child.returncode != 0
            assert STATE['requests'] == before
        elif CASE == 'descriptors':
            result = run(get + ['--as-fd', '99999'], env=env)
            failure(result)
            assert STATE['requests'] == 0
            with open(os.devnull, 'rb') as source:
                failure(run(get + ['--as-fd', str(source.fileno())], env=env, pass_fds=(source.fileno(),)))
            child = spawn(get, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            child.stdout.close()
            child.stdout = None
            _, error = child.communicate(timeout=15)
            assert child.returncode != 0, error
        else: raise AssertionError(CASE)
    finally:
        for child in CHILDREN:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
            for file in (child.stdin, child.stdout, child.stderr):
                if file and not file.closed: file.close()
        server.shutdown()
        worker.join(3)
print(CASE, 'passed')
