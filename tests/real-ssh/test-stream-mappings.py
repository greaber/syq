#!/usr/bin/env python3
"""Exercise the public subprocess contract without a language SDK."""
from array import array
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile


def exact(channel, size):
    data = bytearray()
    while len(data) < size:
        part = channel.recv(size - len(data))
        assert part, 'truncated control message'
        data.extend(part)
    return data


def receive(channel):
    marker, ancillary, flags, _ = channel.recvmsg(1, socket.CMSG_SPACE(8))
    descriptors = array('i')
    for level, kind, data in ancillary:
        assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
        descriptors.frombytes(data)
    for fd in descriptors:
        os.set_inheritable(fd, False)
    assert marker == b'S' and not flags & socket.MSG_CTRUNC
    length, = struct.unpack('!I', exact(channel, 4))
    assert 0 < length <= 65536
    return json.loads(exact(channel, length)), descriptors


def path(name):
    return dict(encoding='utf-8', value=name)


def run(directory, upload, options, payloads, *, abort=False, skipped=False):
    manifest = directory / 'manifest'
    manifest.write_text(''.join(json.dumps(dict(src=dict(stream=i) if upload else path(str(i)),
                                                 dst=path(str(i)) if upload else dict(stream=i))) + '\n'
                                for i in range(len(payloads))))
    left, right = socket.socketpair()
    left.settimeout(30)
    with left, right, tempfile.TemporaryFile() as results, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(['syq', 'cp', '--mapping', str(manifest),
                                    '--stream-mapping-fd', str(right.fileno()),
                                    '--results-fd', str(results.fileno()),
                                    '--stream-concurrency', '2', *options],
                                   pass_fds=(right.fileno(), results.fileno()),
                                   stdout=subprocess.DEVNULL, stderr=errors, start_new_session=True, env=dict(os.environ, SYQ_DEBUG='1'))
        right.close()
        started, completed, jobs = set(), set(), []
        def worker(index, descriptors):
            data_fd, commit_fd = descriptors
            with os.fdopen(data_fd, 'wb' if upload else 'rb') as data, os.fdopen(commit_fd, 'wb') as commit:
                if upload:
                    data.write(payloads[index])
                else:
                    assert data.read() == payloads[index]
                data.close()
                if not abort:
                    commit.write(b'C')
        try:
            hello, fds = receive(left)
            assert hello == dict(type='hello', version=1) and not fds
            answer = b'{"version":1}'
            left.sendall(b'S' + struct.pack('!I', len(answer)) + answer)
            with ThreadPoolExecutor(max_workers=2) as pool:
                while True:
                    message, fds = receive(left)
                    if message['type'] == 'end':
                        assert not fds
                        break
                    index = message['entry']
                    assert 0 <= index < len(payloads)
                    if message['type'] == 'start':
                        assert index not in started and len(fds) == 2
                        assert message['direction'] == ('produce' if upload else 'consume')
                        started.add(index)
                        jobs.append(pool.submit(worker, index, fds))
                    else:
                        assert message['type'] == 'transferred' and not fds
                        assert index in started and index not in completed
                        completed.add(index)
                        assert bool(message['error']) == abort, message
                for job in jobs:
                    job.result(timeout=10)
            code = process.wait(timeout=15)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, 9)
                process.wait()
        errors.seek(0)
        diagnostic = errors.read()
        assert code == (23 if abort else 0), diagnostic
        assert len(started) == (0 if skipped else len(payloads)), started
        results.seek(0)
        records = [json.loads(line) for line in results]
        assert all(r['schema_version'] == 3 and r['seq'] == i for i, r in enumerate(records))
        assert records[-1]['type'] == 'result' and records[-1]['exit_code'] == code
        streams = [r for r in records if r['type'] == 'stream_result']
        assert len(streams) == len(payloads)
        assert all(r['disposition'] == ('failed' if abort else 'skipped' if skipped else 'succeeded') for r in streams)
        return diagnostic


def main():
    host = os.environ.get('SYQ_TEST_STREAM_HOST', 'destination')
    payloads = [bytes([i]) * (1024 * 1024 + i) for i in range(4)]
    with tempfile.TemporaryDirectory(prefix='syq-stream-mapping-') as temp:
        directory = Path(temp)
        for name, transport in [('tcp', []), ('ssh', ['--no-tcp'])]:
            prefix = '/tmp/syq-stream-mapping-' + name
            common = ['--no-progress', '--performance-tuning=workers=2', '-vv', *transport]
            upload = ['--to', host, '--into', prefix, *common]
            download = ['--from', host, '--cwd', prefix, '--into', '.', *common]
            for options, sending in [(upload, True), (download, False)]:
                diagnostic = run(directory, sending, options, payloads)
                expected = b'EncryptedTcp' if name == 'tcp' else b'Ssh'
                # A short entry can finish before its second worker gets shared
                # capacity. It must not open a connection merely to retire it.
                ready = diagnostic.count(b'ready (' + expected + b')')
                assert len(payloads) <= ready <= 2 * len(payloads), diagnostic
                if name == 'tcp':
                    assert diagnostic.count(b'data connection via tcp ') == 2, diagnostic
            run(directory, True, upload + ['--only-new'], payloads, skipped=True)
            run(directory, True, upload, [b'partial'], abort=True)
            run(directory, False, download, payloads)
            print('PASS: shared stream mappings, skip, and failed publication over ' + name, flush=True)


if __name__ == '__main__':
    main()
