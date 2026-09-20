"""Run mixed pathname/callback storage copies from the credential-free worker."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys

spec = importlib.util.spec_from_file_location('channel', '/usr/local/libexec/syq-test-stream-mappings.py')
channel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(channel)
root = Path('/tmp/syq-storage-authorization')
os.chdir(root)
mode = sys.argv[1]
upload = mode != 'download'
payload = (root/'source').read_bytes()
entries = [dict(src=channel.path('source' if upload else 'ordinary'), dst=channel.path('ordinary'))]
for index, name in [(1, 'known'), (2, 'unknown')]:
    callback = dict(stream=index)
    if upload and index == 1:
        callback['size'] = len(payload)
    entries.append(dict(src=callback if upload else channel.path(name),
                        dst=channel.path(name) if upload else callback))
manifest = root/'callback-manifest'
manifest.write_text(''.join(json.dumps(entry)+'\n' for entry in entries))
left, right = socket.socketpair()
left.settimeout(60)
with left, right:
    process = subprocess.Popen([*sys.argv[2:4], '--mapping', str(manifest),
                                '--stream-mapping-fd', str(right.fileno()), *sys.argv[4:]],
                               pass_fds=(right.fileno(),), start_new_session=True)
    right.close()
    jobs = []
    started = set()
    def transfer(index, descriptors):
        data_fd, commit_fd = descriptors
        with os.fdopen(data_fd, 'wb' if upload else 'rb') as data, os.fdopen(commit_fd, 'wb') as commit:
            if upload:
                data.write(payload)
            else:
                assert data.read() == payload
            data.close()
            if not (mode == 'abort' and index == 1):
                commit.write(b'C')
    try:
        hello, fds = channel.receive(left)
        assert hello == dict(type='hello', version=1) and not fds
        answer = b'{"version":1}'
        left.sendall(b'S' + struct.pack('!I', len(answer)) + answer)
        with ThreadPoolExecutor(max_workers=2) as pool:
            while True:
                message, fds = channel.receive(left)
                if message['type'] == 'end':
                    assert not fds
                    break
                index = message['entry']
                assert index in (1, 2), message
                if message['type'] == 'start':
                    assert index not in started and len(fds) == 2, message
                    started.add(index)
                    jobs.append(pool.submit(transfer, index, fds))
                else:
                    assert message['type'] == 'transferred' and not fds, message
                    assert bool(message['error']) == (mode == 'abort' and index == 1), message
            for job in jobs:
                job.result(timeout=10)
        status = process.wait(timeout=15)
        assert started == {1, 2}, started
        assert status == (23 if mode == 'abort' else 0), status
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
sys.exit(status)
