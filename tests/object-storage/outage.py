#!/usr/bin/env python3
"""An outage partway through a copy: syq stops, and a rerun finishes the copy.

A local TCP proxy carries syq's requests to the S3 server. While it is down,
it drops every connection, as an unreachable service would.
"""
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import check as c


class Proxy:
    def __init__(self, endpoint):
        target = urllib.parse.urlsplit(endpoint)
        self.target = (target.hostname, target.port)
        self.listener = socket.create_server(('127.0.0.1', 0))
        self.endpoint = f'http://127.0.0.1:{self.listener.getsockname()[1]}'
        self.lock = threading.Lock()
        self.down = False
        self.sockets = set()
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            try:
                upstream = socket.create_connection(self.target)
            except OSError:
                client.close()
                continue
            with self.lock:
                if self.down:
                    client.close()
                    upstream.close()
                    continue
                self.sockets.update((client, upstream))
            for source, sink in ((client, upstream), (upstream, client)):
                threading.Thread(target=self.pump, args=(source, sink), daemon=True).start()

    @staticmethod
    def pump(source, sink):
        try:
            while data := source.recv(65536):
                sink.sendall(data)
        except OSError:
            pass
        finally:
            for end in (source, sink):
                try:
                    end.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def fail(self):
        with self.lock:
            self.down = True
            sockets, self.sockets = self.sockets, set()
        for end in sockets:
            try:
                end.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def recover(self):
        with self.lock:
            self.down = False

    def close(self):
        self.fail()
        self.listener.close()


def records(reader, process, deadline):
    """Yield results records as the copy writes them."""
    selector = selectors.DefaultSelector()
    selector.register(reader, selectors.EVENT_READ)
    pending = b''
    try:
        while True:
            assert time.monotonic() < deadline, 'outage check deadline expired'
            for _ in selector.select(timeout=1):
                block = os.read(reader, 65536)
                if not block:
                    return
                pending += block
                while b'\n' in pending:
                    line, pending = pending.split(b'\n', 1)
                    yield json.loads(line)
    finally:
        selector.close()


def check():
    with tempfile.TemporaryDirectory(prefix='syq-s3-outage-') as temp:
        root = Path(temp).resolve()
        os.environ['XDG_CACHE_HOME'] = str(root / 'cache')
        source = root / 'source'
        source.mkdir()
        count = 1000
        contents = {f'f{n:04}': f'object {n}\n'.encode() * 100 for n in range(count)}
        for name, data in contents.items():
            (source / name).write_bytes(data)
        destination = c.PREFIX + '/outage'
        proxy = Proxy(c.ENDPOINT)
        # One object at a time, with one retry each, so that eight requests
        # run out of retries quickly once the outage starts; a bandwidth limit
        # keeps the copy running long enough to start the outage partway.
        command = [c.SYQ, 'cp', '--no-progress', '--s3-retries=1',
                   '--performance-tuning=s3-objects=1',
                   '--resource-limits=bandwidth=200KiB',
                   '--srcs-in', source, '--to', 's3://' + c.BUCKET, '--into', destination]
        for name, value in c.HEADERS.items():
            command += ['--s3-header', name + ': ' + value]
        reader, writer = os.pipe()
        process = subprocess.Popen(
            list(map(str, command)) + ['--results-fd', str(writer)],
            env={**os.environ, 'AWS_ENDPOINT_URL_S3': proxy.endpoint},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            pass_fds=(writer,), start_new_session=True)
        os.close(writer)
        output = []
        threading.Thread(target=lambda: output.append(process.communicate()), daemon=True).start()
        stream = []
        failed = None
        try:
            for record in records(reader, process, time.monotonic() + 120):
                stream.append(record)
                if failed is None and record['type'] == 'progress' and record['files_done'] >= 20:
                    proxy.fail()
                    failed = time.monotonic()
            process.wait(timeout=60)
        finally:
            os.close(reader)
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=15)
            proxy.close()
        deadline = time.monotonic() + 15
        while not output and time.monotonic() < deadline:
            time.sleep(.05)
        _, stderr = output[0]
        assert failed, stderr
        # Eight requests in a row ran out of retries, and the copy stopped
        # instead of trying the remaining objects.
        assert process.returncode == 1, (process.returncode, stderr)
        assert '8 S3 requests in a row failed after all their retries' in stderr, stderr
        outcomes = [r for r in stream if r['type'] == 'operation_result']
        named = lambda disposition: {r['dst']['value'] for r in outcomes
                                     if r['disposition'] == disposition}
        failures, copied = named('failed'), named('succeeded')
        # The copy stops at the eighth; a stopping copy does not report the
        # object it was copying as failed.
        assert 1 <= len(failures) <= 8, failures
        assert len(copied) + len(failures) < count, len(outcomes)
        terminal = stream[-1]
        assert terminal['type'] == 'result' and terminal['status'] == 'failed', terminal
        # Every object reported as copied is there. One reported as failed
        # may be too: dropping its connection can lose the answer to an
        # upload that succeeded.
        listed = set(c.listing(destination + '/'))
        assert copied <= listed, sorted(copied - listed)
        assert listed <= copied | failures, sorted(listed - copied - failures)
        # The rerun the stop asks for copies the rest; then every object is
        # there with its contents.
        c.run(['--srcs-in', source, '--to', 's3://' + c.BUCKET, '--into', destination])
        keys = c.listing(destination + '/')
        assert sorted(keys) == sorted(f'{destination}/{name}' for name in contents), len(keys)
        for name, data in contents.items():
            _, body = c.request('GET', destination + '/' + name)
            assert body == data, name
        print('S3 outage checks passed: stopped, and the rerun copied the rest', flush=True)


if __name__ == '__main__':
    try:
        check()
    finally:
        c.clean()
