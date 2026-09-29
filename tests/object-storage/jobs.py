#!/usr/bin/env python3
"""Named S3 job retries preserve scope and count deletions across attempts."""
import json
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import urllib.request
import urllib.error
import os
from pathlib import Path
import subprocess
import tempfile
import check as c


def run(root, command, args, ok=True, endpoint=None):
    result = subprocess.run([c.SYQ, command, '--no-progress', *map(str, args)],
        env={**os.environ, 'XDG_CACHE_HOME': str(root/'cache'), **({'AWS_ENDPOINT_URL_S3': endpoint} if endpoint else {})},
        text=True, capture_output=True, timeout=60)
    assert (result.returncode == 0) == ok, (result.args, result.returncode, result.stdout, result.stderr)
    return result


def token(path):
    return json.loads(path.read_text().splitlines()[0])['job_id']


def cp(root, args, ok=True):
    return run(root, 'cp', args, ok)


class DeleteFault(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def forward(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.command == 'POST' and self.server.reject and b'z-fail' in body:
            data = b'<Error><Code>AccessDenied</Code><Message>test refusal</Message></Error>'
            self.send_response(403)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        request = urllib.request.Request(c.ENDPOINT+self.path, method=self.command,
            data=body if self.command in ('POST', 'PUT') else None,
            headers=dict(self.headers.items()))
        try:
            response = urllib.request.urlopen(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read()
            self.send_response(response.status)
            for name, value in response.headers.items():
                if name.lower() not in ('connection', 'transfer-encoding', 'content-length'):
                    self.send_header(name, value)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            if self.command != 'HEAD': self.wfile.write(data)

    do_GET = do_HEAD = do_POST = do_DELETE = forward


def removal_retry(root, endpoint):
    prefix = c.PREFIX+'/jobs/removal/'
    keys = [prefix+f'{index:04}' for index in range(1000)] + [prefix+'z-fail']
    with ThreadPoolExecutor(max_workers=16) as workers:
        list(workers.map(lambda key: c.request('PUT', key, b'original'), keys))
    server = ThreadingHTTPServer(('127.0.0.1', 0), DeleteFault)
    server.reject = True
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    proxy = f'http://127.0.0.1:{server.server_port}'
    try:
        result = root/'removal.jsonl'
        run(root, 'rm', ['--on', endpoint, '--srcs-in', prefix, '--results', result], False, proxy)
        remaining = c.listing(prefix)
        assert remaining == [prefix+'z-fail'], remaining
        c.request('PUT', keys[0], b'replacement')
        server.reject = False
        run(root, 'rm', ['--resume', token(result)], endpoint=proxy)
        assert c.listing(prefix) == [keys[0]]
        assert c.request('GET', keys[0])[1] == b'replacement'
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root/'source'; src.mkdir(); (src/'file').write_text('payload')
        endpoint = 's3://' + c.BUCKET
        upload = c.PREFIX+'/jobs/upload'
        copied = c.PREFIX+'/jobs/copied'
        try:
            # Upload, server copy, and download all publish before the prune cap
            # fails. A retry must recognize their own protected outputs.
            for route in ['upload', 'server', 'download']:
                result = root/(route+'.jsonl')
                if route == 'upload':
                    c.request('PUT', upload+'/stale', b'stale')
                    args = ['--srcs-in', src, '--to', endpoint, '--into', upload]
                elif route == 'server':
                    c.request('PUT', copied+'/stale', b'stale')
                    args = ['--from', endpoint, '--srcs-in', upload, '--to', endpoint, '--into', copied]
                else:
                    dest = root/'destination'; dest.mkdir(); (dest/'stale').write_text('stale')
                    args = ['--from', endpoint, '--srcs-in', copied, '--into', dest]
                first = cp(root, [*args, '--prune', '--max-delete=0', '--if-exists=error', '--results', result], False)
                assert first.returncode == 25, first.stderr
                job = token(result)
                cp(root, ['--resume', job, '--max-delete=1'])
                cp(root, ['--resume', job], False)
            assert (root/'destination/file').read_text() == 'payload'
            # Newly created placement roots also survive the first attempt.
            newroot = root/'new'; result = root/'new.jsonl'
            # A missing source fails after another source has been copied.
            cp(root, ['--from', endpoint, '--src', copied+'/file', '--src', copied+'/missing',
                      '--into-new', newroot, '--if-exists=error', '--results', result], False)
            job = token(result)
            c.request('PUT', copied+'/missing', b'now present')
            cp(root, ['--resume', job])
            assert (newroot/'file').read_text() == 'payload'
            assert (newroot/'missing').read_text() == 'now present'
            # An invalid source fails before deletion; the saved rm command can
            # restart discovery when that selector is corrected externally.
            rmresult = root/'rm.jsonl'
            run(root, 'rm', ['--on', endpoint, '--src', copied, '--results', rmresult], False)
            run(root, 'rm', ['--resume', token(rmresult), '--srcs-in', copied], False)
            run(root, 'rm', ['--on', endpoint, '--srcs-in', copied])
            removal_retry(root, endpoint)
            print('S3 named copy/removal jobs passed', flush=True)
        finally:
            c.clean()


if __name__ == '__main__':
    main()
