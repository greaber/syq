"""What the local fake S3 servers share: one response per connection."""
import http.server

LIST_EMPTY = b'<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>'


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send_response(self, *args):
        super().send_response(*args)
        # The server closes every connection after one response. Say so: a
        # client that pools the connection may otherwise send its next
        # request just as the server closes, and see a broken pipe.
        self.send_header('Connection', 'close')
        self.close_connection = True

    def reply(self, code, data=b'', headers=None, length=None):
        """Send `data`, announcing `length` bytes when given instead."""
        self.send_response(code)
        self.send_header('Content-Length', str(len(data) if length is None else length))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command == 'HEAD':
            return
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def body(self):
        return self.rfile.read(int(self.headers.get('Content-Length', '0')))
