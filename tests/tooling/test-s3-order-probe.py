#!/usr/bin/env python3
"""The provider order probe tells byte order from other orders and skipped keys."""
from support import SCRIPTS

import http.server
import json
import os
import subprocess
import sys
import threading
import unittest
import urllib.parse


class Store:
    """Objects, listed in byte order, in Cloudflare R2's measured order
    (`r2`), or in byte order with Tigris's skip after a common prefix
    (`skip`)."""

    def __init__(self, mode):
        self.mode = mode
        self.objects = set()

    def position(self, key):
        data = key.encode()
        return data + b"9\xff" if self.mode == "r2" else data

    def items(self, prefix, delimiter):
        out = []
        for key in sorted((k for k in self.objects if k.startswith(prefix)), key=self.position):
            rest = key[len(prefix):]
            item = ("prefix", prefix + rest[:rest.index("/") + 1]) if delimiter and "/" in rest else ("key", key)
            if item not in out:
                out.append(item)
        return out

    def page(self, query):
        prefix = query.get("prefix", "")
        delimiter = "delimiter" in query
        items = self.items(prefix, delimiter)
        size = int(query.get("max-keys", "1000"))
        token = query.get("continuation-token")
        if token is not None:
            start = int(token)
            if self.mode == "skip" and delimiter and start and items[start - 1][0] == "prefix":
                skipped = ("key", items[start - 1][1][:-1] + "0")
                if skipped in items[start:]:
                    items.remove(skipped)
        elif "start-after" in query:
            after = self.position(query["start-after"])
            start = sum(1 for _, item in items if self.position(item) <= after)
        else:
            start = 0
        page = items[start:start + size]
        truncated = start + size < len(items)
        body = "<ListBucketResult><EncodingType>url</EncodingType>"
        body += f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>"
        if truncated:
            body += f"<NextContinuationToken>{start + size}</NextContinuationToken>"
        for kind, item in page:
            name = urllib.parse.quote(item, safe="/")
            body += (f"<Contents><Key>{name}</Key><Size>1</Size></Contents>" if kind == "key"
                     else f"<CommonPrefixes><Prefix>{name}</Prefix></CommonPrefixes>")
        return (body + "</ListBucketResult>").encode()


def serve(store):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def key(self):
            path = urllib.parse.urlsplit(self.path).path
            return urllib.parse.unquote(path.split("/", 2)[2]) if path.count("/") > 1 else ""

        def reply(self, code, body=b""):
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_PUT(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            store.objects.add(self.key())
            self.reply(200)

        def do_DELETE(self):
            store.objects.discard(self.key())
            self.reply(204)

        def do_HEAD(self):
            self.reply(200 if self.key() in store.objects else 404)

        def do_GET(self):
            query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query,
                                                keep_blank_values=True))
            self.reply(200, store.page(query))

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class ProbeTests(unittest.TestCase):
    def probe(self, mode):
        store = Store(mode)
        server = serve(store)
        try:
            env = dict(os.environ, AWS_ACCESS_KEY_ID="id", AWS_SECRET_ACCESS_KEY="secret")
            env.pop("AWS_SESSION_TOKEN", None)
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "s3-order-probe.py"), "--endpoint",
                 f"http://127.0.0.1:{server.server_address[1]}", "s3://bucket/base"],
                env=env, capture_output=True, text=True, timeout=120)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(store.objects, set(), "the probe deletes what it stored")
        report = json.loads(result.stdout)
        self.assertTrue(report["prefix"].startswith("base/syq-order-probe-"))
        return result.returncode, {name: check["pass"] for name, check in report["checks"].items()}

    def test_byte_order_passes(self):
        self.assertEqual(self.probe("bytes"), (0, {
            "flat-order": True, "start-after": True, "delimiter-pages": True,
            "distinct-forms": True}))

    def test_another_order_fails_order_and_start_after(self):
        code, checks = self.probe("r2")
        self.assertEqual(code, 1)
        self.assertFalse(checks["flat-order"])
        self.assertFalse(checks["start-after"])

    def test_a_key_skipped_after_a_common_prefix_fails_delimiter_pages(self):
        code, checks = self.probe("skip")
        self.assertEqual(code, 1)
        self.assertEqual(checks, {"flat-order": True, "start-after": True,
                                  "delimiter-pages": False, "distinct-forms": True})


if __name__ == "__main__":
    unittest.main()
