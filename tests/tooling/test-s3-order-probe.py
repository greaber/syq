#!/usr/bin/env python3
"""The provider order probe tells byte order from other orders and skipped keys."""
from support import SCRIPTS

import importlib.util

import http.server
import json
import os
import subprocess
import sys
import threading
import unittest
import unicodedata
import urllib.parse


spec = importlib.util.spec_from_file_location("probe", SCRIPTS / "s3-order-probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Store:
    """Objects, listed in byte order, in Cloudflare R2's measured order
    (`r2`), or in byte order with Tigris's skip after a common prefix
    (`skip`); hiding from listings a key below another stored key, as MinIO
    does (`hide`); storing the NFD spelling of a name as NFC (`merge`); or
    refusing keys that hold an emoji (`refuse`)."""

    def __init__(self, mode):
        self.mode = mode
        self.objects = set()

    def position(self, key):
        data = key.encode()
        return data + b"9\xff" if self.mode == "r2" else data

    def listed(self):
        if self.mode != "hide":
            return self.objects
        return {key for key in self.objects
                if not any(key.startswith(other + "/") for other in self.objects)}

    def items(self, prefix, delimiter):
        out = []
        for key in sorted((k for k in self.listed() if k.startswith(prefix)), key=self.position):
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
            key = self.key()
            if store.mode == "refuse" and "\U0001f600" in key:
                return self.reply(400, b"<Error><Code>InvalidObjectName</Code></Error>")
            if store.mode == "merge":
                key = unicodedata.normalize("NFC", key)
            store.objects.add(key)
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
        self.assertTrue(result.stdout, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["prefix"].startswith("base/syq-order-probe-"))
        self.report = report
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

    def test_a_key_stored_but_never_listed_fails_flat_order(self):
        code, checks = self.probe("hide")
        self.assertEqual(code, 1)
        self.assertFalse(checks["flat-order"])
        hidden = self.report["checks"]["flat-order"]["stored_but_never_listed"]
        self.assertTrue(hidden and all("/o/" in key for key in hidden), hidden)

    def test_merged_spellings_fail_distinct_forms(self):
        self.assertEqual(self.probe("merge"), (1, {
            "flat-order": True, "start-after": True, "delimiter-pages": True,
            "distinct-forms": False}))

    def test_refused_keys_are_reported_and_left_out(self):
        code, checks = self.probe("refuse")
        self.assertEqual(code, 0, checks)
        refused = self.report["refused"]
        self.assertTrue(refused)
        self.assertTrue(all(r["status"] == 400 and r["code"] == "InvalidObjectName" for r in refused))

    def test_every_small_page_size_ends_a_page_before_a_skippable_key(self):
        for size in probe.DELIMITER_PAGE_SIZES[:-1]:
            keys = set(probe.delimiter_keys(size))
            items = sorted(probe.expected_items(keys, f"d{size}/"), key=lambda item: item[1].encode())
            ends = [items[i] for i in range(size - 1, len(items) - 1, size)
                    if items[i][0] == "prefix" and items[i + 1] == ("key", items[i][1][:-1] + "0")]
            self.assertGreaterEqual(len(ends), 2, size)


if __name__ == "__main__":
    unittest.main()
