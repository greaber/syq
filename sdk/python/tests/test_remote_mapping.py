from __future__ import annotations

import asyncio
from contextlib import ExitStack
from dataclasses import replace
import http.server
import os
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.parse

import syq


class ObjectServer:
    """Two instances expose identical names with distinct bytes."""
    def __init__(self, content: bytes) -> None:
        self.requests: list[tuple[str, str, str | None]] = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, code, body=b"", headers=()):
                owner.requests.append((self.command, self.path, self.headers.get("X-Mapping-Source")))
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                for key, value in headers:
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_HEAD(self):
                if self.path != "/bucket/prefix/file":
                    self.reply(404)
                else:
                    self.reply(200, content, [("ETag", '"fixture"'),
                               ("Last-Modified", "Thu, 01 Jan 2026 00:00:00 GMT")])

            def do_GET(self):
                if "list-type=2" in self.path:
                    self.reply(200, ("<ListBucketResult><EncodingType>url</EncodingType>"
                        "<IsTruncated>false</IsTruncated><Contents><Key>prefix%2Ffile</Key>"
                        f"<Size>{len(content)}</Size></Contents></ListBucketResult>").encode())
                elif byte_range := self.headers.get("Range"):
                    start, end = map(int, byte_range.removeprefix("bytes=").split("-"))
                    self.reply(206, content[start:end + 1], [
                        ("ETag", '"fixture"'),
                        ("Content-Range", f"bytes {start}-{end}/{len(content)}"),
                    ])
                else:
                    self.reply(200, content, [("ETag", '"fixture"')])

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@unittest.skipUnless(os.environ.get("SYQ_CANDIDATE_EXECUTABLE"), "candidate binary required")
class RemoteMappingTests(unittest.TestCase):
    def test_source_endpoint_and_header_survive_sync_and_async_copy(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous), ExitStack() as stack:
                directory = stack.enter_context(tempfile.TemporaryDirectory())
                root = Path(directory).resolve()
                source = stack.enter_context(ObjectServer(b"source A"))
                other = stack.enter_context(ObjectServer(b"source B"))
                env = os.environ | {
                    "AWS_ACCESS_KEY_ID": "fixture", "AWS_SECRET_ACCESS_KEY": "fixture",
                    "AWS_REGION": "us-east-1",
                    "AWS_EC2_METADATA_DISABLED": "true", "AWS_ENDPOINT_URL_S3": other.endpoint,
                    "AWS_CONFIG_FILE": str(root / "no-config"),
                    "AWS_SHARED_CREDENTIALS_FILE": str(root / "no-credentials"),
                }
                for key in ("AWS_SESSION_TOKEN", "AWS_PROFILE"):
                    env.pop(key, None)
                options = dict(from_="s3://bucket", srcs_in="prefix", include=["size"],
                               s3_endpoint=source.endpoint, s3_region="us-east-1",
                               s3_header=iter(["X-Mapping-Source: A"]))
                client_options = dict(executable=os.environ["SYQ_CANDIDATE_EXECUTABLE"],
                                      process_cwd=root, env=env, timeout=10)
                def rename(entry):
                    self.assertEqual(entry.size, len(b"source A"))
                    return replace(entry, dst=syq.RelativePath("renamed"))
                if asynchronous:
                    async def copy():
                        producer = syq.AsyncClient(**client_options)
                        consumer = syq.AsyncClient(**client_options)
                        async with producer.map(**options) as mapping:
                            await consumer.cp(mapping=mapping.transform(rename), into="output")
                    asyncio.run(copy())
                else:
                    producer = syq.Client(**client_options)
                    consumer = syq.Client(**client_options)
                    with producer.map(**options) as mapping:
                        consumer.cp(mapping=mapping.transform(rename), into="output")
                self.assertEqual((root / "output/renamed").read_bytes(), b"source A")
                self.assertEqual(other.requests, [])
                self.assertTrue(any(method == "GET" and urllib.parse.urlsplit(path).path == "/bucket/prefix/file"
                                    for method, path, _ in source.requests))
                self.assertTrue(all(header == "A" for _, _, header in source.requests))

    def test_s3_path_entries_share_a_manifest_with_callback_entries(self):
        with tempfile.TemporaryDirectory() as directory, ObjectServer(b"source bytes") as source:
            root = Path(directory).resolve()
            env = os.environ | {
                "AWS_ACCESS_KEY_ID": "fixture", "AWS_SECRET_ACCESS_KEY": "fixture",
                "AWS_EC2_METADATA_DISABLED": "true",
                "AWS_CONFIG_FILE": str(root / "no-config"),
                "AWS_SHARED_CREDENTIALS_FILE": str(root / "no-credentials"),
                "XDG_CACHE_HOME": str(root / "cache"),
            }
            for key in ("AWS_SESSION_TOKEN", "AWS_PROFILE"):
                env.pop(key, None)
            client = syq.Client(executable=os.environ["SYQ_CANDIDATE_EXECUTABLE"],
                                process_cwd=root, env=env, timeout=10)
            received = []
            client.cp(mapping=[
                syq.MappingEntry("prefix/file", "ordinary"),
                syq.MappingEntry("prefix/file", syq.StreamDestination(lambda inp: received.append(inp.read()))),
            ], from_="s3://bucket", into="output", s3_endpoint=source.endpoint, s3_region="us-east-1")
            self.assertEqual((root / "output/ordinary").read_bytes(), b"source bytes")
            self.assertEqual(received, [b"source bytes"])
