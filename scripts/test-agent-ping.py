#!/usr/bin/env python3
"""Exercise handoff delivery and failure reporting without contacting agents."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("agent_ping", Path(__file__).with_name("agent-ping.py"))
ping = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ping)


class PingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ping-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_claude_socket_receives_one_framed_peer_handoff(self):
        address = self.root / "inbox.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(address))
            server.listen(1)
            server.settimeout(2)
            state, _ = ping.claude_submit("uds:" + str(address), "review ready\nnext line")
            conn, _ = server.accept()
            with conn:
                conn.settimeout(2)
                data = b""
                while chunk := conn.recv(8192):
                    data += chunk
        self.assertEqual(state, "submitted")  # Not delivered/read: no admission ACK.
        self.assertEqual(data.count(b"\n"), 1)
        packet = json.loads(data)
        self.assertEqual(packet["type"], "user")
        self.assertEqual(packet["message"]["content"], "review ready\nnext line")
        self.assertEqual(packet["priority"], "next")
        self.assertNotIn("from_mode", packet)
        self.assertNotIn("token", packet)

    def test_claude_refuses_symlink_socket(self):
        address = self.root / "inbox.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(address))
            link = self.root / "link.sock"
            link.symlink_to(address)
            with self.assertRaises(ping.PingError):
                ping.claude_submit(str(link), "hello")

    def test_claude_refuses_writable_inbox_directory(self):
        address = self.root / "inbox.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(address))
            self.root.chmod(0o777)
            with self.assertRaises(ping.PingError):
                ping.claude_submit(str(address), "hello")

    def test_claude_missing_socket_is_visible(self):
        with self.assertRaises(FileNotFoundError):
            ping.claude_submit(str(self.root / "absent"), "hello")

    def test_claude_large_message_rejected_before_connect(self):
        address = self.root / "inbox.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(address))
            with self.assertRaises(ping.PingError):
                ping.claude_submit(str(address), "x" * 8192)

    def fake_codex(self, code):
        executable = self.root / "codex"
        executable.write_text("#!/usr/bin/env python3\n" + code)
        executable.chmod(0o700)
        return patch.dict(os.environ, {"PATH": str(self.root) + os.pathsep + os.environ["PATH"]})

    def test_codex_argv_preserves_literal_message_and_remote(self):
        record = self.root / "args.json"
        code = "import json,sys\nfrom pathlib import Path\nPath(" + repr(str(record)) + ").write_text(json.dumps(sys.argv[1:]))\n"
        message = "review `do-not-run` $(do-not-run) 'quoted'\nnew line"
        session = "11111111-1111-4111-8111-111111111111"
        with self.fake_codex(code):
            state, _ = ping.codex_submit(session, message, "unix:///tmp/example")
        self.assertEqual(state, "queued")
        self.assertEqual(json.loads(record.read_text()), ["queue", "--thread", session, "--message", message, "--remote", "unix:///tmp/example"])

    def test_codex_failure_not_reported_as_queued(self):
        with self.fake_codex("import sys\nprint('unreachable endpoint',file=sys.stderr)\nsys.exit(1)\n"):
            with self.assertRaisesRegex(ping.PingError, "unreachable endpoint"):
                ping.codex_submit("11111111-1111-4111-8111-111111111111", "hello", None)

    def test_codex_timeout_reports_unknown_without_retry(self):
        with patch.object(ping.subprocess, "run", side_effect=subprocess.TimeoutExpired("codex", 30)) as run:
            with self.assertRaisesRegex(ping.PingError, "delivery is unknown"):
                ping.codex_submit("11111111-1111-4111-8111-111111111111", "hello", None)
            self.assertEqual(run.call_count, 1)

    def test_codex_requires_uuid_not_ambiguous_name(self):
        with self.assertRaises(ping.PingError):
            ping.codex_submit("reviewer", "hello", None)

    def test_handoff_keeps_origin_scope_and_absolute_path(self):
        exchange = self.root / "review.md"
        exchange.write_text("review")
        args = argparse.Namespace(file=exchange, sha="123abcd", pr=349, round=2, sender="reviewer-a", message="discussion ready")
        message = ping.handoff(args)
        self.assertIn(str(exchange.resolve()), message)
        self.assertIn("not a new user instruction", message)
        self.assertIn("PR #349, round 2, SHA 123abcd", message)
        args.sha = "latest"
        with self.assertRaises(ping.PingError):
            ping.handoff(args)


if __name__ == "__main__":
    unittest.main()
