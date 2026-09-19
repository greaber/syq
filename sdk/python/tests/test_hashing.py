from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

import syq
from syq.models import _mapping_json
from syq.protocol import AutomationDecoder, parse_mapping_line
from test_native import FAKE_NATIVE


class HashTests(unittest.TestCase):
    def test_old_schema_and_old_mapping_field_are_rejected(self):
        fixture = Path(__file__).parent / "fixtures/automation-v1.ndjson"
        decoder = AutomationDecoder(prune=False, mapping=False, dry_run=False)
        with self.assertRaisesRegex(syq.SyqProtocolError, "schema"):
            decoder.feed(fixture.read_bytes().splitlines()[0])
        old = b'{"src":{"encoding":"utf-8","value":"a"},"dst":{"encoding":"utf-8","value":"b"},"expected_digest":{"algorithm":"md5","value":"900150983cd24fb0d6963f7d28e17f72"}}'
        with self.assertRaisesRegex(syq.SyqProtocolError, "unknown"):
            parse_mapping_line(old)

    def test_algorithms_lengths_and_immutable_canonical_value(self):
        for algorithm, length in (("blake3", 64), ("sha256", 64), ("md5", 32), ("xxh3-128", 32)):
            with self.subTest(algorithm=algorithm):
                digest = syq.Hash(algorithm, "AB" * (length // 2))
                self.assertEqual(digest.value, "ab" * (length // 2))
                self.assertEqual(str(digest.algorithm), algorithm)
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    digest.value = "0" * length
                for value in ("0" * (length - 1), "0" * (length + 1), "z" * length, " " * length):
                    with self.assertRaises(ValueError):
                        syq.Hash(algorithm, value)
        with self.assertRaises(ValueError):
            syq.Hash("rolling", "0" * 32)
        with self.assertRaises(TypeError):
            syq.Hash("md5", b"0" * 32)

    def test_mapping_roundtrip_preserves_expectation_and_raw_paths(self):
        digest = syq.Hash("md5", "a" * 32)
        entry = syq.MappingEntry(b"source-\xff", b"destination-\xff", "file", expected_hash=digest)
        record = _mapping_json(entry)
        self.assertEqual(record["expected_hash"], {"algorithm": "md5", "value": "a" * 32})
        self.assertEqual(parse_mapping_line(json.dumps(record).encode()), entry)
        self.assertEqual(
            parse_mapping_line(json.dumps(_mapping_json(syq.MappingEntry("a", "b"))).encode()),
            syq.MappingEntry("a", "b"),
        )
        for kind in ("dir", "symlink", "special"):
            with self.assertRaisesRegex(ValueError, "regular file"):
                syq.MappingEntry("a", "b", kind, expected_hash=digest)
        for malformed in (None, "md5:abc", {"algorithm": "md5"}, {"algorithm": "md5", "value": "invalid"}):
            record["expected_hash"] = malformed
            with self.assertRaises(syq.SyqProtocolError):
                parse_mapping_line(json.dumps(record).encode())

    def test_mismatch_result_retry_keeps_expectation(self):
        fixtures = Path(__file__).resolve().parents[3] / "tests/fixtures/automation"
        records = [json.loads(line) for line in (fixtures / "partial.ndjson").read_bytes().splitlines()]
        result_record = next(record for record in records if record["type"] == "operation_result" and record["disposition"] == "failed")
        result_record["expected_hash"] = {"algorithm": "md5", "value": "a" * 32}
        result_record["message"] = "expected md5 digest does not match destination"
        decoder = AutomationDecoder(prune=False, mapping=True, dry_run=False)
        events = [decoder.feed(json.dumps(record).encode()) for record in records]
        result = decoder.finish(23)
        self.assertIs(result.status, syq.OperationStatus.PARTIAL)
        failure = next(event for event in events if isinstance(event, syq.OperationResult) and event.expected_hash is not None)
        self.assertEqual(failure.expected_hash, syq.Hash("md5", "a" * 32))
        self.assertEqual(failure.retry_entry().expected_hash, failure.expected_hash)
        retry_json = _mapping_json(failure.retry_entry())
        self.assertEqual(retry_json["expected_hash"], result_record["expected_hash"])

    def test_operation_records_decode_without_expectations(self):
        fixtures = Path(__file__).resolve().parents[3] / "tests/fixtures/automation"
        decoder = AutomationDecoder(prune=False, mapping=True, dry_run=False)
        events = [decoder.feed(line) for line in (fixtures / "partial.ndjson").read_bytes().splitlines()]
        decoder.finish(23)
        failures = [event for event in events if isinstance(event, syq.OperationResult)]
        self.assertTrue(failures)
        self.assertTrue(all(event.expected_hash is None for event in failures))


class HashArgumentsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.executable = root / "syq"
        self.executable.write_text(FAKE_NATIVE)
        self.executable.chmod(0o755)
        self.log = root / "argv.json"
        self.client = syq.Client(executable=self.executable, env={**os.environ, "SYQ_FAKE_ARGV": str(self.log)})

    def test_choices_forward_independently_of_comparison_and_encryption(self):
        self.client.cp("source", as_="destination", integrity_checking="compare=xxh3-128,transfer=sha256")
        argv = json.loads(self.log.read_bytes())
        self.assertNotIn("--hash", argv)
        self.assertEqual(argv[argv.index("--integrity-checking") + 1], "compare=xxh3-128,transfer=sha256")
        self.assertNotIn("--tcp-plain", argv)
        self.client.cp("source", as_="destination", integrity_checking="compare=sha256")
        argv = json.loads(self.log.read_bytes())
        self.assertNotIn("--hash", argv)
        self.assertEqual(argv[argv.index("--integrity-checking") + 1], "compare=sha256")
        self.assertNotIn("--expected-hash", argv)

    def test_invalid_options_fail_before_starting_process(self):
        for options in ({"integrity_checking": False}, {"integrity_checking": ["compare=md5"]}):
            with self.subTest(options=options), self.assertRaises(syq.SyqInvocationError):
                self.client.cp("source", as_="destination", **options)
            self.assertFalse(self.log.exists())


class AsyncHashArgumentsTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_uses_identical_hash_options(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            executable = root / "syq"
            executable.write_text(FAKE_NATIVE)
            executable.chmod(0o755)
            log = root / "argv.json"
            client = syq.AsyncClient(executable=executable, env={**os.environ, "SYQ_FAKE_ARGV": str(log)})
            await client.cp("source", as_="destination", integrity_checking="compare=md5,transfer=sha256")
            argv = json.loads(log.read_bytes())
            self.assertEqual(argv[argv.index("--integrity-checking") + 1], "compare=md5,transfer=sha256")


@unittest.skipUnless(os.environ.get("SYQ_CANDIDATE_EXECUTABLE"), "candidate binary required")
class CandidateHashingTests(unittest.TestCase):
    def test_expected_hash_verifies_copy_and_metadata_match_then_reports_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "src").mkdir()
            (root / "src/source").write_bytes(b"abc")
            client = syq.Client(executable=os.environ["SYQ_CANDIDATE_EXECUTABLE"], process_cwd=root)
            expected = syq.Hash("md5", hashlib.md5(b"abc").hexdigest())
            result = client.cp(mapping=[syq.MappingEntry("source", "destination", expected_hash=expected)], cwd="src", into=".",
                               integrity_checking="compare=xxh3-128,transfer=sha256")
            self.assertIs(result.status, syq.OperationStatus.SUCCESS)
            self.assertEqual((root / "destination").read_bytes(), b"abc")
            original = (root / "destination").stat()
            (root / "destination").write_bytes(b"bad")
            os.utime(root / "destination", ns=(original.st_atime_ns, original.st_mtime_ns))
            result = client.cp(mapping=[syq.MappingEntry("source", "destination", expected_hash=expected)], cwd="src", into=".")
            self.assertIs(result.status, syq.OperationStatus.SUCCESS)
            self.assertEqual((root / "destination").read_bytes(), b"abc")
            events = []
            result = client.cp(mapping=[syq.MappingEntry("source", "destination", expected_hash=syq.Hash("md5", "0" * 32))], cwd="src", into=".",
                               on_event=events.append, check=False)
            self.assertIsNot(result.status, syq.OperationStatus.SUCCESS)
            failed = [event for event in events if isinstance(event, syq.OperationResult)
                      and event.disposition is syq.Disposition.FAILED]
            self.assertTrue(failed)
            self.assertEqual(failed[0].expected_hash, syq.Hash("md5", "0" * 32))

    def test_mapping_digest_survives_failure_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "src").mkdir()
            (root / "src/source").write_bytes(b"abc")
            client = syq.Client(executable=os.environ["SYQ_CANDIDATE_EXECUTABLE"], process_cwd=root)
            expected = syq.Hash("sha256", "0" * 64)
            events = []
            result = client.cp(mapping=[syq.MappingEntry("source", "destination", "file", expected_hash=expected)],
                               cwd="src", into="out", on_event=events.append, check=False)
            self.assertIsNot(result.status, syq.OperationStatus.SUCCESS)
            failed = [event for event in events if isinstance(event, syq.OperationResult)
                      and event.disposition is syq.Disposition.FAILED]
            self.assertTrue(failed)
            self.assertEqual(failed[0].retry_entry().expected_hash, expected)

    def test_dry_run_hash_reports_changes_without_verification_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "source").write_bytes(b"abc")
            (root / "destination").write_bytes(b"abc")
            source = (root / "source").stat()
            os.utime(root / "destination", ns=(source.st_atime_ns, source.st_mtime_ns))
            client = syq.Client(executable=os.environ["SYQ_CANDIDATE_EXECUTABLE"], process_cwd=root)
            events = []
            result = client.cp("source", as_="destination", dry_run=True, hash=True,
                               on_event=events.append)
            self.assertEqual(result.files_unchanged, 1)
            self.assertEqual(result.files_transferred, 0)
            self.assertFalse(any(isinstance(event, syq.TraceEvent) for event in events))
            (root / "destination").write_bytes(b"bad")
            os.utime(root / "destination", ns=(source.st_atime_ns, source.st_mtime_ns))
            events.clear()
            result = client.cp("source", as_="destination", dry_run=True, hash=True,
                               on_event=events.append)
            self.assertIs(result.status, syq.OperationStatus.SUCCESS)
            self.assertEqual(result.files_transferred, 1)
            self.assertEqual(result.errors, 0)
            trace = next(event for event in events if isinstance(event, syq.TraceEvent))
            self.assertIs(trace.reason, syq.TraceReason.CONTENT_DIFFERS)
            self.assertEqual(trace.bytes, 3)
            self.assertEqual((root / "destination").read_bytes(), b"bad")
