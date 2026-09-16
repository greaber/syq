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


class DigestTests(unittest.TestCase):
    def test_algorithms_lengths_and_immutable_canonical_value(self):
        for algorithm, length in (("blake3", 64), ("sha256", 64), ("md5", 32), ("xxh3-128", 32)):
            with self.subTest(algorithm=algorithm):
                digest = syq.Digest(algorithm, "AB" * (length // 2))
                self.assertEqual(digest.value, "ab" * (length // 2))
                self.assertEqual(str(digest.algorithm), algorithm)
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    digest.value = "0" * length
                for value in ("0" * (length - 1), "0" * (length + 1), "z" * length, " " * length):
                    with self.assertRaises(ValueError):
                        syq.Digest(algorithm, value)
        with self.assertRaises(ValueError):
            syq.Digest("rolling", "0" * 32)
        with self.assertRaises(TypeError):
            syq.Digest("md5", b"0" * 32)

    def test_mapping_roundtrip_preserves_expectation_and_raw_paths(self):
        digest = syq.Digest("md5", "a" * 32)
        entry = syq.MappingEntry(b"source-\xff", b"destination-\xff", "file", expected_digest=digest)
        record = _mapping_json(entry)
        self.assertEqual(record["expected_digest"], {"algorithm": "md5", "value": "a" * 32})
        self.assertEqual(parse_mapping_line(json.dumps(record).encode()), entry)
        self.assertEqual(
            parse_mapping_line(json.dumps(_mapping_json(syq.MappingEntry("a", "b"))).encode()),
            syq.MappingEntry("a", "b"),
        )
        for kind in ("dir", "symlink", "special"):
            with self.assertRaisesRegex(ValueError, "regular file"):
                syq.MappingEntry("a", "b", kind, expected_digest=digest)
        for malformed in (None, "md5:abc", {"algorithm": "md5"}, {"algorithm": "md5", "value": "invalid"}):
            record["expected_digest"] = malformed
            with self.assertRaises(syq.SyqProtocolError):
                parse_mapping_line(json.dumps(record).encode())

    def test_mismatch_result_retry_keeps_expectation(self):
        fixtures = Path(__file__).resolve().parents[3] / "tests/fixtures/automation"
        records = [json.loads(line) for line in (fixtures / "partial.ndjson").read_bytes().splitlines()]
        result_record = next(record for record in records if record["type"] == "operation_result" and record["disposition"] == "failed")
        result_record["expected_digest"] = {"algorithm": "md5", "value": "a" * 32}
        result_record["message"] = "expected md5 digest does not match destination"
        decoder = AutomationDecoder(prune=False, mapping=True, dry_run=False)
        events = [decoder.feed(json.dumps(record).encode()) for record in records]
        result = decoder.finish(23)
        self.assertIs(result.status, syq.OperationStatus.PARTIAL)
        failure = next(event for event in events if isinstance(event, syq.OperationResult) and event.expected_digest is not None)
        self.assertEqual(failure.expected_digest, syq.Digest("md5", "a" * 32))
        self.assertEqual(failure.retry_entry().expected_digest, failure.expected_digest)
        retry_json = _mapping_json(failure.retry_entry())
        self.assertEqual(retry_json["expected_digest"], result_record["expected_digest"])

    def test_legacy_operation_records_still_decode_without_expectations(self):
        fixtures = Path(__file__).resolve().parents[3] / "tests/fixtures/automation"
        decoder = AutomationDecoder(prune=False, mapping=True, dry_run=False)
        events = [decoder.feed(line) for line in (fixtures / "partial.ndjson").read_bytes().splitlines()]
        decoder.finish(23)
        failures = [event for event in events if isinstance(event, syq.OperationResult)]
        self.assertTrue(failures)
        self.assertTrue(all(event.expected_digest is None for event in failures))


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
        self.client.cp("source", as_="destination", hash=True, hash_algorithm=syq.HashAlgorithm.XXH3_128,
                       transfer_integrity=True, expected_digest=syq.Digest("md5", "A" * 32))
        argv = json.loads(self.log.read_bytes())
        self.assertIn("--hash", argv)
        self.assertIn("--transfer-integrity", argv)
        self.assertEqual(argv[argv.index("--hash-algorithm") + 1], "xxh3-128")
        self.assertEqual(argv[argv.index("--expected-hash") + 1], "md5:" + "a" * 32)
        self.assertNotIn("--tcp-plain", argv)
        self.client.cp("source", as_="destination", hash_algorithm="sha256")
        argv = json.loads(self.log.read_bytes())
        self.assertNotIn("--hash", argv)
        self.assertNotIn("--transfer-integrity", argv)
        self.assertNotIn("--expected-hash", argv)

    def test_invalid_options_fail_before_starting_process(self):
        digest = syq.Digest("md5", "a" * 32)
        for options in ({"hash_algorithm": "rolling"}, {"transfer_integrity": "false"},
                        {"expected_digest": "md5:abc"}, {"expected_digest": digest, "src": ["other"]},
                        {"expected_digest": digest, "mapping": [syq.MappingEntry("a", "b")]}):
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
            await client.cp("source", as_="destination", hash_algorithm="md5", transfer_integrity=True,
                            expected_digest=syq.Digest("md5", "b" * 32))
            argv = json.loads(log.read_bytes())
            self.assertEqual(argv[argv.index("--hash-algorithm") + 1], "md5")
            self.assertEqual(argv[argv.index("--expected-hash") + 1], "md5:" + "b" * 32)
            self.assertIn("--transfer-integrity", argv)


@unittest.skipUnless(os.environ.get("SYQ_CANDIDATE_EXECUTABLE"), "candidate binary required")
class CandidateHashingTests(unittest.TestCase):
    def test_expected_digest_verifies_copy_and_metadata_match_then_reports_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "source").write_bytes(b"abc")
            client = syq.Client(executable=os.environ["SYQ_CANDIDATE_EXECUTABLE"], process_cwd=root)
            expected = syq.Digest("md5", hashlib.md5(b"abc").hexdigest())
            result = client.cp("source", as_="destination", expected_digest=expected,
                               hash_algorithm="xxh3-128", transfer_integrity=True)
            self.assertIs(result.status, syq.OperationStatus.SUCCESS)
            self.assertEqual((root / "destination").read_bytes(), b"abc")
            original = (root / "destination").stat()
            (root / "destination").write_bytes(b"bad")
            os.utime(root / "destination", ns=(original.st_atime_ns, original.st_mtime_ns))
            result = client.cp("source", as_="destination", expected_digest=expected)
            self.assertIs(result.status, syq.OperationStatus.SUCCESS)
            self.assertEqual((root / "destination").read_bytes(), b"abc")
            events = []
            result = client.cp("source", as_="destination", expected_digest=syq.Digest("md5", "0" * 32),
                               on_event=events.append, check=False)
            self.assertIsNot(result.status, syq.OperationStatus.SUCCESS)
            failed = [event for event in events if isinstance(event, syq.OperationResult)
                      and event.disposition is syq.Disposition.FAILED]
            self.assertTrue(failed)
            self.assertEqual(failed[0].expected_digest, syq.Digest("md5", "0" * 32))

    def test_mapping_digest_survives_failure_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "src").mkdir()
            (root / "src/source").write_bytes(b"abc")
            client = syq.Client(executable=os.environ["SYQ_CANDIDATE_EXECUTABLE"], process_cwd=root)
            expected = syq.Digest("sha256", "0" * 64)
            events = []
            result = client.cp(mapping=[syq.MappingEntry("source", "destination", "file", expected_digest=expected)],
                               cwd="src", into="out", on_event=events.append, check=False)
            self.assertIsNot(result.status, syq.OperationStatus.SUCCESS)
            failed = [event for event in events if isinstance(event, syq.OperationResult)
                      and event.disposition is syq.Disposition.FAILED]
            self.assertTrue(failed)
            self.assertEqual(failed[0].retry_entry().expected_digest, expected)
