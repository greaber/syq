from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import syq


EXECUTABLE = os.environ.get("SYQ_CANDIDATE_EXECUTABLE")
EXPECTED_VERSION = os.environ.get("SYQ_CANDIDATE_VERSION")


@unittest.skipUnless(
    EXECUTABLE and EXPECTED_VERSION,
    "candidate compatibility requires SYQ_CANDIDATE_EXECUTABLE and version",
)
class CandidateCompatibilityTests(unittest.TestCase):
    def test_candidate_version_and_typed_native_surface(self) -> None:
        assert EXECUTABLE is not None
        assert EXPECTED_VERSION is not None
        executable = Path(EXECUTABLE)
        self.assertEqual(syq.version(executable=executable), EXPECTED_VERSION)

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source; $(not-a-command)"
            destination = root / "destination"
            source.write_bytes(b"candidate compatibility\n")

            client = syq.Client(executable=executable, process_cwd=root)
            events: list[syq.AutomationEvent] = []
            preview = client.cp(
                source.name,
                as_new=destination.name,
                dry_run=True,
                on_event=events.append,
            )
            self.assertTrue(preview.dry_run)
            self.assertEqual(preview.files_transferred, 1)
            self.assertEqual(
                preview.bytes_transferred, len(b"candidate compatibility\n")
            )
            self.assertFalse(destination.exists())
            self.assertTrue(
                any(
                    isinstance(event, syq.TraceEvent)
                    and event.reason is syq.TraceReason.DESTINATION_MISSING
                    for event in events
                )
            )

            result = client.cp(source.name, as_new=destination.name)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.files_transferred, 1)
            self.assertEqual(destination.read_bytes(), source.read_bytes())

            mapping_source = root / "mapping-source"
            mapping_source.mkdir()
            (mapping_source / "mapped.txt").write_bytes(b"mapped")
            mapping_alias = root / "mapping-source-link"
            mapping_alias.symlink_to(mapping_source, target_is_directory=True)
            with client.map(src_src=mapping_alias.name, follow=True) as mapping:
                entries = list(mapping)
            self.assertEqual(entries[0].src, syq.RelativePath("mapped.txt"))
            physical_temp = root / "physical-temp"
            physical_temp.mkdir()
            temporary_alias = root / "temporary-alias"
            temporary_alias.symlink_to(physical_temp, target_is_directory=True)
            named_temporary_file = tempfile.NamedTemporaryFile

            def create_through_alias(**kwargs):
                return named_temporary_file(dir=temporary_alias, **kwargs)

            with mock.patch(
                "syq.client.tempfile.NamedTemporaryFile",
                side_effect=create_through_alias,
            ):
                mapped = client.cp(
                    mapping=entries,
                    cwd=mapping.cwd,
                    follow=True,
                    into="mapped",
                )
            self.assertEqual(mapped.files_transferred, 1)
            self.assertEqual((root / "mapped" / "mapped.txt").read_bytes(), b"mapped")

            generated_source = root / "generated-source"
            generated_source.mkdir()
            (generated_source / "generated.txt").write_bytes(b"generated")
            with mock.patch(
                "syq.client.tempfile.NamedTemporaryFile",
                side_effect=create_through_alias,
            ):
                generated = client.cp(
                    mapping=[syq.MappingEntry("generated.txt", "generated.txt")],
                    cwd=generated_source.name,
                    into="generated-target",
                )
            self.assertEqual(generated.files_transferred, 1)
            self.assertEqual(
                (root / "generated-target" / "generated.txt").read_bytes(),
                b"generated",
            )

            ignore_source = root / "ignore-source"
            ignore_source.mkdir()
            (ignore_source / "keep.tmp").write_bytes(b"keep")
            ignore_rules = root / "ignore.rules"
            ignore_rules.write_text("*.tmp\n", encoding="utf-8")
            ordered = client.cp(
                src_src=ignore_source.name,
                into="ignore-target",
                ignore=[syq.IgnoreFrom(ignore_rules.name), "!keep.tmp"],
            )
            self.assertEqual(ordered.files_transferred, 1)
            self.assertEqual(
                (root / "ignore-target" / "keep.tmp").read_bytes(), b"keep"
            )

            prune_source = root / "prune-source"
            prune_target = root / "prune-target"
            prune_source.mkdir()
            prune_target.mkdir()
            (prune_source / "keep").write_bytes(b"keep")
            (prune_target / "extra").write_bytes(b"extra")
            pruned = client.cp(
                src_src=prune_source.name,
                into_existing=prune_target.name,
                prune=True,
                max_delete=1,
            )
            self.assertEqual(pruned.deletions_completed, 1)
            self.assertFalse((prune_target / "extra").exists())

            raw_name = b"raw-\xff"
            raw_source = os.fsencode(root) + b"/" + raw_name
            descriptor = os.open(raw_source, os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                os.write(descriptor, b"raw")
            finally:
                os.close(descriptor)
            raw_events: list[syq.AutomationEvent] = []
            raw_result = client.cp(
                src=raw_name,
                into=b"raw-target",
                on_event=raw_events.append,
            )
            self.assertEqual(raw_result.files_transferred, 1)
            raw_operation = next(
                event
                for event in raw_events
                if isinstance(event, syq.OperationResult) and event.kind == "file"
            )
            self.assertEqual(raw_operation.dst.raw, raw_name)

    def test_candidate_failure_is_retained(self) -> None:
        assert EXECUTABLE is not None
        result = syq.run(
            ["not-a-syq-command"],
            executable=EXECUTABLE,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr)


if __name__ == "__main__":
    unittest.main()
