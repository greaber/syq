#!/usr/bin/env python3
"""Exercise benchmark failures, accounting and comparisons without big fixtures."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("benchmark", ROOT / "scripts/benchmark-concurrency.py")
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="syq-benchmark-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def case(self, operation="cp"):
        return dict(name="tree", operation=operation, root=str(self.root), files=6,
                    directories=2, sizes=[0, 19, 4097])

    def run_measure(self, command, cpus=None, timeout=10):
        with contextlib.redirect_stdout(io.StringIO()):
            return bench.measure(command, dict(os.environ, LC_ALL="C"), cpus,
                                 self.root / "measure", timeout)

    def test_verification_checks_bytes_source_and_unexpected_directories(self):
        case = self.case()
        with contextlib.redirect_stdout(io.StringIO()):
            hashes, sizes = bench.fixture(self.root, case, bench.Deadline(10, "setup"))
            self.assertEqual(sizes["logical_bytes"], 8232)
            shutil.copytree(self.root / "source", self.root / "destination", dirs_exist_ok=True)
            bench.verify(self.root, case, hashes, bench.Deadline(10, "verify"))
            path = self.root / "destination" / bench.filename(case, 1)
            path.write_bytes(b"wrong content")
            with self.assertRaisesRegex(RuntimeError, "changed file"):
                bench.verify(self.root, case, hashes, bench.Deadline(10, "verify"))
            shutil.copyfile(self.root / "source" / bench.filename(case, 1), path)
            (self.root / "destination/extra").mkdir()
            with self.assertRaisesRegex(RuntimeError, "tree differs"):
                bench.verify(self.root, case, hashes, bench.Deadline(10, "verify"))
            (self.root / "destination/extra").rmdir()
            shutil.rmtree(self.root / "destination")
            (self.root / "destination").symlink_to(self.root / "source", target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "expected directory"):
                bench.verify(self.root, case, hashes, bench.Deadline(10, "verify"))
            (self.root / "destination").unlink()
            shutil.copytree(self.root / "source", self.root / "destination")
            (self.root / "source" / bench.filename(case, 1)).unlink()
            with self.assertRaisesRegex(RuntimeError, "tree differs"):
                bench.verify(self.root, case, hashes, bench.Deadline(10, "verify"))

    def test_failure_preserves_partial_results_and_cleans_only_owned_fixture(self):
        # A zero-exit executable doing no work must fail result verification.
        sentinel = self.root / "unrelated"
        sentinel.write_text("keep me")
        plan = dict(reference="noop", cases=[self.case("rm")], variants=[
            dict(name="noop", binary="/usr/bin/true", workers=None, cpus=None)])
        path = self.root / "plan.json"
        path.write_text(json.dumps(plan))
        result = subprocess.run([sys.executable, str(ROOT / "scripts/benchmark-concurrency.py"),
                                 "--plan", str(path), "--output", str(self.root / "results"),
                                 "--rounds", "1"], capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        report = json.loads((self.root / "results/results.json").read_text())
        self.assertIn("left paths", report["error"])
        self.assertFalse(report["complete"])
        self.assertTrue(report["cleaned"])
        self.assertFalse(report["trials"][0]["verified"])
        self.assertEqual(sentinel.read_text(), "keep me")
        self.assertFalse(list(self.root.glob("syq-concurrency-*")))

    def test_native_accounting_does_not_inherit_fixture_builder_peak_rss(self):
        # wait4 on a Python-spawned child itself can inherit this memory peak.
        allocation = bytearray(96 * 1024 * 1024)
        allocation[0] = 1
        result = self.run_measure(["/usr/bin/true"])
        self.assertEqual(result["exit_code"], 0)
        self.assertLess(result["resources"]["peak_rss_bytes"], len(allocation) // 2)
        self.assertGreater(result["seconds"], 0)

    @unittest.skipUnless(hasattr(os, "sched_getaffinity"), "CPU affinity is Linux-only")
    def test_affinity_applies_to_product_and_restores_runner(self):
        before = os.sched_getaffinity(0)
        chosen = min(before)
        result = self.run_measure([sys.executable, "-c",
            f"import os,time; assert os.sched_getaffinity(0)=={{{chosen}}}; time.sleep(.08)"], [chosen])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(os.sched_getaffinity(0), before)
        self.assertEqual(result["observed_cpu_sets"], [str(chosen)])

    def test_timeout_terminates_grandchild_process_group(self):
        pidfile = self.root / "group"
        code = ("import os,subprocess,time,pathlib; "
                f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpgrp())); "
                "subprocess.Popen(['sleep','60']); time.sleep(60)")
        with self.assertRaises(TimeoutError):
            self.run_measure([sys.executable, "-c", code], timeout=.3)
        self.assertTrue(pidfile.exists())
        self.assertFalse(bench.group_alive(int(pidfile.read_text())))

    def test_comparison_preserves_bad_case_and_bad_round(self):
        rows = []
        for case, seconds in (("fast", [5, 5]), ("bad", [10, 30])):
            for iteration, value in enumerate(seconds):
                for variant, elapsed in (("reference", 10), ("candidate", value)):
                    rows.append(dict(case=case, variant=variant, round=iteration, verified=True,
                                     seconds=elapsed, resources=dict(cpu_seconds=10, peak_rss_bytes=1024)))
        # An incomplete/unverified round is never paired or counted as a win.
        rows.append(dict(case="bad", variant="candidate", round=2, verified=False))
        results = bench.comparisons(rows, "reference")
        self.assertEqual(results[0]["case"], "bad")
        self.assertEqual(results[0]["paired_rounds"], 2)
        self.assertEqual(results[0]["seconds"]["paired_ratios"], [1, 3])
        self.assertEqual(results[0]["seconds"]["worst_ratio"], 3)
        self.assertEqual(results[1]["seconds"]["median_ratio"], .5)

    def test_zero_cpu_resolution_is_not_a_ratio(self):
        base = dict(case="case", round=1, verified=True, seconds=.001,
                    resources=dict(cpu_seconds=0, peak_rss_bytes=100))
        result = bench.comparisons([dict(base, variant="old"), dict(base, variant="new")], "old")
        self.assertIsNone(result[0]["cpu_seconds"]["median_ratio"])
        self.assertEqual(result[0]["cpu_seconds"]["paired_ratios"], [])
        nonzero = copy.deepcopy(base)
        nonzero["resources"]["cpu_seconds"] = .01
        result = bench.comparisons([dict(nonzero, variant="old"), dict(base, variant="new")], "old")
        self.assertIsNone(result[0]["cpu_seconds"]["median_ratio"])

    def test_macos_time_units_and_missing_fields(self):
        log = """syq: incidental diagnostic
        1.24 real         0.31 user         0.87 sys
             5242880  maximum resident set size
                   3  voluntary context switches
                   4  involuntary context switches
                   5  block input operations
                   6  block output operations
"""
        result = bench.time_usage(log, "Darwin")
        self.assertEqual(result["peak_rss_bytes"], 5242880)
        self.assertEqual(result["system_seconds"], .87)
        self.assertEqual(result["input_blocks"], 5)
        with self.assertRaisesRegex(ValueError, "missing macOS time field"):
            bench.time_usage(log.replace("maximum resident set size", "unknown"), "Darwin")

    def test_plan_rejects_unknown_knobs_and_affinity_outside_allowed_set(self):
        plan = dict(reference="base", cases=[self.case()], variants=[
            dict(name="base", binary="/usr/bin/true", workers=32, cpus=None)])
        bench.validate(copy.deepcopy(plan))
        bad = copy.deepcopy(plan)
        bad["cases"][0]["filez"] = 1
        with self.assertRaisesRegex(ValueError, "case needs"):
            bench.validate(bad)
        if hasattr(os, "sched_getaffinity"):
            bad = copy.deepcopy(plan)
            bad["variants"][0]["cpus"] = [max(os.sched_getaffinity(0)) + 1]
            with self.assertRaisesRegex(ValueError, "outside"):
                bench.validate(bad)

    def test_nonfinite_timeout_is_rejected_before_creating_output(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/benchmark-concurrency.py"),
                                 "--plan", "unused.json", "--output", str(self.root / "results"),
                                 "--timeout", "nan"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("positive rounds/timeouts", result.stderr)
        self.assertFalse((self.root / "results").exists())


if __name__ == "__main__":
    unittest.main()
