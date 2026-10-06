#!/usr/bin/env python3
"""The pinned Rust runner times out one test and still executes later tests."""
from support import ROOT

import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import tomllib
import unittest


class TimeoutTests(unittest.TestCase):
    def test_timeout_includes_cleanup_and_does_not_stop_later_tests(self):
        with tempfile.TemporaryDirectory(prefix="syq-test-timeout-") as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / ".config").mkdir()
            (root / "Cargo.toml").write_text(
                '[package]\nname = "timeout-fixture"\nversion = "0.0.0"\nedition = "2021"\n')
            # Exercise the real policy without taking two minutes per check.
            config = (ROOT / ".config/nextest.toml").read_text()
            self.assertIn('period = "30s", terminate-after = 4, grace-period = "5s"', config)
            (root / ".config/nextest.toml").write_text(
                config.replace('"30s"', '"100ms"').replace('"5s"', '"100ms"'))
            (root / "src/lib.rs").write_text(r'''
#[test]
fn a_stuck_destructor() {
    struct Stuck;
    impl Drop for Stuck {
        fn drop(&mut self) { loop { std::thread::park(); } }
    }
    std::fs::write("test-pid", std::process::id().to_string()).unwrap();
    // Exercise forced termination after the grace period too.
    unsafe extern "C" { fn signal(sig: i32, handler: usize) -> usize; }
    unsafe { signal(15, 1); } // SIGTERM, SIG_IGN on Linux and macOS.
    let _stuck = Stuck;
    panic!("failure before cleanup hangs");
}
#[test]
fn b_runs_after_timeout() {
    std::fs::write("later-test-ran", "yes").unwrap();
}
''')
            env = dict(os.environ)
            # The fixture is outside the checkout, where rustup cannot discover
            # our toolchain file. Do not depend on a global default being set.
            env["RUSTUP_TOOLCHAIN"] = tomllib.loads(
                (ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
            env.pop("CARGO_TARGET_DIR", None)
            env.pop("NEXTEST_PROFILE", None)
            subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root,
                           env=env, check=True)
            process = subprocess.Popen(
                ["cargo", "nextest", "run", "--locked", "--offline", "--test-threads", "1"],
                cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True)
            started = time.monotonic()
            cleanup_needed = True
            try:
                output, _ = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 100, output)
                self.assertIn("TIMEOUT", output)
                self.assertEqual((root / "later-test-ran").read_text(), "yes", output)
                pid = int((root / "test-pid").read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
                cleanup_needed = False
                self.assertLess(time.monotonic() - started, 30, output)
            finally:
                # Also clean up if a broken runner fails this regression check.
                if cleanup_needed:
                    groups = [process.pid] if process.poll() is None else []
                    if (root / "test-pid").exists():
                        groups.append(int((root / "test-pid").read_text()))
                    for pid in groups:
                        try:
                            os.killpg(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                process.wait()


if __name__ == "__main__":
    unittest.main()
