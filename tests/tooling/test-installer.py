#!/usr/bin/env python3
"""Exercise generated installer target selection and failure paths without
network access or real user paths."""
from support import SCRIPTS

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

TARGETS = {
    "linux-x86_64": ("Linux", "x86_64"),
    "linux-aarch64": ("Linux", "arm64"),
    "macos-arm64": ("Darwin", "arm64"),
    "macos-x86_64": ("Darwin", "x86_64"),
}

FAKE_UNAME = """#!/bin/sh
case "$1" in
  -s) printf '%s\\n' "$SYQ_TEST_UNAME_S" ;;
  -m) printf '%s\\n' "$SYQ_TEST_UNAME_M" ;;
  *) exit 2 ;;
esac
"""
FAKE_CURL = """#!/bin/sh
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    *) url=$1; shift ;;
  esac
done
cp "$SYQ_TEST_RELEASE_DIR/${url##*/}" "$output"
"""
FAKE_WGET = """#!/bin/sh
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -O) output=$2; shift 2 ;;
    http*) url=$1; shift ;;
    *) shift ;;
  esac
done
cp "$SYQ_TEST_RELEASE_DIR/${url##*/}" "$output"
"""


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def executable(path, content):
    Path(path).write_text(content)
    os.chmod(path, 0o755)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="syq-installer-test.")
        self.work = Path(self.temp.name)
        self.release = self.work / "release"
        self.fakebin = self.work / "fakebin"
        self.release.mkdir()
        self.fakebin.mkdir()
        executable(self.fakebin / "uname", FAKE_UNAME)
        executable(self.fakebin / "curl", FAKE_CURL)
        for target in TARGETS:
            self.write_archive(target)
        self.installer = self.generate("manifest.json", "install.sh")

    def tearDown(self):
        self.temp.cleanup()

    def env(self, target="linux-x86_64", path=None, **changes):
        os_name, machine = TARGETS.get(target, (None, None))
        env = dict(os.environ, XDG_CONFIG_HOME=str(self.work / "config"),
                   SYQ_TEST_UNAME_S=os_name or "", SYQ_TEST_UNAME_M=machine or "",
                   SYQ_TEST_RELEASE_DIR=str(self.release),
                   PATH=path or f"{self.fakebin}{os.pathsep}{os.environ['PATH']}")
        for name, value in changes.items():
            if value is None:
                env.pop(name, None)
            else:
                env[name] = value
        return env

    def write_archive(self, target, version="0.1.0", identity="v0.1.0"):
        program = self.work / f"program-{target}"
        executable(program, f"""#!/bin/sh
case "$1" in
  --version) echo 'syq {version}' ;;
  --build-identity) echo '{identity}' ;;
  --register-standalone-install) exit 0 ;;
  --test-target) echo '{target}' ;;
  *) exit 2 ;;
esac
""")
        archive = subprocess.run(["gzip", "-9", "-n", "-c", str(program)], check=True,
                                 stdout=subprocess.PIPE).stdout
        (self.release / f"syq-{target}.gz").write_bytes(archive)

    def write_manifest(self, output):
        artifacts = {}
        for target in TARGETS:
            archive = self.release / f"syq-{target}.gz"
            program = self.work / f"program-{target}"
            artifacts[target] = {
                "binary": {"name": f"syq-{target}", "sha256": sha256(program),
                           "size": program.stat().st_size},
                "archive": {"name": f"syq-{target}.gz", "sha256": sha256(archive),
                            "size": archive.stat().st_size},
            }
        manifest = {"schema": 1, "repository": "https://github.com/greaber/syq", "version": "0.1.0",
                    "tag": "v0.1.0", "artifacts": artifacts,
                    "installer": {"name": "install.sh", "sha256": "1" * 64, "size": 1},
                    "homebrew_formula": {"name": "syq.rb", "sha256": "2" * 64, "size": 1}}
        output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    def generate(self, manifest_name, installer_name):
        manifest = self.work / manifest_name
        self.write_manifest(manifest)
        installer = self.work / installer_name
        subprocess.run([str(SCRIPTS / "generate-installer.py"), str(manifest), str(installer)],
                       check=True)
        return installer

    def install(self, bin_dir, installer=None, shell="sh", **env):
        return subprocess.run([shell, str(installer or self.installer), "--bin-dir", str(bin_dir)],
                              env=self.env(**env), stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)

    def expect_failure(self, expected, command, env):
        result = subprocess.run(command, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        self.assertNotEqual(result.returncode, 0, f"command unexpectedly succeeded: {command}")
        self.assertIn(expected, result.stdout)

    def run_program(self, path, *args):
        return subprocess.run([str(path), *args], check=True, stdout=subprocess.PIPE,
                              text=True).stdout.rstrip("\n")

    def test_each_platform_installs_its_own_target(self):
        for target in TARGETS:
            with self.subTest(target=target):
                install_dir = self.work / f"install-{target}"
                result = self.install(install_dir, target=target)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertEqual(self.run_program(install_dir / "syq", "--version"), "syq 0.1.0")
                self.assertEqual(self.run_program(install_dir / "syq", "--test-target"), target)

    def test_wget_only_download(self):
        # Exercise the wget-only branch with a PATH containing every required utility
        # except curl.
        wgetbin = self.work / "wgetbin"
        wgetbin.mkdir()
        checksum_utility = next((candidate for candidate in ("sha256sum", "shasum", "openssl")
                                 if shutil.which(candidate)), None)
        self.assertIsNotNone(checksum_utility)
        for utility in ["chmod", "cp", "gzip", "mkdir", "mktemp", "mv", "rm", "sed", "tr", "wc",
                        checksum_utility]:
            (wgetbin / utility).symlink_to(shutil.which(utility))
        shutil.copy(self.fakebin / "uname", wgetbin / "uname")
        executable(wgetbin / "wget", FAKE_WGET)
        result = self.install(self.work / "install-wget", shell="/bin/sh", path=str(wgetbin))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.run_program(self.work / "install-wget/syq", "--test-target"),
                         "linux-x86_64")

    def test_help_and_usage_errors(self):
        help_text = subprocess.run(["sh", str(self.installer), "--help"], check=True,
                                   stdout=subprocess.PIPE, text=True, env=self.env()).stdout
        self.assertEqual(help_text.split("\n")[0], "Install syq 0.1.0 without sudo.")
        self.expect_failure("unknown option: --bogus", ["sh", str(self.installer), "--bogus"],
                            self.env())
        self.expect_failure("--bin-dir needs a value", ["sh", str(self.installer), "--bin-dir"],
                            self.env())
        self.expect_failure("HOME is not set", ["sh", str(self.installer)],
                            self.env(HOME=None, XDG_CONFIG_HOME=None))

    def test_explicit_bin_dir_needs_no_home_or_usable_config(self):
        # Explicit bin-dir works without HOME or config, and ignores unusable config.
        result = self.install(self.work / "no-config", HOME=None, XDG_CONFIG_HOME=None)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(os.access(self.work / "no-config/syq", os.X_OK))
        blocked = self.work / "blocked-config"
        blocked.write_text("not a directory\n")
        result = self.install(self.work / "invalid-config", XDG_CONFIG_HOME=str(blocked))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(os.access(self.work / "invalid-config/syq", os.X_OK))

    def test_unsupported_platform(self):
        self.expect_failure("unsupported platform: Plan9 mips",
                            ["sh", str(self.installer), "--bin-dir", str(self.work / "unsupported")],
                            self.env(SYQ_TEST_UNAME_S="Plan9", SYQ_TEST_UNAME_M="mips"))

    def test_directory_destination_is_refused(self):
        destination = self.work / "directory-destination"
        (destination / "syq").mkdir(parents=True)
        self.expect_failure("destination is a directory",
                            ["sh", str(self.installer), "--bin-dir", str(destination)], self.env())

    def test_bad_downloads_keep_the_working_installation(self):
        install_dir = self.work / "install-linux-x86_64"
        self.assertEqual(self.install(install_dir).returncode, 0)
        installed_sha = sha256(install_dir / "syq")
        # A bad download must not alter a working installation.
        with (self.release / "syq-linux-x86_64.gz").open("ab") as archive:
            archive.write(b"tamper")
        self.expect_failure("downloaded archive has size",
                            ["sh", str(self.installer), "--bin-dir", str(install_dir)], self.env())
        self.assertEqual(sha256(install_dir / "syq"), installed_sha)

        # Even correctly hashed content is rejected if its build identity does not
        # match the release metadata, again without replacing the installed binary.
        self.write_archive("linux-x86_64", "0.1.0", "v0.1.0+dev.wrong")
        wrong = self.generate("wrong-identity-manifest.json", "wrong-identity-install.sh")
        self.expect_failure("unexpected identity",
                            ["sh", str(wrong), "--bin-dir", str(install_dir)], self.env())
        self.assertEqual(sha256(install_dir / "syq"), installed_sha)


if __name__ == "__main__":
    unittest.main()
