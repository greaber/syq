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
# Each fake reports the release file a URL names on stderr and serves it, or
# with SYQ_TEST_ENDLESS_DOWNLOAD set, data that never ends.
FAKE_DOWNLOAD = """
echo "test fetched ${url##*/}" >&2
[ -z "${SYQ_TEST_ENDLESS_DOWNLOAD:-}" ] || exec yes
if [ "$output" = - ]; then
  exec cat "$SYQ_TEST_RELEASE_DIR/${url##*/}"
fi
cp "$SYQ_TEST_RELEASE_DIR/${url##*/}" "$output"
"""
FAKE_CURL = """#!/bin/sh
[ -z "${SYQ_TEST_ARGS_FILE:-}" ] || printf '%s\\n' "$@" > "$SYQ_TEST_ARGS_FILE"
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    *) url=$1; shift ;;
  esac
done
""" + FAKE_DOWNLOAD
FAKE_WGET = """#!/bin/sh
[ -z "${SYQ_TEST_ARGS_FILE:-}" ] || printf '%s\\n' "$@" > "$SYQ_TEST_ARGS_FILE"
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -O) output=$2; shift 2 ;;
    http*) url=$1; shift ;;
    *) shift ;;
  esac
done
""" + FAKE_DOWNLOAD
# Stands in for zstd on fixture archives, which hold gzip data; with
# SYQ_TEST_ZSTD_FAILS set, it fails as a broken zstd would.
FAKE_ZSTD = """#!/bin/sh
[ -z "${SYQ_TEST_ZSTD_FAILS:-}" ] || exit 1
exec gzip "$@"
"""
FORMATS = {"gzip": ".gz", "zstd": ".zst"}


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
        # First on the default PATH, so the default is the zstd archive.
        executable(self.fakebin / "zstd", FAKE_ZSTD)
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
        """Write a target's program, which the manifest signs, and both its
        archives; the zstd one holds gzip data for FAKE_ZSTD."""
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
        for suffix in FORMATS.values():
            self.write_archive_of(target, suffix, program.read_bytes())

    def write_archive_of(self, target, suffix, content):
        """Replace one archive of a target with one of `content`, which the
        manifests generated afterwards sign as that archive."""
        archive = subprocess.run(["gzip", "-9", "-n", "-c"], input=content, check=True,
                                 stdout=subprocess.PIPE).stdout
        (self.release / f"syq-{target}{suffix}").write_bytes(archive)

    def write_manifests(self, output, zstd_output):
        artifacts = {}
        archives = {}
        for target in TARGETS:
            program = self.work / f"program-{target}"
            files = {format: self.release / f"syq-{target}{suffix}"
                     for format, suffix in FORMATS.items()}
            artifacts[target] = {
                "binary": {"name": f"syq-{target}", "sha256": sha256(program),
                           "size": program.stat().st_size},
                "archive": {"name": files["gzip"].name, "sha256": sha256(files["gzip"]),
                            "size": files["gzip"].stat().st_size},
            }
            archives[target] = {"name": files["zstd"].name, "sha256": sha256(files["zstd"]),
                                "size": files["zstd"].stat().st_size}
        identity = {"schema": 1, "repository": "https://github.com/greaber/syq",
                    "version": "0.1.0", "tag": "v0.1.0"}
        manifest = dict(identity, artifacts=artifacts,
                        installer={"name": "install.sh", "sha256": "1" * 64, "size": 1},
                        homebrew_formula={"name": "syq.rb", "sha256": "2" * 64, "size": 1})
        output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        zstd_output.write_text(json.dumps(dict(identity, archives=archives,
                                               signature_scheme="ed25519-jcs-v1"),
                                          indent=2, sort_keys=True) + "\n")

    def generate(self, manifest_name, installer_name):
        manifest = self.work / manifest_name
        zstd_manifest = self.work / f"zstd-{manifest_name}"
        self.write_manifests(manifest, zstd_manifest)
        installer = self.work / installer_name
        subprocess.run([str(SCRIPTS / "generate-installer.py"), str(manifest), str(zstd_manifest),
                        str(installer)], check=True)
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
                self.assertIn(f"test fetched syq-{target}.zst", result.stdout)

    def tool_path(self, downloader="curl", zstd=None):
        """A PATH directory with every utility the installer and the fake
        downloader use, `downloader` as the only downloader, and as zstd
        FAKE_ZSTD ("fake"), this host's ("real"), or none."""
        tools = self.work / f"tools-{downloader}-{zstd or 'no'}-zstd"
        if tools.exists():
            return tools
        tools.mkdir()
        checksum_utility = next((candidate for candidate in ("sha256sum", "shasum", "openssl")
                                 if shutil.which(candidate)), None)
        self.assertIsNotNone(checksum_utility)
        for utility in ["cat", "chmod", "cp", "gzip", "head", "mkdir", "mktemp", "mv", "rm", "sed",
                        "tr", "wc", "yes", checksum_utility]:
            (tools / utility).symlink_to(shutil.which(utility))
        shutil.copy(self.fakebin / "uname", tools / "uname")
        executable(tools / downloader, FAKE_CURL if downloader == "curl" else FAKE_WGET)
        if zstd == "fake":
            executable(tools / "zstd", FAKE_ZSTD)
        elif zstd == "real":
            (tools / "zstd").symlink_to(shutil.which("zstd"))
        return tools

    def test_wget_only_download(self):
        result = self.install(self.work / "install-wget", shell="/bin/sh",
                              path=str(self.tool_path("wget")))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.run_program(self.work / "install-wget/syq", "--test-target"),
                         "linux-x86_64")
        self.assertIn("test fetched syq-linux-x86_64.gz", result.stdout)

    def test_downloaders_set_transfer_timeouts(self):
        for downloader, expected_pairs in [
            ("curl", [("--connect-timeout", "10"), ("--speed-time", "30"), ("--speed-limit", "1024")]),
            ("wget", [("--timeout=10", None)]),
        ]:
            with self.subTest(downloader=downloader):
                args_file = self.work / f"args-{downloader}.txt"
                result = self.install(
                    self.work / f"install-timeouts-{downloader}",
                    shell="/bin/sh",
                    path=str(self.tool_path(downloader)),
                    SYQ_TEST_ARGS_FILE=str(args_file),
                )
                self.assertEqual(result.returncode, 0, result.stdout)
                argv = args_file.read_text().splitlines()
                for flag, value in expected_pairs:
                    self.assertIn(flag, argv)
                    if value is not None:
                        index = argv.index(flag)
                        self.assertEqual(argv[index + 1], value)

    def test_the_archive_follows_whether_zstd_is_installed(self):
        for zstd, expected in [("fake", "zstd"), (None, "gzip")]:
            for downloader in ("curl", "wget"):
                with self.subTest(zstd=zstd, downloader=downloader):
                    install_dir = self.work / f"install-{downloader}-{expected}"
                    result = self.install(install_dir, shell="/bin/sh",
                                          path=str(self.tool_path(downloader, zstd)))
                    self.assertEqual(result.returncode, 0, result.stdout)
                    self.assertIn("test fetched syq-linux-x86_64" + FORMATS[expected],
                                  result.stdout)

    def test_a_failed_decompression_keeps_the_working_installation(self):
        install_dir = self.work / "install-broken-zstd"
        self.assertEqual(self.install(install_dir).returncode, 0)
        installed_sha = sha256(install_dir / "syq")
        result = self.install(install_dir, SYQ_TEST_ZSTD_FAILS="1")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("could not decompress the downloaded zstd archive", result.stdout)
        self.assertEqual(sha256(install_dir / "syq"), installed_sha)

    @unittest.skipUnless(shutil.which("zstd"), "this host has no zstd")
    def test_a_real_zstd_archive_installs(self):
        program = self.work / "program-linux-x86_64"
        archive = self.release / "syq-linux-x86_64.zst"
        archive.write_bytes(subprocess.run(["zstd", "-19", "--single-thread", "-q", "-c",
                                            str(program)], check=True,
                                           stdout=subprocess.PIPE).stdout)
        installer = self.generate("real-zstd-manifest.json", "real-zstd-install.sh")
        install_dir = self.work / "install-real-zstd"
        result = self.install(install_dir, installer=installer, shell="/bin/sh",
                              path=str(self.tool_path("curl", "real")))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual((install_dir / "syq").read_bytes(), program.read_bytes())

    def test_an_archive_of_another_binary_is_never_run(self):
        """Each archive matches the digest and size its signed manifest gives,
        but unpacks to a binary other than the one the main manifest signs."""
        marker = self.work / "mismatched-binary-ran"
        signed = (self.work / "program-linux-x86_64").read_bytes()
        other = f"#!/bin/sh\n: > '{marker}'\necho 'syq 0.1.0'\n".encode()
        same_size = (other + b"#" * len(signed))[:len(signed) - 1] + b"\n"
        self.assertLess(len(other), len(signed))
        for format, suffix in FORMATS.items():
            for content, error in [(same_size, "unpacked binary failed SHA-256 verification"),
                                   (other, "unpacked binary")]:
                with self.subTest(format=format, size=len(content)):
                    self.write_archive("linux-x86_64")
                    self.write_archive_of("linux-x86_64", suffix, content)
                    installer = self.generate("mismatched-manifest.json", "mismatched.sh")
                    self.assertIn(f"binary_sha='{sha256(self.work / 'program-linux-x86_64')}'",
                                  installer.read_text())
                    install_dir = self.work / f"install-mismatched-{format}"
                    path = None if format == "zstd" else str(self.tool_path())
                    result = self.install(install_dir, installer=installer, shell="/bin/sh",
                                          path=path)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(error, result.stdout)
                    self.assertIn(f"test fetched syq-linux-x86_64{suffix}", result.stdout)
                    self.assertFalse(marker.exists(), result.stdout)
                    self.assertFalse((install_dir / "syq").exists())

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

    def test_an_endless_download_stops_after_the_archive_size(self):
        for downloader, path in [("curl", None), ("wget", str(self.tool_path("wget")))]:
            with self.subTest(downloader=downloader):
                install_dir = self.work / f"endless-{downloader}"
                result = subprocess.run(
                    ["/bin/sh", str(self.installer), "--bin-dir", str(install_dir)],
                    env=self.env(path=path, SYQ_TEST_ENDLESS_DOWNLOAD="1"),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("downloaded archive is larger than the expected", result.stdout)
                self.assertFalse((install_dir / "syq").exists())

    def test_bad_downloads_keep_the_working_installation(self):
        install_dir = self.work / "install-linux-x86_64"
        self.assertEqual(self.install(install_dir).returncode, 0)
        installed_sha = sha256(install_dir / "syq")
        # A bad download of either archive must not alter a working installation.
        for format, path in [("zstd", None), ("gzip", str(self.tool_path()))]:
            with self.subTest(format=format):
                env = self.env(path=path)
                command = ["/bin/sh", str(self.installer), "--bin-dir", str(install_dir)]
                archive_path = self.release / f"syq-linux-x86_64{FORMATS[format]}"
                archive = archive_path.read_bytes()
                archive_path.write_bytes(archive + b"tamper")
                self.expect_failure("downloaded archive is larger than the expected", command, env)
                self.assertEqual(sha256(install_dir / "syq"), installed_sha)
                archive_path.write_bytes(archive[:-1])
                self.expect_failure("downloaded archive has size", command, env)
                self.assertEqual(sha256(install_dir / "syq"), installed_sha)
                archive_path.write_bytes(archive[:-1] + bytes([archive[-1] ^ 1]))
                self.expect_failure("failed SHA-256 verification", command, env)
                self.assertEqual(sha256(install_dir / "syq"), installed_sha)
                archive_path.write_bytes(archive)

        # Even correctly hashed content is rejected if its build identity does not
        # match the release metadata, again without replacing the installed binary.
        self.write_archive("linux-x86_64", "0.1.0", "v0.1.0+dev.wrong")
        wrong = self.generate("wrong-identity-manifest.json", "wrong-identity-install.sh")
        self.expect_failure("unexpected identity",
                            ["sh", str(wrong), "--bin-dir", str(install_dir)], self.env())
        self.assertEqual(sha256(install_dir / "syq"), installed_sha)


if __name__ == "__main__":
    unittest.main()
