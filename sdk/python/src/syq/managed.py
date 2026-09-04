"""Install the syq release pinned by this Python package."""

from __future__ import annotations

import gzip
import hashlib
import http.client
import json
import os
import platform
import stat
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any, BinaryIO


_DOWNLOAD_TIMEOUT_SECONDS = 30
_CHUNK_SIZE = 1024 * 1024
_EXPECTED_REPOSITORY = "https://github.com/greaber/syq"


class SyqInstallError(RuntimeError):
    """The SDK could not install or validate its pinned syq executable."""


@dataclass(frozen=True, slots=True)
class _Artifact:
    target: str
    archive_name: str
    archive_sha256: str
    archive_size: int
    binary_sha256: str
    binary_size: int


@lru_cache(maxsize=1)
def _load_release_manifest() -> dict[str, Any]:
    try:
        raw = files("syq").joinpath("syq-release-manifest.json").read_bytes()
        manifest = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SyqInstallError(
            "the packaged syq release manifest is invalid"
        ) from error
    if not isinstance(manifest, dict):
        raise SyqInstallError("the packaged syq release manifest is not an object")
    if manifest.get("repository") != _EXPECTED_REPOSITORY:
        raise SyqInstallError("the packaged syq release repository is unexpected")
    version = manifest.get("version")
    tag = manifest.get("tag")
    if not isinstance(version, str) or tag != f"v{version}":
        raise SyqInstallError("the packaged syq release version is invalid")
    return manifest


PINNED_SYQ_VERSION = str(_load_release_manifest()["version"])


def _host_target() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "linux" and machine in {"x86_64", "amd64"}:
        return "linux-x86_64"
    if system == "linux" and machine in {"aarch64", "arm64"}:
        return "linux-aarch64"
    if system == "darwin" and machine in {"arm64", "aarch64"}:
        return "macos-arm64"
    if system == "darwin" and machine in {"x86_64", "amd64"}:
        return "macos-x86_64"
    raise SyqInstallError(
        f"syq {PINNED_SYQ_VERSION} has no binary for {system or 'unknown'} "
        f"{machine or 'unknown'}"
    )


def _positive_integer(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise SyqInstallError(f"the packaged {label} is invalid")
    return value


def _digest(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SyqInstallError(f"the packaged {label} is invalid")
    return value


def _artifact(manifest: dict[str, Any], target: str) -> _Artifact:
    try:
        entry = manifest["artifacts"][target]
        archive = entry["archive"]
        binary = entry["binary"]
    except (KeyError, TypeError) as error:
        raise SyqInstallError(f"the packaged metadata has no {target} artifact") from error
    if not isinstance(archive, dict) or not isinstance(binary, dict):
        raise SyqInstallError(f"the packaged metadata has an invalid {target} artifact")
    archive_name = archive.get("name")
    if (
        not isinstance(archive_name, str)
        or not archive_name.startswith("syq-")
        or not archive_name.endswith(".gz")
        or "/" in archive_name
        or "\\" in archive_name
    ):
        raise SyqInstallError("the packaged archive name is invalid")
    return _Artifact(
        target=target,
        archive_name=archive_name,
        archive_sha256=_digest(archive.get("sha256"), label="archive digest"),
        archive_size=_positive_integer(archive.get("size"), label="archive size"),
        binary_sha256=_digest(binary.get("sha256"), label="binary digest"),
        binary_size=_positive_integer(binary.get("size"), label="binary size"),
    )


def _default_cache_root() -> Path:
    configured = os.environ.get("XDG_CACHE_HOME")
    if configured and os.path.isabs(configured):
        return Path(configured)
    try:
        return Path.home() / ".cache"
    except RuntimeError as error:
        raise SyqInstallError("could not locate the user cache directory") from error


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _matches(path: Path, *, size: int, sha256: str) -> bool:
    try:
        metadata = path.stat(follow_symlinks=False)
        return (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_size == size
            and _sha256_file(path) == sha256
        )
    except OSError:
        return False


def _copy_bounded(
    source: BinaryIO,
    destination: BinaryIO,
    *,
    expected_size: int,
    label: str,
) -> str:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = source.read(min(_CHUNK_SIZE, expected_size + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > expected_size:
            raise SyqInstallError(f"the downloaded {label} is larger than expected")
        digest.update(chunk)
        destination.write(chunk)
    if total != expected_size:
        raise SyqInstallError(
            f"the downloaded {label} has size {total}, expected {expected_size}"
        )
    return digest.hexdigest()


def _download_archive(url: str, destination: Path, artifact: _Artifact) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "syq-python-sdk"})
    try:
        with urllib.request.urlopen(
            request, timeout=_DOWNLOAD_TIMEOUT_SECONDS
        ) as response, destination.open("wb") as output:
            final_url = response.geturl()
            if urllib.parse.urlparse(final_url).scheme != "https":
                raise SyqInstallError("the syq download redirected away from HTTPS")
            actual_sha256 = _copy_bounded(
                response,
                output,
                expected_size=artifact.archive_size,
                label="archive",
            )
    except SyqInstallError:
        raise
    except (OSError, http.client.HTTPException, urllib.error.URLError) as error:
        raise SyqInstallError(f"could not download pinned syq from {url}") from error
    if actual_sha256 != artifact.archive_sha256:
        raise SyqInstallError("the downloaded syq archive failed SHA-256 verification")


def _decompress_archive(
    archive_path: Path, binary_path: Path, artifact: _Artifact
) -> None:
    try:
        with gzip.open(archive_path, "rb") as source, binary_path.open("wb") as output:
            actual_sha256 = _copy_bounded(
                source,
                output,
                expected_size=artifact.binary_size,
                label="binary",
            )
    except SyqInstallError:
        raise
    except (EOFError, gzip.BadGzipFile, OSError) as error:
        raise SyqInstallError("could not decompress the pinned syq archive") from error
    if actual_sha256 != artifact.binary_sha256:
        raise SyqInstallError("the downloaded syq binary failed SHA-256 verification")


def _query_binary(path: Path, argument: str) -> str:
    try:
        completed = subprocess.run(
            [os.fspath(path), argument],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SyqInstallError("the downloaded syq binary could not run") from error
    try:
        output = completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise SyqInstallError(
            "the downloaded syq binary returned invalid output"
        ) from error
    if completed.returncode != 0:
        raise SyqInstallError(
            f"the downloaded syq binary rejected {argument} with status "
            f"{completed.returncode}"
        )
    return output


def _validate_binary(path: Path, manifest: dict[str, Any]) -> None:
    version = manifest["version"]
    tag = manifest["tag"]
    if _query_binary(path, "--version") != f"syq {version}":
        raise SyqInstallError("the downloaded binary reports an unexpected version")
    if _query_binary(path, "--build-identity") != tag:
        raise SyqInstallError("the downloaded binary reports an unexpected build identity")


def managed_executable(
    *, cache_dir: str | os.PathLike[str] | None = None
) -> Path:
    """Return the verified executable pinned by this SDK, downloading if needed.

    The executable is cached by syq release and host target. Its complete bytes
    are checked against the manifest packaged in this SDK before every use.
    """

    manifest = _load_release_manifest()
    target = _host_target()
    artifact = _artifact(manifest, target)
    cache_root = (
        Path(cache_dir) if cache_dir is not None else _default_cache_root()
    )
    install_dir = (
        cache_root
        / "syq"
        / "sdk"
        / "python"
        / f"v{manifest['version']}"
        / target
    )
    try:
        install_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as error:
        raise SyqInstallError(f"could not prepare syq SDK cache at {install_dir}") from error
    executable = install_dir / "syq"
    if _matches(
        executable, size=artifact.binary_size, sha256=artifact.binary_sha256
    ):
        try:
            executable.chmod(0o755)
        except OSError as error:
            raise SyqInstallError(
                f"could not make cached syq executable: {executable}"
            ) from error
        return executable

    base_url = f"{manifest['repository']}/releases/download/{manifest['tag']}"
    url = f"{base_url}/{artifact.archive_name}"
    archive_path: Path | None = None
    binary_path: Path | None = None
    try:
        archive_file = tempfile.NamedTemporaryFile(
            prefix=".syq-download-", suffix=".gz", dir=install_dir, delete=False
        )
        archive_path = Path(archive_file.name)
        archive_file.close()
        binary_file = tempfile.NamedTemporaryFile(
            prefix=".syq-install-", dir=install_dir, delete=False
        )
        binary_path = Path(binary_file.name)
        binary_file.close()
        _download_archive(url, archive_path, artifact)
        _decompress_archive(archive_path, binary_path, artifact)
        binary_path.chmod(0o755)
        _validate_binary(binary_path, manifest)
        os.replace(binary_path, executable)
        binary_path = None
        return executable
    except SyqInstallError:
        raise
    except OSError as error:
        raise SyqInstallError(f"could not install pinned syq at {executable}") from error
    finally:
        for temporary_path in (archive_path, binary_path):
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass
