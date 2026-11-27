from __future__ import annotations

import asyncio
import fcntl
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


def resolved_temporary_directory(
    *,
    suffix: str | None = None,
    prefix: str | None = None,
) -> tempfile.TemporaryDirectory[str]:
    """Create a temporary directory below the physical temporary root so host
    symlinks such as macOS /var -> /private/var do not enter paths under test."""

    return tempfile.TemporaryDirectory(
        suffix=suffix,
        prefix=prefix,
        dir=Path(tempfile.gettempdir()).resolve(),
    )


def warm_executable(path: str | os.PathLike[str], *args: str) -> None:
    """Run a newly written fixture script once before any timed test so
    first-exec OS scanning does not eat into a short test timeout."""

    subprocess.run(
        [os.fspath(path), *args],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def assert_descendant_exited(
    test_case: unittest.TestCase,
    marker: Path,
    *,
    timeout: float = 2.0,
) -> None:
    """Confirm the fake descendant holding marker.lock exited after cleanup."""

    lock_path = marker.with_suffix(".lock")
    test_case.assertTrue(
        marker.with_suffix(".ready").exists(),
        f"descendant never became ready: {marker}",
    )
    deadline = time.monotonic() + timeout
    with lock_path.open("rb") as lock_file:
        while True:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    test_case.fail(
                        f"descendant still holds {lock_path} after {timeout}s"
                    )
                time.sleep(0.005)
            else:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
                return


async def async_assert_descendant_exited(
    test_case: unittest.TestCase,
    marker: Path,
    *,
    timeout: float = 2.0,
) -> None:
    """Async counterpart to assert_descendant_exited()."""

    lock_path = marker.with_suffix(".lock")
    test_case.assertTrue(
        marker.with_suffix(".ready").exists(),
        f"descendant never became ready: {marker}",
    )
    deadline = time.monotonic() + timeout
    with lock_path.open("rb") as lock_file:
        while True:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    test_case.fail(
                        f"descendant still holds {lock_path} after {timeout}s"
                    )
                await asyncio.sleep(0.005)
            else:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
                return
