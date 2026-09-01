"""Minimal process adapter for syq's command-line interface."""

from __future__ import annotations

import os
import signal
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .bootstrap import managed_executable


@dataclass(frozen=True, slots=True)
class Result:
    """The complete result of one syq process."""

    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


class SyqProcessError(RuntimeError):
    """A syq process completed with a nonzero status."""

    def __init__(self, result: Result) -> None:
        self.result = result
        super().__init__(f"syq exited with status {result.returncode}")


class SyqOutputError(ValueError):
    """syq returned output that the requested operation cannot interpret."""


def _text_arg(value: str | os.PathLike[str], *, label: str) -> str:
    result = os.fspath(value)
    if not isinstance(result, str):
        raise TypeError(f"{label} must resolve to text, not bytes")
    return result


def run(
    args: Sequence[str | os.PathLike[str]],
    *,
    executable: str | os.PathLike[str] | None = None,
    check: bool = True,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
) -> Result:
    """Run syq without a shell and capture its complete byte output.

    ``args`` contains only arguments after the executable name. By default the
    SDK downloads and uses its pinned syq release. Passing ``executable`` opts
    into an untested custom binary. A missing custom executable, timeout, or
    other spawn failure is reported by ``subprocess``. A completed nonzero
    process raises :class:`SyqProcessError` unless ``check`` is false.
    """

    if isinstance(args, (str, bytes, os.PathLike)):
        raise TypeError("args must be a sequence of individual arguments")
    executable_text = (
        os.fspath(managed_executable())
        if executable is None
        else _text_arg(executable, label="executable")
    )
    argument_text = tuple(
        _text_arg(argument, label=f"args[{index}]")
        for index, argument in enumerate(args)
    )
    argv = (executable_text, *argument_text)
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    result = Result(
        argv=argv,
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
    )
    if check and result.returncode != 0:
        raise SyqProcessError(result)
    return result


def version(*, executable: str | os.PathLike[str] | None = None) -> str:
    """Return the version of the pinned or explicitly overridden executable."""

    result = run(["--version"], executable=executable)
    try:
        output = result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise SyqOutputError("syq --version did not return UTF-8") from error
    prefix = "syq "
    if not output.startswith(prefix) or len(output) == len(prefix):
        raise SyqOutputError(f"unexpected syq --version output: {output!r}")
    return output[len(prefix) :]
