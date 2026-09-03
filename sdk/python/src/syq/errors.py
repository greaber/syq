"""Public exception types for the syq Python API."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .client import Result
    from .models import OperationSummary


class SyqInvocationError(ValueError):
    """Python inputs cannot form a valid native syq invocation."""


class SyqProcessError(RuntimeError):
    """A raw syq process completed with a nonzero status."""

    def __init__(self, result: Result) -> None:
        self.result = result
        super().__init__(f"syq exited with status {result.returncode}")


class SyqOutputError(ValueError):
    """A raw syq helper returned output it cannot interpret."""


class SyqProtocolError(ValueError):
    """A typed operation returned an invalid or incomplete automation stream."""

    def __init__(
        self,
        message: str,
        *,
        returncode: int | None = None,
        stderr: bytes = b"",
    ) -> None:
        self.returncode = returncode
        self.stderr = stderr[-8192:]
        super().__init__(message)


class SyqOperationError(RuntimeError):
    """A valid automation result reports a non-successful operation."""

    def __init__(self, result: OperationSummary, *, stderr: bytes = b"") -> None:
        self.result = result
        self.stderr = stderr[-8192:]
        super().__init__(
            f"syq {result.status.value} with status {result.exit_code}"
        )
