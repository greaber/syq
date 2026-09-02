"""Value objects for syq's mapping and automation protocols."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any


class _StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class EntryKind(_StringEnum):
    FILE = "file"
    DIR = "dir"
    SYMLINK = "symlink"
    SPECIAL = "special"


class Disposition(_StringEnum):
    PLANNED = "planned"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class Retryability(_StringEnum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


class OperationStatus(_StringEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    REFUSED = "refused"
    FAILED = "failed"


def _path_bytes(value: str | bytes | os.PathLike[str] | os.PathLike[bytes]) -> bytes:
    path = os.fspath(value)
    if isinstance(path, str):
        return os.fsencode(path)
    if isinstance(path, bytes):
        return path
    raise TypeError("path must resolve to str or bytes")


@dataclass(frozen=True, slots=True)
class PathValue:
    """A lossless path from an automation event."""

    raw: bytes
    display: str

    @property
    def text(self) -> str:
        """Decode the path as UTF-8, raising when it is a byte-only path."""

        return self.raw.decode("utf-8")

    def __bytes__(self) -> bytes:
        return self.raw

    def __str__(self) -> str:
        return self.display


@dataclass(frozen=True, slots=True, init=False)
class RelativePath:
    """A validated, byte-preserving path in a syq mapping."""

    raw: bytes

    def __init__(
        self, value: str | bytes | os.PathLike[str] | os.PathLike[bytes]
    ) -> None:
        raw = _path_bytes(value)
        if not raw:
            raise ValueError("mapping paths may not be empty")
        if b"\0" in raw:
            raise ValueError("mapping paths may not contain NUL")
        if raw.startswith(b"/"):
            raise ValueError("mapping paths must be relative")
        if any(component in {b"", b".", b".."} for component in raw.split(b"/")):
            raise ValueError("mapping paths may not contain empty, '.' or '..' components")
        object.__setattr__(self, "raw", raw)

    @property
    def text(self) -> str:
        """Decode the path as UTF-8, raising when it is a byte-only path."""

        return self.raw.decode("utf-8")

    def __bytes__(self) -> bytes:
        return self.raw

    def __fspath__(self) -> bytes:
        return self.raw

    def __str__(self) -> str:
        return os.fsdecode(self.raw)

    def __truediv__(
        self, other: str | bytes | os.PathLike[str] | os.PathLike[bytes]
    ) -> RelativePath:
        return RelativePath(self.raw + b"/" + _path_bytes(other))


@dataclass(frozen=True, slots=True)
class MappingEntry:
    src: RelativePath
    dst: RelativePath
    kind: EntryKind | None = None
    size: int | None = None
    mtime: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.src, RelativePath):
            object.__setattr__(self, "src", RelativePath(self.src))
        if not isinstance(self.dst, RelativePath):
            object.__setattr__(self, "dst", RelativePath(self.dst))
        if self.kind is not None and not isinstance(self.kind, EntryKind):
            try:
                object.__setattr__(self, "kind", EntryKind(self.kind))
            except ValueError as error:
                raise ValueError(f"unknown mapping kind: {self.kind!r}") from error
        for label, value in (("size", self.size), ("mtime", self.mtime)):
            if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
                raise TypeError(f"{label} must be an integer or None")
        if self.size is not None and self.size < 0:
            raise ValueError("size must not be negative")


@dataclass(frozen=True, slots=True)
class RunEvent:
    schema: str
    schema_version: int
    run_id: str
    seq: int
    elapsed_ms: int
    syq_version: str
    mode: str
    dry_run: bool
    mapping: bool
    type: str = "run"


@dataclass(frozen=True, slots=True)
class OperationResult:
    schema: str
    schema_version: int
    run_id: str
    seq: int
    elapsed_ms: int
    action: str
    dst: PathValue
    src: PathValue | None
    kind: str
    disposition: Disposition
    bytes: int | None
    attempts: int | None
    retryable: Retryability | None
    message: str | None
    type: str = "operation_result"

    @property
    def is_retryable(self) -> bool:
        return (
            self.disposition is Disposition.FAILED
            and self.retryable is not Retryability.NO
        )

    def retry_entry(self) -> MappingEntry | None:
        if not self.is_retryable or self.src is None:
            return None
        try:
            kind = EntryKind(self.kind)
            return MappingEntry(
                RelativePath(self.src.raw),
                RelativePath(self.dst.raw),
                kind,
            )
        except ValueError:
            return None


@dataclass(frozen=True, slots=True)
class WarningEvent:
    schema: str
    schema_version: int
    run_id: str
    seq: int
    elapsed_ms: int
    code: str
    count: int
    message: str
    type: str = "warning"


@dataclass(frozen=True, slots=True)
class ErrorEvent:
    schema: str
    schema_version: int
    run_id: str
    seq: int
    elapsed_ms: int
    error_class: str
    retryable: Retryability
    message: str
    type: str = "error"


@dataclass(frozen=True, slots=True)
class OperationSummary:
    schema: str
    schema_version: int
    run_id: str
    seq: int
    elapsed_ms: int
    status: OperationStatus
    exit_code: int
    dry_run: bool
    files_planned: int
    files_completed: int
    files_unchanged: int
    files_excluded: int
    directories_planned: int
    directories_completed: int
    symlinks_planned: int
    symlinks_completed: int
    specials_planned: int
    specials_completed: int
    deletions_planned: int
    deletions_completed: int
    deletions_blocked: bool
    errors: int
    bytes_planned: int
    bytes_completed: int
    bytes_unchanged: int
    type: str = "result"


@dataclass(frozen=True, slots=True)
class CpResult(OperationSummary):
    pass


@dataclass(frozen=True, slots=True)
class CpPruneResult(OperationSummary):
    pass


@dataclass(frozen=True, slots=True)
class RmResult(OperationSummary):
    pass


AutomationEvent = (
    RunEvent
    | OperationResult
    | WarningEvent
    | ErrorEvent
    | CpResult
    | CpPruneResult
    | RmResult
)


def _tagged_path(path: RelativePath) -> dict[str, str]:
    try:
        value = path.raw.decode("utf-8")
    except UnicodeDecodeError:
        return {
            "encoding": "base64",
            "value": base64.b64encode(path.raw).decode("ascii"),
        }
    return {"encoding": "utf-8", "value": value}


def _mapping_json(entry: MappingEntry) -> dict[str, Any]:
    record: dict[str, Any] = {
        "src": _tagged_path(entry.src),
        "dst": _tagged_path(entry.dst),
    }
    if entry.kind is not None:
        record["kind"] = entry.kind.value
    if entry.size is not None:
        record["size"] = entry.size
    if entry.mtime is not None:
        record["mtime"] = entry.mtime
    return record
