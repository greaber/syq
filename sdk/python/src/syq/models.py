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


class EndpointKind(_StringEnum):
    LOCAL = "local"
    SSH = "ssh"


class EndpointRole(_StringEnum):
    SOURCE = "source"
    DESTINATION = "destination"


class OperationAction(_StringEnum):
    TRANSFER_FILE = "transfer_file"
    CREATE_DIRECTORY = "create_directory"
    CREATE_SYMLINK = "create_symlink"
    CREATE_SPECIAL = "create_special"
    DELETE = "delete"
    SET_METADATA = "set_metadata"
    OBSERVE_HASH = "observe_hash"


class Disposition(_StringEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    INCOMPLETE = "incomplete"
    OBSERVED = "observed"


class ReceiptCode(_StringEnum):
    NONE = "none"
    EXECUTION_FAILED = "execution_failed"
    AUTHORIZATION_REFUSED = "authorization_refused"
    FILE_LIFECYCLE_INCOMPLETE = "file_lifecycle_incomplete"
    OBSERVATION_FAILED = "observation_failed"


class FinalObjectState(_StringEnum):
    PRESENT = "present"
    ABSENT = "absent"
    OBSERVATION_FAILED = "observation_failed"


class FinalObjectKind(_StringEnum):
    """The receiver's final-state vocabulary for what an object is."""

    DIR = "dir"
    FILE = "file"
    SYMLINK = "symlink"
    FIFO = "fifo"
    SOCKET = "socket"
    CHARACTER_DEVICE = "character_device"
    BLOCK_DEVICE = "block_device"
    OTHER = "other"


class ReceiptStatus(_StringEnum):
    CLEAN = "clean"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


class Retryability(_StringEnum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


class ErrorClass(_StringEnum):
    IO = "io"
    TRANSPORT = "transport"
    CONFLICT = "conflict"
    INTEGRITY = "integrity"
    SAFETY_LIMIT = "safety_limit"
    USAGE = "usage"
    INTERNAL = "internal"


class OsKind(_StringEnum):
    NOT_FOUND = "not_found"
    PERMISSION_DENIED = "permission_denied"
    ALREADY_EXISTS = "already_exists"
    INVALID_INPUT = "invalid_input"
    NO_SPACE = "no_space"
    QUOTA_EXCEEDED = "quota_exceeded"
    READ_ONLY = "read_only"
    OTHER = "other"


class TraceReason(_StringEnum):
    DESTINATION_MISSING = "destination_missing"
    TYPE_DIFFERS = "type_differs"
    CONTENT_DIFFERS = "content_differs"
    METADATA_DIFFERS = "metadata_differs"
    DESTINATION_ONLY = "destination_only"


class OperationStatus(_StringEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    REFUSED = "refused"
    ABORTED = "aborted"
    FAILED = "failed"


class SelectionStatus(_StringEnum):
    RESOLVED = "resolved"
    MISSING = "missing"


class RemovalDisposition(_StringEnum):
    WOULD_REMOVE = "would_remove"
    REMOVED = "removed"
    ALREADY_ABSENT = "already_absent"
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

    @property
    def text(self) -> str:
        """Decode the path as UTF-8, raising when it is a byte-only path."""

        return self.raw.decode("utf-8")

    @property
    def display(self) -> str:
        """Return a lossy display spelling without making it protocol data."""

        return os.fsdecode(self.raw)

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
class IgnoreFrom:
    """An ordered ``--ignore-from`` occurrence in an ``ignore`` stream."""

    path: str | bytes | os.PathLike[str] | os.PathLike[bytes]


@dataclass(frozen=True, slots=True)
class Endpoint:
    role: EndpointRole
    kind: EndpointKind
    host: str | None = None
    user: str | None = None


@dataclass(frozen=True, slots=True)
class RunEvent:
    schema: str
    schema_version: int
    seq: int
    run_id: str
    started_at: int
    syq_version: str
    mode: str
    prune: bool | None
    mapping: bool | None
    dry_run: bool
    endpoints: tuple[Endpoint, ...]
    type: str = "run"


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    schema: str
    schema_version: int
    seq: int
    bytes_done: int
    bytes_total: int
    bytes_unchanged: int
    files_done: int
    files_total: int
    files_unchanged: int
    files_excluded: int
    scanned: int
    scan_done: bool
    elapsed_ms: int
    destination_index: int | None = None
    type: str = "progress"


@dataclass(frozen=True, slots=True)
class TraceEvent:
    schema: str
    schema_version: int
    seq: int
    action: OperationAction
    dst: PathValue
    src: PathValue | None
    kind: EntryKind
    bytes: int | None
    reason: TraceReason
    destination_index: int | None = None
    type: str = "trace"


@dataclass(frozen=True, slots=True)
class OperationResult:
    schema: str
    schema_version: int
    seq: int
    action: OperationAction
    dst: PathValue
    src: PathValue | None
    kind: EntryKind | None
    disposition: Disposition
    bytes: int | None
    attempts: int | None
    retryable: Retryability | None
    class_: ErrorClass | None
    os_kind: OsKind | None
    message: str | None
    destination_index: int | None = None
    provenance: str | None = None
    scope: int | None = None
    code: ReceiptCode | None = None
    type: str = "operation_result"

    @property
    def is_retryable(self) -> bool:
        return (
            self.disposition is Disposition.FAILED
            and self.retryable is not Retryability.NO
        )

    def retry_entry(self) -> MappingEntry | None:
        if not self.is_retryable or self.src is None or self.kind is None:
            return None
        try:
            return MappingEntry(
                RelativePath(self.src.raw),
                RelativePath(self.dst.raw),
                self.kind,
            )
        except ValueError:
            return None


@dataclass(frozen=True, slots=True)
class SelectionResult:
    schema: str
    schema_version: int
    seq: int
    selector: int
    path: PathValue
    status: SelectionStatus
    kind: EntryKind | None
    type: str = "selection_result"


@dataclass(frozen=True, slots=True)
class RemovalTrace:
    schema: str
    schema_version: int
    seq: int
    selector: int
    path: PathValue
    kind: EntryKind
    disposition: RemovalDisposition
    type: str = "removal_trace"


@dataclass(frozen=True, slots=True)
class RemovalResult:
    schema: str
    schema_version: int
    seq: int
    selector: int
    path: PathValue
    kind: EntryKind | None
    disposition: RemovalDisposition
    attempts: int
    retryable: Retryability | None
    class_: ErrorClass | None
    os_kind: OsKind | None
    message: str | None
    type: str = "removal_result"


@dataclass(frozen=True, slots=True)
class ErrorEvent:
    schema: str
    schema_version: int
    seq: int
    message: str
    class_: ErrorClass | None
    os_kind: OsKind | None
    destination_index: int | None = None
    provenance: str | None = None
    code: ReceiptCode | None = None
    type: str = "error"


@dataclass(frozen=True, slots=True)
class ObjectMetadata:
    """Filesystem metadata the receiver attested for a final object."""

    mode: int
    uid: int
    gid: int
    mtime: int
    mtime_nsec: int
    rdev: int


@dataclass(frozen=True, slots=True)
class AttestedDigest:
    """A content digest from the receipt, algorithm included."""

    algorithm: str
    value: str


@dataclass(frozen=True, slots=True)
class FinalStateEvent:
    """A receiver-attested closure-time observation of one touched path."""

    schema: str
    schema_version: int
    seq: int
    provenance: str
    scope: int
    dst: PathValue
    state: FinalObjectState
    kind: FinalObjectKind | None
    size: int | None
    metadata: ObjectMetadata | None
    digest: AttestedDigest | None
    symlink_target: PathValue | None
    observation_error: str | None
    code: ReceiptCode | None
    message: str | None
    type: str = "final_state"


class OperationSummary:
    """Common runtime type for typed terminal results."""

    __slots__ = ()

    schema: str
    schema_version: int
    seq: int
    status: OperationStatus
    exit_code: int
    dry_run: bool
    errors: int
    elapsed_ms: int


@dataclass(frozen=True, slots=True)
class CpResult(OperationSummary):
    schema: str
    schema_version: int
    seq: int
    status: OperationStatus
    exit_code: int
    dry_run: bool
    files_transferred: int
    files_unchanged: int
    files_excluded: int
    directories_created: int
    symlinks_created: int
    specials_created: int
    errors: int
    bytes_transferred: int
    bytes_unchanged: int
    elapsed_ms: int
    deletions_planned: int | None
    deletions_completed: int | None
    deletions_blocked: int | None
    provenance: str | None = None
    receipt_status: ReceiptStatus | None = None
    operations: int | None = None
    final_states: int | None = None
    receipt_records: int | None = None
    type: str = "result"


@dataclass(frozen=True, slots=True)
class DestinationResult(OperationSummary):
    """The settled outcome for one target in a multi-target copy."""

    schema: str
    schema_version: int
    seq: int
    destination_index: int
    status: OperationStatus
    exit_code: int
    dry_run: bool
    files_transferred: int
    files_unchanged: int
    files_excluded: int
    directories_created: int
    symlinks_created: int
    specials_created: int
    errors: int
    bytes_transferred: int
    bytes_unchanged: int
    elapsed_ms: int
    deletions_planned: int | None
    deletions_completed: int | None
    deletions_blocked: int | None
    type: str = "destination_result"


@dataclass(frozen=True, slots=True)
class RmResult(OperationSummary):
    schema: str
    schema_version: int
    seq: int
    status: OperationStatus
    exit_code: int
    dry_run: bool
    selectors_total: int
    selectors_resolved: int
    selectors_missing: int
    entries_planned: int
    entries_removed: int
    entries_already_absent: int
    entries_failed: int
    errors: int
    elapsed_ms: int
    mode: str = "rm"
    type: str = "result"


AutomationEvent = (
    RunEvent
    | ProgressEvent
    | DestinationResult
    | TraceEvent
    | OperationResult
    | SelectionResult
    | RemovalTrace
    | RemovalResult
    | ErrorEvent
    | FinalStateEvent
    | CpResult
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
