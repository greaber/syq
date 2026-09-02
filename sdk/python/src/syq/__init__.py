"""Typed native-command and safe subprocess access to syq."""

from importlib.metadata import version as distribution_version

from .async_client import AsyncClient, AsyncMapStream
from .bootstrap import PINNED_SYQ_VERSION, SyqInstallError, managed_executable
from .client import Client, MapStream, Result, run, version
from .errors import (
    SyqInvocationError,
    SyqOperationError,
    SyqOutputError,
    SyqProcessError,
    SyqProtocolError,
)
from .models import (
    AutomationEvent,
    CpResult,
    Disposition,
    Endpoint,
    EndpointKind,
    EndpointRole,
    EntryKind,
    ErrorClass,
    ErrorEvent,
    IgnoreFrom,
    MappingEntry,
    OperationAction,
    OperationResult,
    OperationStatus,
    OsKind,
    PathValue,
    ProgressEvent,
    RelativePath,
    Retryability,
    RunEvent,
    TraceEvent,
    TraceReason,
)

_default_client = Client()
cp = _default_client.cp
map = _default_client.map

__all__ = [
    "PINNED_SYQ_VERSION",
    "AsyncClient",
    "AsyncMapStream",
    "AutomationEvent",
    "Client",
    "CpResult",
    "Disposition",
    "Endpoint",
    "EndpointKind",
    "EndpointRole",
    "EntryKind",
    "ErrorClass",
    "ErrorEvent",
    "IgnoreFrom",
    "MapStream",
    "MappingEntry",
    "OperationAction",
    "OperationResult",
    "OperationStatus",
    "OsKind",
    "PathValue",
    "ProgressEvent",
    "RelativePath",
    "Result",
    "Retryability",
    "RunEvent",
    "SyqInstallError",
    "SyqInvocationError",
    "SyqOperationError",
    "SyqOutputError",
    "SyqProcessError",
    "SyqProtocolError",
    "TraceEvent",
    "TraceReason",
    "cp",
    "managed_executable",
    "map",
    "run",
    "version",
]

__version__ = distribution_version("syq")
