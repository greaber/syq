"""Typed native-command and safe subprocess access to syq."""

from importlib.metadata import version as distribution_version

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
    CpPruneResult,
    CpResult,
    Disposition,
    EntryKind,
    ErrorEvent,
    MappingEntry,
    OperationResult,
    OperationStatus,
    PathValue,
    RelativePath,
    Retryability,
    RmResult,
    RunEvent,
    WarningEvent,
)

_default_client = Client()
cp = _default_client.cp
cp_prune = _default_client.cp_prune
rm = _default_client.rm
map = _default_client.map

__all__ = [
    "PINNED_SYQ_VERSION",
    "AutomationEvent",
    "Client",
    "CpPruneResult",
    "CpResult",
    "Disposition",
    "EntryKind",
    "ErrorEvent",
    "MapStream",
    "MappingEntry",
    "OperationResult",
    "OperationStatus",
    "PathValue",
    "RelativePath",
    "Result",
    "Retryability",
    "RmResult",
    "RunEvent",
    "SyqInstallError",
    "SyqInvocationError",
    "SyqOperationError",
    "SyqOutputError",
    "SyqProcessError",
    "SyqProtocolError",
    "WarningEvent",
    "cp",
    "cp_prune",
    "managed_executable",
    "map",
    "rm",
    "run",
    "version",
]

__version__ = distribution_version("syq")
