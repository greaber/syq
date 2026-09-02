"""Safe subprocess access to the syq executable."""

from importlib.metadata import version as distribution_version

from .bootstrap import PINNED_SYQ_VERSION, SyqInstallError, managed_executable
from .client import Result, SyqOutputError, SyqProcessError, run, version

__all__ = [
    "PINNED_SYQ_VERSION",
    "Result",
    "SyqInstallError",
    "SyqOutputError",
    "SyqProcessError",
    "managed_executable",
    "run",
    "version",
]

__version__ = distribution_version("syq")
