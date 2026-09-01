"""Safe subprocess access to the syq executable."""

from importlib.metadata import version as distribution_version

from .client import Result, SyqOutputError, SyqProcessError, run, version

__all__ = [
    "Result",
    "SyqOutputError",
    "SyqProcessError",
    "run",
    "version",
]

__version__ = distribution_version("syq")
