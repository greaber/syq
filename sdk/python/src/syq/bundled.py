"""Locate the executable installed by this Python distribution."""

from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

from .managed import SyqInstallError


def bundled_executable() -> Path:
    """Return this distribution's binary without downloading or searching PATH."""
    try:
        package = distribution("syq")
    except PackageNotFoundError as error:
        raise SyqInstallError(
            "syq is not installed; install its wheel or pass executable= explicitly"
        ) from error
    # Wheel installers record the scripts path relative to site-packages in
    # RECORD. This also works for user installs and environments not on PATH.
    matches = [
        package.locate_file(entry)
        for entry in package.files or ()
        if entry.name == "syq" and entry.parent.name in {"bin", "Scripts"}
    ]
    if len(matches) != 1 or not matches[0].is_file():
        raise SyqInstallError(
            "the installed syq package has no bundled executable; "
            "reinstall its wheel or pass executable= explicitly"
        )
    return Path(matches[0])
