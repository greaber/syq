from __future__ import annotations

import tempfile
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
