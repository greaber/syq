"""Application callbacks used as mapping endpoints."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class StreamSource:
    """Produce one entry's bytes when the copy admits it.

    The callback receives a binary writer. Returning normally permits publication;
    closing the writer alone does not. ``size`` is an optional exact byte count.
    """

    produce: Callable[..., object]
    size: int | None = field(default=None, kw_only=True)

    def __post_init__(self) -> None:
        if not callable(self.produce):
            raise TypeError("produce must be callable")
        if self.size is not None and (
            isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or not 0 <= self.size <= 2**64 - 1
        ):
            raise ValueError("stream size must be an unsigned 64-bit integer or None")


@dataclass(frozen=True, slots=True)
class StreamDestination:
    """Consume one entry's bytes through a binary reader.

    Normal callback return drains any remaining bytes and checks the transfer.
    The callback controls any files or other side effects it creates.
    """

    consume: Callable[..., object]

    def __post_init__(self) -> None:
        if not callable(self.consume):
            raise TypeError("consume must be callable")
