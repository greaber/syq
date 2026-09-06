"""Lazy mapping transformations that preserve local source context."""

from __future__ import annotations

import inspect
from collections.abc import (
    AsyncIterable, AsyncIterator, Awaitable, Callable, Iterable, Iterator,
)
from dataclasses import dataclass
from pathlib import Path

from ._paths import PathArgument, _map_stream_cwd
from .errors import SyqInvocationError
from .models import MappingEntry


@dataclass(frozen=True, slots=True)
class _Source:
    base: Path
    confined: bool
    follow_src: bool


class _ContextMapping:
    def __init__(
        self, *,
        cwd: PathArgument | None = None,
        root: PathArgument | None = None,
        follow_src: bool = False,
    ) -> None:
        if cwd is not None and root is not None:
            raise SyqInvocationError("cwd and root are mutually exclusive")
        self._source = _Source(
            _map_stream_cwd(None, None, root if root is not None else cwd, None),
            root is not None, follow_src,
        )

    @property
    def cwd(self) -> Path:
        """Absolute source-base spelling, without resolving symlinks or '..'."""
        return self._source.base

    @property
    def root(self) -> Path | None:
        """Source confinement root, or None for an unconfined mapping."""
        return self.cwd if self._source.confined else None

    @property
    def follow_src(self) -> bool:
        return self._source.follow_src


def _check_entry(entry: MappingEntry | None) -> MappingEntry | None:
    if entry is not None and not isinstance(entry, MappingEntry):
        if inspect.iscoroutine(entry):
            entry.close()
        raise SyqInvocationError("a mapping transform must return MappingEntry or None")
    return entry


@dataclass(frozen=True, slots=True)
class _TransformedEntries(Iterable[MappingEntry]):
    source: Iterable[MappingEntry]
    function: Callable[[MappingEntry], MappingEntry | None]

    def __iter__(self) -> Iterator[MappingEntry]:
        for entry in self.source:
            transformed = _check_entry(self.function(entry))
            if transformed is not None:
                yield transformed


@dataclass(frozen=True, slots=True)
class _AsyncTransformedEntries(AsyncIterable[MappingEntry]):
    source: AsyncIterable[MappingEntry]
    function: Callable[
        [MappingEntry], MappingEntry | None | Awaitable[MappingEntry | None]
    ]

    async def __aiter__(self) -> AsyncIterator[MappingEntry]:
        async for entry in self.source:
            transformed = self.function(entry)
            if inspect.isawaitable(transformed):
                transformed = await transformed
            transformed = _check_entry(transformed)
            if transformed is not None:
                yield transformed


class Mapping(_ContextMapping, Iterable[MappingEntry]):
    """Entries plus a local source base; transform returns another lazy mapping."""

    def __init__(
        self, entries: Iterable[MappingEntry], *,
        cwd: PathArgument | None = None,
        root: PathArgument | None = None,
        follow_src: bool = False,
    ) -> None:
        super().__init__(cwd=cwd, root=root, follow_src=follow_src)
        self._entries = entries

    def __iter__(self) -> Iterator[MappingEntry]:
        return iter(self._entries)

    def transform(self, function: Callable[[MappingEntry], MappingEntry | None]) -> Mapping:
        """Transform each entry; return None to omit it. Source context is kept."""
        return Mapping(
            _TransformedEntries(self, function),
            cwd=None if self.root is not None else self.cwd,
            root=self.root, follow_src=self.follow_src,
        )


class AsyncMapping(_ContextMapping, AsyncIterable[MappingEntry]):
    """Async entries plus a local source base; transforms may be awaitable."""

    def __init__(
        self, entries: AsyncIterable[MappingEntry], *,
        cwd: PathArgument | None = None,
        root: PathArgument | None = None,
        follow_src: bool = False,
    ) -> None:
        super().__init__(cwd=cwd, root=root, follow_src=follow_src)
        self._entries = entries

    def __aiter__(self) -> AsyncIterator[MappingEntry]:
        return aiter(self._entries)

    def transform(
        self, function: Callable[[MappingEntry], MappingEntry | None | Awaitable[MappingEntry | None]],
    ) -> AsyncMapping:
        """Transform in stream order, awaiting callbacks; None omits an entry."""
        return AsyncMapping(
            _AsyncTransformedEntries(self, function),
            cwd=None if self.root is not None else self.cwd,
            root=self.root, follow_src=self.follow_src,
        )


def _source_options(
    mapping: object, *, from_: str | None, cwd: PathArgument | None,
    root: PathArgument | None, follow_src: bool,
) -> tuple[PathArgument | None, PathArgument | None, bool]:
    if not isinstance(mapping, _ContextMapping):
        return cwd, root, follow_src
    if from_ is not None or cwd is not None or root is not None:
        raise SyqInvocationError("a context-carrying mapping cannot override from_, cwd, or root")
    return (
        None if mapping.root is not None else mapping.cwd,
        mapping.root,
        follow_src or mapping.follow_src,
    )
