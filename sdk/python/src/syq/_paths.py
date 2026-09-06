"""Source-base spelling shared by mapping creation and map subprocesses."""

import os
from collections.abc import Mapping
from pathlib import Path

PathArgument = str | bytes | os.PathLike[str] | os.PathLike[bytes]


def _native_path_spelling(
    value: PathArgument, env: Mapping[str, str] | None
) -> str:
    """Apply native ``~`` expansion without normalizing path components."""

    spelling = os.fsdecode(os.fspath(value))
    if spelling == "~" or spelling.startswith("~/"):
        home = (os.environ if env is None else env).get("HOME")
        if home is not None:
            suffix = spelling[2:] if len(spelling) > 2 else ""
            return os.path.join(home, suffix) if suffix else home
    return spelling


def _join_path_spelling(base: str, path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(base, path)


def _map_stream_cwd(
    process_cwd: PathArgument | None,
    env: Mapping[str, str] | None,
    selected_base: PathArgument | None,
    contents_selector: PathArgument | None,
) -> Path:
    """Derive the consumer base using the native component spelling."""

    if process_cwd is None:
        process_base = os.getcwd()
    else:
        process_spelling = os.fsdecode(os.fspath(process_cwd))
        process_base = _join_path_spelling(os.getcwd(), process_spelling)
    base_spelling = _native_path_spelling(
        "." if selected_base is None else selected_base, env
    )
    effective = _join_path_spelling(process_base, base_spelling)
    if contents_selector is not None:
        effective = _join_path_spelling(
            effective, _native_path_spelling(contents_selector, env)
        )
    # Path preserves `..` components. In particular, do not use abspath or
    # resolve here: the native walker must encounter symlinks before `..`.
    return Path(effective)

