#!/usr/bin/env python3
"""Rewrite Python source distributions with deterministic archive metadata."""

from __future__ import annotations

import argparse
import copy
import gzip
import os
from pathlib import Path
import tarfile
import tempfile
from typing import BinaryIO


def normalized_mode(member: tarfile.TarInfo) -> int:
    if member.isdir():
        return 0o755
    if member.isfile():
        return 0o755 if member.mode & 0o111 else 0o644
    return member.mode


def add_member(
    source: tarfile.TarFile,
    destination: tarfile.TarFile,
    member: tarfile.TarInfo,
    epoch: int,
) -> None:
    normalized = copy.copy(member)
    normalized.uid = 0
    normalized.gid = 0
    normalized.uname = ""
    normalized.gname = ""
    normalized.mtime = epoch
    normalized.mode = normalized_mode(member)
    normalized.pax_headers = {}

    contents: BinaryIO | None = None
    if member.isfile():
        contents = source.extractfile(member)
        if contents is None:
            raise ValueError(f"could not read {member.name!r} from source distribution")
    try:
        destination.addfile(normalized, contents)
    finally:
        if contents is not None:
            contents.close()


def normalize(archive: Path, epoch: int) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b",
            prefix=f".{archive.name}.",
            suffix=".tmp",
            dir=archive.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            with tarfile.open(archive, mode="r:gz") as source:
                with gzip.GzipFile(
                    filename="",
                    mode="wb",
                    compresslevel=9,
                    mtime=epoch,
                    fileobj=temporary,
                ) as compressed:
                    with tarfile.open(
                        fileobj=compressed,
                        mode="w",
                        format=tarfile.PAX_FORMAT,
                    ) as destination:
                        for member in sorted(source.getmembers(), key=lambda item: item.name):
                            add_member(source, destination, member, epoch)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, archive)
    except BaseException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--epoch", type=int, required=True)
    parser.add_argument("archives", nargs="+", type=Path)
    args = parser.parse_args()
    if not 0 <= args.epoch <= 0xFFFFFFFF:
        parser.error("--epoch must fit in a gzip timestamp")
    for archive in args.archives:
        normalize(archive, args.epoch)


if __name__ == "__main__":
    main()
