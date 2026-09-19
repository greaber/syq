"""Pack and restore RSB-compatible archives through syq callbacks.

Import upload(), restore(), and publish_record() from this example. The caller
chooses an unused destination prefix and supplies the existing RSB record.
Archive bodies are streamed; the Parquet index is buffered in memory. This
example uses RSB's extraction policy and expects trusted dataset archives.
"""
from functools import partial
from io import BytesIO
from pathlib import Path
import os
import json
import tarfile

import polars as pl
import syq


def fail_scan(error):
    raise error


def write_archive(root, names, out):
    with tarfile.open(fileobj=out, mode="w|") as archive:
        for name in names:
            archive.add(root / name, arcname=name, recursive=False)


def write_empty_directories(names, out):
    with tarfile.open(fileobj=out, mode="w|") as archive:
        for name in names:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            archive.addfile(info)


def upload(client, source, prefix, *, to=None, shard_bytes=512 << 20):
    root = Path(source)
    rows, empty = [], []

    def entries():
        names, size, shard = [], 0, 0
        for directory, dirs, files in os.walk(root, onerror=fail_scan):
            links = [name for name in dirs if (Path(directory) / name).is_symlink()]
            dirs[:] = [name for name in dirs if name not in links]
            files += links
            if not dirs and not files:
                empty.append(Path(directory).relative_to(root).as_posix())
            for name in files:
                path = Path(directory) / name
                relative = path.relative_to(root).as_posix()
                length = path.stat().st_size if path.is_file() and not path.is_symlink() else 0
                rows.append(dict(shard_idx=shard, idx=len(rows), path=relative, size=length))
                names.append(relative)
                size += length
                if size >= shard_bytes or len(names) >= 10_000:
                    yield syq.MappingEntry(syq.StreamSource(partial(write_archive, root, tuple(names))),
                                           f"shard_{shard}.tar")
                    names, size, shard = [], 0, shard + 1
        if names:
            yield syq.MappingEntry(syq.StreamSource(partial(write_archive, root, tuple(names))),
                                   f"shard_{shard}.tar")
            shard += 1
        for name in empty:
            rows.append(dict(shard_idx=shard, idx=len(rows), path=name, size=0))
        yield syq.MappingEntry(syq.StreamSource(partial(write_empty_directories, tuple(empty))),
                               "empty_dirs.tar")

    client.cp(mapping=entries(), to=to, into=prefix, stream_concurrency=4)
    manifest = pl.DataFrame(rows, schema={"shard_idx": pl.Int64, "idx": pl.Int64,
                                         "path": pl.String, "size": pl.Int64})
    client.cp(mapping=[syq.MappingEntry(syq.StreamSource(manifest.write_parquet), "manifest.parquet")],
              to=to, into=prefix)
    # After success, the caller publishes PREFIX.rsb with the existing RSB fields
    # (sharded_by_rsb, original paths, pushes, stage='ap'). Do not claim rcheck ran.
    return manifest


def extract_archive(directory, inp):
    with tarfile.open(fileobj=inp, mode="r|") as archive:
        archive.extractall(directory, filter="tar")


def restore(client, prefix, destination, *, from_=None):
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    staging = destination.with_name(destination.name + ".unsharding")
    staging.mkdir()  # Refuses leftover staging from an earlier interrupted run.
    # Failure leaves only the separate staging tree for inspection or cleanup.
    with client.open_reader(f"{prefix}/manifest.parquet", from_=from_) as inp:
        manifest = pl.read_parquet(BytesIO(inp.read()))  # Only the index needs seeking.
    with client.open_reader(f"{prefix}/empty_dirs.tar", from_=from_) as inp:
        with tarfile.open(fileobj=inp, mode="r|") as archive:
            empty = list(archive)
            archive.extractall(staging, members=empty, filter="tar")
    # RSB assigns all empty-directory rows the next, unused numeric shard ID.
    data = manifest
    if empty and data.height:
        data = data.filter(pl.col("shard_idx") != data["shard_idx"].max())
    # Pre-create shared parents, avoiding concurrent tarfile mkdir races.
    for name in data["path"] if data.height else []:
        path = Path(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"invalid manifest path: {name}")
        (staging / path).parent.mkdir(parents=True, exist_ok=True)
    ids = sorted(data["shard_idx"].unique()) if data.height else []
    if ids:
        client.cp(mapping=(syq.MappingEntry(f"shard_{i}.tar",
                          syq.StreamDestination(partial(extract_archive, staging))) for i in ids),
                  from_=from_, cwd=prefix, stream_concurrency=4)
    staging.rename(destination)


def publish_record(client, prefix, record, remote_name, *, to=None):
    """Call after upload; preserve RSB's record fields and mark upload, not rcheck."""
    updated = dict(record, stage="ap", pushes=[*record["pushes"], remote_name])
    with client.open_writer(as_new=f"{prefix}.rsb", to=to) as out:
        out.write(json.dumps(updated).encode())
    return updated
