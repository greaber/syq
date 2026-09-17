#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["syq", "pyyaml"]
# ///
"""Push and pull DVC-tracked data with syq.

DVC stores each tracked file in its remote under a path derived from the
file's MD5, and describes a tracked directory with a small `.dir` object
listing the files inside it. This script reads the `.dvc` files and
`dvc.lock` in a repository, works out which objects each command needs, and
hands syq one mapping per copy instead of moving objects one at a time.

    dvc_syq.py pull            # fetch missing objects, then check out the workspace
    dvc_syq.py fetch           # fetch into the cache only
    dvc_syq.py push            # upload objects the remote lacks

Supported remotes: local directories, `ssh://host/path`, and
`s3://bucket/prefix`. Objects written by DVC 3 are verified against their MD5
as they arrive. Objects tracked by DVC 2 use a different cache layout and, for
text files, a different MD5; they are copied without a digest check.
"""

from __future__ import annotations

import argparse
import configparser
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

import yaml

import syq

try:
    from syq import Digest, MappingEntry
except ImportError:
    sys.exit("error: this script needs a syq package newer than 0.6.0 (per-file expected digests)")


@dataclass(frozen=True)
class Out:
    """One tracked output: a file or a directory."""

    path: PurePosixPath  # relative to the repository root
    md5: str  # ends with ".dir" for a directory
    legacy: bool  # DVC 2 object: top-level cache layout, no digest check

    @property
    def is_dir(self) -> bool:
        return self.md5.endswith(".dir")


@dataclass(frozen=True)
class Remote:
    kind: str  # "local", "ssh", or "s3"
    endpoint: str | None  # syq --from/--to value, None for local
    base: str  # directory or key prefix holding the objects ("" for none)
    options: dict[str, str]


def object_path(md5: str, legacy: bool) -> str:
    """Relative path of an object in the cache and in every DVC remote."""
    tail = f"{md5[:2]}/{md5[2:]}"
    return tail if legacy else f"files/md5/{tail}"


def find_repo_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / ".dvc").is_dir():
            return candidate
    sys.exit(f"error: no .dvc directory above {start}")


def read_config(root: Path) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.read([root / ".dvc" / "config", root / ".dvc" / "config.local"])
    return config


def cache_dir(root: Path, config: configparser.ConfigParser) -> Path:
    configured = config.get("cache", "dir", fallback=None)
    if configured is None:
        return root / ".dvc" / "cache"
    return (root / ".dvc" / configured).resolve()


def parse_remote(root: Path, config: configparser.ConfigParser, name: str | None) -> Remote:
    name = name or config.get("core", "remote", fallback=None)
    if name is None:
        sys.exit("error: no default remote; pass --remote NAME")
    # DVC writes remote sections as ['remote "name"'], quotes included.
    section = next(
        (s for s in config.sections() if s.strip("'") == f'remote "{name}"'), None
    )
    if section is None:
        sys.exit(f"error: remote {name!r} is not configured")
    url = config.get(section, "url")
    parsed = urlparse(url)
    options: dict[str, str] = {}
    if parsed.scheme == "s3":
        for key, option in (("endpointurl", "s3_endpoint"), ("profile", "s3_profile"), ("region", "s3_region")):
            value = config.get(section, key, fallback=None)
            if value:
                options[option] = value
        return Remote("s3", f"s3://{parsed.netloc}", parsed.path.strip("/"), options)
    if parsed.scheme == "ssh":
        if parsed.port is not None:
            sys.exit("error: ssh remotes with an explicit port are not supported by this script")
        host = parsed.hostname or ""
        if parsed.username:
            host = f"{parsed.username}@{host}"
        return Remote("ssh", host, parsed.path or ".", options)
    if parsed.scheme in ("", "file"):
        path = Path(parsed.path if parsed.scheme else url)
        if not path.is_absolute():
            path = root / ".dvc" / path
        return Remote("local", None, str(path.resolve()), options)
    sys.exit(f"error: remote {name!r} uses {parsed.scheme}://, which this script does not support")


def parse_outs(root: Path, file: Path) -> list[Out]:
    """Tracked outputs of one `.dvc` file or `dvc.lock`."""
    try:
        data = yaml.safe_load(file.read_text()) or {}
    except (OSError, yaml.YAMLError) as error:
        sys.exit(f"error: cannot read {file}: {error}")
    stages = data.get("stages", {}).values() if file.name == "dvc.lock" else [data]
    outs: list[Out] = []
    for stage in stages:
        base = file.parent / stage.get("wdir", ".")
        for out in stage.get("outs", []) or []:
            md5 = out.get("md5")
            if md5 is None:
                continue  # an output without a hash is not in the cache
            relative = (base / out["path"]).resolve().relative_to(root.resolve())
            outs.append(Out(PurePosixPath(relative.as_posix()), md5, out.get("hash") != "md5"))
    return outs


def collect_outs(root: Path, targets: list[str]) -> list[Out]:
    files: list[Path] = []
    if targets:
        for target in targets:
            path = Path(target)
            if path.is_file() and (path.suffix == ".dvc" or path.name == "dvc.lock"):
                files.append(path)
            elif (Path(f"{target}.dvc")).is_file():
                files.append(Path(f"{target}.dvc"))
            else:
                sys.exit(f"error: {target} is not a .dvc file, dvc.lock, or tracked path")
    else:
        for directory, names, filenames in os.walk(root):
            names[:] = [n for n in names if n not in (".git", ".dvc")]
            files.extend(Path(directory) / f for f in filenames if f.endswith(".dvc") or f == "dvc.lock")
    outs = [out for file in sorted(files) for out in parse_outs(root, file)]
    if not outs:
        sys.exit("error: no tracked outputs found")
    return outs


def read_dir_object(cache: Path, out: Out) -> list[tuple[str, str]]:
    """(relpath, md5) pairs listed by a directory's `.dir` object."""
    try:
        entries = json.loads((cache / object_path(out.md5, out.legacy)).read_bytes())
    except (OSError, ValueError) as error:
        sys.exit(f"error: cannot read directory listing for {out.path}: {error}")
    return [(entry["relpath"], entry["md5"]) for entry in entries]


class Transfer:
    """Runs one mapping copy in each direction between the cache and the remote."""

    def __init__(self, client: syq.Client, remote: Remote, cache: Path, dry_run: bool) -> None:
        self.client = client
        self.remote = remote
        self.cache = cache
        self.dry_run = dry_run

    def remote_source(self, relative: str) -> str:
        """Object path as a mapping source when copying from the remote."""
        if self.remote.kind == "s3" and self.remote.base:
            return f"{self.remote.base}/{relative}"
        return relative

    def download(self, objects: list[tuple[str, bool, str | None]], label: str) -> None:
        """objects: (relative object path, legacy, md5 or None) tuples."""
        if not objects:
            print(f"{label}: nothing to fetch")
            return
        entries = [
            MappingEntry(
                src=self.remote_source(relative), dst=relative, kind="file",
                expected_digest=None if legacy or md5 is None else Digest("md5", md5),
            )
            for relative, legacy, md5 in objects
        ]
        print(f"{label}: fetching {len(entries)} objects")
        options: dict[str, object] = {}
        if self.remote.kind == "s3":
            options["from_"] = self.remote.endpoint
        elif self.remote.kind == "ssh":
            options["from_"] = self.remote.endpoint
            options["cwd"] = self.remote.base
        else:
            options["cwd"] = self.remote.base
        self.run(entries, into=self.cache, label=label, **options)

    def upload(self, objects: list[str], label: str) -> None:
        entries = [MappingEntry(src=relative, dst=relative, kind="file") for relative in objects]
        print(f"{label}: offering {len(entries)} objects")
        options: dict[str, object] = {"cwd": self.cache}
        if self.remote.kind == "local":
            into: str = self.remote.base
        else:
            options["to"] = self.remote.endpoint
            into = self.remote.base or "."
        self.run(entries, into=into, label=label, **options)

    def run(self, entries: list[MappingEntry], *, label: str, **options: object) -> None:
        started = time.monotonic()
        try:
            result = self.client.cp(
                mapping=entries, only_new=True, dry_run=self.dry_run,
                **self.remote.options, **options,
            )
        except syq.SyqOperationError as error:
            print(f"{label}: {error.result.errors} objects failed", file=sys.stderr)
            print(error.stderr.decode(errors="replace"), file=sys.stderr)
            sys.exit(23)
        seconds = time.monotonic() - started
        rate = result.bytes_transferred / seconds / 1e6 if seconds else 0.0
        print(
            f"{label}: {result.files_transferred} copied, {result.files_unchanged} already present, "
            f"{result.bytes_transferred / 1e6:.1f} MB in {seconds:.1f}s ({rate:.1f} MB/s)"
        )


def checkout(client: syq.Client, root: Path, cache: Path, outs: list[Out], dry_run: bool) -> None:
    entries: list[MappingEntry] = []
    for out in outs:
        if out.is_dir:
            for relpath, md5 in read_dir_object(cache, out):
                entries.append(MappingEntry(src=object_path(md5, out.legacy), dst=str(out.path / relpath), kind="file"))
        else:
            entries.append(MappingEntry(src=object_path(out.md5, out.legacy), dst=str(out.path), kind="file"))
    print(f"checkout: {len(entries)} files")
    try:
        result = client.cp(mapping=entries, cwd=cache, into=root, dry_run=dry_run)
    except syq.SyqOperationError as error:
        print(f"checkout: {error.result.errors} files failed", file=sys.stderr)
        print(error.stderr.decode(errors="replace"), file=sys.stderr)
        sys.exit(23)
    print(f"checkout: {result.files_transferred} written, {result.files_unchanged} unchanged")


def pull(args: argparse.Namespace, *, checkout_after: bool) -> None:
    root, cache, outs, transfer = setup(args)
    dirs = [out for out in outs if out.is_dir]
    missing = [
        (object_path(out.md5, out.legacy), out.legacy, None)
        for out in dirs
        if not (cache / object_path(out.md5, out.legacy)).exists()
    ]
    transfer.download(sorted(set(missing)), "directory listings")
    if args.dry_run and missing:
        print("dry run: directory contents are unknown until their listings are fetched")
        return
    wanted: dict[str, tuple[bool, str]] = {}
    for out in outs:
        if out.is_dir:
            for _, md5 in read_dir_object(cache, out):
                wanted[object_path(md5, out.legacy)] = (out.legacy, md5)
        else:
            wanted[object_path(out.md5, out.legacy)] = (out.legacy, out.md5)
    files = [
        (relative, legacy, md5)
        for relative, (legacy, md5) in sorted(wanted.items())
        if not (cache / relative).exists()
    ]
    print(f"{len(wanted)} tracked files, {len(files)} not in the cache")
    transfer.download(files, "files")
    if checkout_after:
        checkout(transfer.client, root, cache, outs, args.dry_run)


def push(args: argparse.Namespace) -> None:
    _, cache, outs, transfer = setup(args)
    objects: set[str] = set()
    listings: set[str] = set()
    for out in outs:
        if out.is_dir:
            listings.add(object_path(out.md5, out.legacy))
            for _, md5 in read_dir_object(cache, out):
                objects.add(object_path(md5, out.legacy))
        else:
            objects.add(object_path(out.md5, out.legacy))
    absent = sorted(o for o in objects if not (cache / o).exists())
    if absent:
        sys.exit(f"error: {len(absent)} tracked objects are not in the local cache, for example {absent[0]}")
    transfer.upload(sorted(objects), "files")
    if listings:
        transfer.upload(sorted(listings), "directory listings")


def setup(args: argparse.Namespace) -> tuple[Path, Path, list[Out], Transfer]:
    root = find_repo_root(Path.cwd())
    config = read_config(root)
    cache = cache_dir(root, config)
    remote = parse_remote(root, config, args.remote)
    outs = collect_outs(root, args.targets)
    # Default to the executable bundled with the syq package, not one on PATH.
    client = syq.Client(executable=args.syq or os.environ.get("SYQ_EXECUTABLE"))
    print(f"remote {remote.kind}: {remote.endpoint or ''}{'/' if remote.endpoint else ''}{remote.base}")
    return root, cache, outs, Transfer(client, remote, cache, args.dry_run)


def main() -> None:
    parser = argparse.ArgumentParser(description="Push and pull DVC data with syq.")
    parser.add_argument("command", choices=["pull", "fetch", "push"])
    parser.add_argument("targets", nargs="*", help=".dvc files, dvc.lock, or tracked paths (default: all)")
    parser.add_argument("--remote", help="DVC remote name (default: core.remote)")
    parser.add_argument("--dry-run", action="store_true", help="plan without copying")
    parser.add_argument("--syq", help="syq executable (default: $SYQ_EXECUTABLE, then the syq package's own)")
    args = parser.parse_args()
    if args.command == "push":
        push(args)
    else:
        pull(args, checkout_after=args.command == "pull")


if __name__ == "__main__":
    main()
