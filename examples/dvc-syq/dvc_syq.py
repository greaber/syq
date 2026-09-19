#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["syq>0.6.0", "pyyaml"]
# ///
"""Pull and push DVC-tracked data with syq.

    dvc_syq.py pull  TARGET...   # download missing objects, then write the workspace
    dvc_syq.py fetch TARGET...   # download into DVC's cache only
    dvc_syq.py push  TARGET...   # upload objects the remote lacks

A target is a `.dvc` file, a tracked path, or with -R a directory to search.

How DVC stores data, which is all this script relies on:

* A `.dvc` file (or `dvc.lock`) lists tracked outputs: a path and an MD5.
* DVC's cache holds one object per file, at a path made from its MD5. A DVC
  remote uses exactly the same layout, so an object has the same relative
  path in both places.
* A tracked directory's MD5 ends in `.dir`. That object is a JSON list of the
  files inside: `[{"md5": ..., "relpath": ...}, ...]`.

So every copy is known before it starts. Each step below builds a list of
(source, destination) pairs and gives the whole list to syq in one call.
"""

from __future__ import annotations

import argparse
import configparser
import filecmp
import hashlib
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

import syq

try:
    from syq import Hash, MappingEntry
except ImportError:
    sys.exit("error: this script needs a syq package newer than 0.6.0")


# --- DVC's data model -------------------------------------------------------


@dataclass(frozen=True)
class CacheObject:
    """One object in the cache or a remote, named by its MD5."""

    md5: str  # ends with ".dir" when the object is a directory listing
    legacy: bool  # written by DVC 2

    @property
    def is_listing(self) -> bool:
        return self.md5.endswith(".dir")

    @property
    def path(self) -> str:
        """Relative path, identical in the cache and in every remote."""
        tail = f"{self.md5[:2]}/{self.md5[2:]}"
        return tail if self.legacy else f"files/md5/{tail}"

    @property
    def named_after_its_bytes(self) -> bool:
        """Whether the name is the plain MD5 of the contents, which syq can check.

        DVC 2 hashed text files after turning CRLF line endings into LF, so a
        DVC 2 file needs the more forgiving check in `matches_dvc2_md5`.
        """
        return self.is_listing or not self.legacy

    @property
    def digest(self) -> Hash:
        return Hash("md5", self.md5.removesuffix(".dir"))


@dataclass(frozen=True)
class Output:
    """One tracked path in the workspace and the object holding its contents."""

    path: str  # relative to the repository root
    object: CacheObject


def read_outputs(root: Path, dvc_file: Path) -> list[Output]:
    """Tracked outputs listed in one `.dvc` file or `dvc.lock`."""
    try:
        # BaseLoader keeps every value as text; an all-digit MD5 must not become a number.
        data = yaml.load(dvc_file.read_text(), Loader=yaml.BaseLoader) or {}
    except (OSError, yaml.YAMLError) as error:
        sys.exit(f"error: cannot read {dvc_file}: {error}")
    stages = data.get("stages", {}).values() if dvc_file.name == "dvc.lock" else [data]
    outputs = []
    for stage in stages:
        if any("repo" in dependency for dependency in stage.get("deps") or []):
            # `dvc import` data lives in the source repository's remote, not this one.
            print(f"skipping {dvc_file.relative_to(root)}: imported from another repository; use dvc pull")
            continue
        directory = dvc_file.parent / stage.get("wdir", ".")
        for out in stage.get("outs") or []:
            if "md5" not in out:
                continue  # not cached, for example `cache: false`
            path = (directory / out["path"]).resolve().relative_to(root.resolve())
            # DVC 3 marks its objects with `hash: md5`; DVC 2 wrote no such field.
            outputs.append(Output(path.as_posix(), CacheObject(out["md5"], legacy=out.get("hash") != "md5")))
    return outputs


def find_outputs(root: Path, targets: list[str], recursive: bool) -> list[Output]:
    """Outputs of the named targets."""
    dvc_files = []
    for target in targets:
        for candidate in (Path(target), Path(f"{target}.dvc")):
            if candidate.is_file() and (candidate.suffix == ".dvc" or candidate.name == "dvc.lock"):
                dvc_files.append(candidate.resolve())
                break
        else:
            if not Path(target).is_dir():
                sys.exit(f"error: {target} is not a .dvc file, dvc.lock, or tracked path")
            if not recursive:
                sys.exit(f"error: {target} is a directory; use -R to include every .dvc file under it")
            for directory, subdirectories, names in os.walk(Path(target).resolve()):
                subdirectories[:] = [d for d in subdirectories if d not in (".git", ".dvc")]
                dvc_files += [Path(directory) / n for n in names if n.endswith(".dvc") or n == "dvc.lock"]
    outputs = [output for dvc_file in sorted(set(dvc_files)) for output in read_outputs(root, dvc_file)]
    if not outputs:
        sys.exit("error: no tracked outputs found")
    return outputs


def read_listing(cache: Path, listing: CacheObject) -> list[tuple[str, CacheObject]]:
    """(relative path, object) for each file in a tracked directory."""
    try:
        entries = json.loads((cache / listing.path).read_bytes())
    except (OSError, ValueError) as error:
        sys.exit(f"error: cannot read directory listing {listing.path}: {error}")
    return [(entry["relpath"], CacheObject(entry["md5"], listing.legacy)) for entry in entries]


def files_of(cache: Path, outputs: list[Output]) -> list[tuple[str, CacheObject]]:
    """(workspace path, object) for every tracked file, expanding directories."""
    files = []
    for output in outputs:
        if output.object.is_listing:
            files += [(f"{output.path}/{relpath}", obj) for relpath, obj in read_listing(cache, output.object)]
        else:
            files.append((output.path, output.object))
    return files


# --- The DVC remote ---------------------------------------------------------


@dataclass(frozen=True)
class Remote:
    endpoint: str | None  # what syq's --from/--to take: a host, "s3://bucket", or None for local
    base: str  # directory or key prefix holding the objects; "" for a bucket's root
    s3_options: dict[str, str]

    @property
    def is_s3(self) -> bool:
        return self.endpoint is not None and self.endpoint.startswith("s3://")


def read_remote(root: Path, config: configparser.ConfigParser, name: str | None) -> Remote:
    name = name or config.get("core", "remote", fallback=None)
    if name is None:
        sys.exit("error: no default remote; pass --remote NAME")
    # DVC writes the section header as ['remote "name"'], quotes included.
    section = next((s for s in config.sections() if s.strip("'") == f'remote "{name}"'), None)
    if section is None:
        sys.exit(f"error: remote {name!r} is not configured")
    settings = config[section]
    if settings.get("version_aware") or settings.get("worktree"):
        sys.exit(f"error: remote {name!r} uses DVC cloud versioning, which stores files differently; use dvc")

    url = urlparse(settings["url"])
    if url.scheme == "s3":
        options = {}
        if settings.get("profile"):
            options["s3_profile"] = settings["profile"]
        if settings.get("endpointurl"):
            options["s3_endpoint"] = settings["endpointurl"]
        other_provider = "s3_endpoint" in options or any(
            os.environ.get(variable) for variable in ("AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL")
        )
        if other_provider and settings.get("region"):
            options["s3_region"] = settings["region"]  # used as configured
        # On AWS no region is passed: syq asks S3 where the bucket is, which works
        # even when the configured region is wrong, as it does under DVC.
        return Remote(f"s3://{url.netloc}", url.path.strip("/"), options)
    if url.scheme == "ssh":
        if url.port is not None:
            sys.exit("error: ssh remotes with an explicit port are not supported")
        host = f"{url.username}@{url.hostname}" if url.username else url.hostname
        return Remote(host, url.path or ".", {})
    if url.scheme in ("", "file"):
        path = Path(url.path)
        if not path.is_absolute():
            path = root / ".dvc" / path  # DVC resolves relative remotes from its config file
        return Remote(None, str(path.resolve()), {})
    sys.exit(f"error: remote {name!r} uses {url.scheme}://, which this script does not support")


# --- Copying ----------------------------------------------------------------


class ProgressLine:
    """One updating status line on a terminal, fed by syq's progress events."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.enabled = sys.stderr.isatty()
        self.started = time.monotonic()
        self.updated = 0.0

    def __call__(self, event: object) -> None:
        now = time.monotonic()
        if not self.enabled or not isinstance(event, syq.ProgressEvent) or now - self.updated < 0.1:
            return
        self.updated = now
        rate = event.bytes_done / max(now - self.started, 1e-9) / 1e6
        sys.stderr.write(
            f"\r{self.label}: {event.files_done}/{event.files_total} files, "
            f"{event.bytes_done / 1e6:.0f}/{event.bytes_total / 1e6:.0f} MB, {rate:.1f} MB/s\x1b[K"
        )
        sys.stderr.flush()

    def clear(self) -> None:
        if self.enabled:
            sys.stderr.write("\r\x1b[K")
            sys.stderr.flush()


def copy(client: syq.Client, label: str, entries: list[MappingEntry], **options: object) -> None:
    """Give syq one list of copies, show progress, and report the outcome."""
    if not entries:
        return
    progress = ProgressLine(label)
    started = time.monotonic()
    try:
        result = client.cp(mapping=entries, on_event=progress, **options)
    except syq.SyqOperationError as error:
        progress.clear()
        print(f"{label}: {error.result.errors} of {len(entries)} failed", file=sys.stderr)
        print(error.stderr.decode(errors="replace"), file=sys.stderr)
        sys.exit(23)
    progress.clear()
    seconds = time.monotonic() - started
    print(
        f"{label}: {result.files_transferred} copied, {result.files_unchanged} already in place, "
        f"{result.bytes_transferred / 1e6:.1f} MB in {seconds:.1f}s"
    )


def download(
    client: syq.Client, remote: Remote, cache: Path, label: str, objects: list[CacheObject],
    *, verify: bool, dry_run: bool,
) -> None:
    """Remote to cache. The path is the same on both sides; S3 keys also carry the prefix."""
    prefix = f"{remote.base}/" if remote.is_s3 and remote.base else ""
    entries = [
        MappingEntry(
            src=prefix + obj.path, dst=obj.path, kind="file",
            # syq checks the digest as the bytes arrive and keeps a mismatched file out of the cache.
            expected_hash=obj.digest if verify and obj.named_after_its_bytes else None,
        )
        for obj in objects
    ]
    source = {"from_": remote.endpoint} if remote.endpoint else {}
    if not remote.is_s3:
        source["cwd"] = remote.base
    copy(client, label, entries, into=cache, only_new=True, dry_run=dry_run, **source, **remote.s3_options)

    if verify and not dry_run:
        dvc2_files = [obj for obj in objects if not obj.named_after_its_bytes]
        with ThreadPoolExecutor() as pool:
            results = pool.map(lambda obj: matches_dvc2_md5(cache / obj.path, obj.md5), dvc2_files)
        corrupt = [obj for obj, matches in zip(dvc2_files, results) if not matches]
        for obj in corrupt:
            (cache / obj.path).unlink()
        if corrupt:
            sys.exit(f"error: {len(corrupt)} downloads did not match their MD5, for example {corrupt[0].path}")


def matches_dvc2_md5(path: Path, md5: str) -> bool:
    """Whether a file's MD5 is `md5`, either as it is or with CRLF turned into LF as DVC 2 did for text."""
    plain, normalized, held_back = hashlib.md5(), hashlib.md5(), b""
    with open(path, "rb") as file:
        while chunk := file.read(1 << 20):
            plain.update(chunk)
            chunk = held_back + chunk
            # A CR ending this chunk may be half of a CRLF; decide when the next chunk arrives.
            held_back = b"\r" if chunk.endswith(b"\r") else b""
            normalized.update(chunk[: len(chunk) - len(held_back)].replace(b"\r\n", b"\n"))
    normalized.update(held_back)
    return md5 in (plain.hexdigest(), normalized.hexdigest())


def upload(client: syq.Client, remote: Remote, cache: Path, label: str, objects: list[CacheObject], dry_run: bool) -> None:
    """Cache to remote. `only_new` skips every object the remote already has."""
    entries = [MappingEntry(src=obj.path, dst=obj.path, kind="file") for obj in objects]
    destination = {"to": remote.endpoint} if remote.endpoint else {}
    copy(
        client, label, entries, cwd=cache, into=remote.base or ".", only_new=True, dry_run=dry_run,
        **destination, **remote.s3_options,
    )


def checkout(client: syq.Client, root: Path, cache: Path, outputs: list[Output], dry_run: bool, force: bool) -> None:
    """Cache to workspace. This is where objects get their real names."""
    entries = [MappingEntry(src=obj.path, dst=path, kind="file") for path, obj in files_of(cache, outputs)]
    tracked = {str(entry.dst) for entry in entries}
    untracked = [
        file
        for output in outputs if output.object.is_listing
        for file in (root / output.path).rglob("*")
        if not file.is_dir() and file.relative_to(root).as_posix() not in tracked
    ]
    if not force and not dry_run:
        # Like DVC, refuse to replace a file whose contents differ from the tracked version.
        # Matching size and modification time settle most files without reading them.
        modified = [
            str(entry.dst)
            for entry in entries
            if (root / str(entry.dst)).is_file()
            and not filecmp.cmp(root / str(entry.dst), cache / str(entry.src), shallow=True)
            and not filecmp.cmp(root / str(entry.dst), cache / str(entry.src), shallow=False)
        ]
        unsaved = modified + [file.relative_to(root).as_posix() for file in untracked]
        if unsaved:
            shown = "\n  ".join(unsaved[:10])
            sys.exit(
                f"error: {len(unsaved)} files are changed or not tracked; "
                f"use --force to replace and remove them\n  {shown}"
            )
    if force and not dry_run:
        for file in untracked:  # as `dvc pull --force` does, make tracked directories match exactly
            file.unlink()
    copy(client, "checkout", entries, cwd=cache, into=root, dry_run=dry_run)


# --- Commands ---------------------------------------------------------------


def pull(client: syq.Client, root: Path, cache: Path, remote: Remote, outputs: list[Output], args: argparse.Namespace) -> None:
    # Directory listings first: the files inside a directory are unknown until its listing is here.
    listings = {o.object for o in outputs if o.object.is_listing and not (cache / o.object.path).exists()}
    listings = sorted(listings, key=lambda o: o.md5)
    download(client, remote, cache, "directory listings", listings, verify=args.verify, dry_run=args.dry_run)
    if listings and args.dry_run:
        print("dry run: the files inside those directories are unknown until their listings are downloaded")
        return

    wanted = {obj for _, obj in files_of(cache, outputs)}
    missing = sorted((obj for obj in wanted if not (cache / obj.path).exists()), key=lambda o: o.md5)
    print(f"{len(wanted)} tracked files, {len(missing)} not in the cache")
    download(client, remote, cache, "files", missing, verify=args.verify, dry_run=args.dry_run)

    if args.command == "pull":
        checkout(client, root, cache, outputs, args.dry_run, args.force)


def push(client: syq.Client, cache: Path, remote: Remote, outputs: list[Output], args: argparse.Namespace) -> None:
    files = {obj for _, obj in files_of(cache, outputs)}
    listings = {o.object for o in outputs if o.object.is_listing}
    absent = sorted(obj.path for obj in files | listings if not (cache / obj.path).exists())
    if absent:
        sys.exit(f"error: {len(absent)} tracked objects are not in the local cache, for example {absent[0]}")
    # Listings go last, so a directory never appears in the remote before its files.
    upload(client, remote, cache, "files", sorted(files, key=lambda o: o.md5), args.dry_run)
    upload(client, remote, cache, "directory listings", sorted(listings, key=lambda o: o.md5), args.dry_run)


def main() -> None:
    parser = argparse.ArgumentParser(description="Pull and push DVC data with syq.")
    parser.add_argument("command", choices=["pull", "fetch", "push"])
    parser.add_argument("targets", nargs="+", metavar="TARGET", help=".dvc file, dvc.lock, or tracked path")
    parser.add_argument("-R", "--recursive", action="store_true", help="include every .dvc file under a directory target")
    parser.add_argument("-r", "--remote", help="DVC remote name (default: the repository's default remote)")
    parser.add_argument("--verify", action="store_true", help="check each download against its MD5")
    parser.add_argument("-f", "--force", action="store_true", help="let pull replace changed files and remove untracked ones")
    parser.add_argument("--dry-run", action="store_true", help="show what would be copied")
    parser.add_argument("--syq", help="syq executable (default: the one installed with the syq package)")
    args = parser.parse_args()

    root = next((d for d in [Path.cwd(), *Path.cwd().parents] if (d / ".dvc").is_dir()), None)
    if root is None:
        sys.exit("error: not inside a DVC repository")
    config = configparser.ConfigParser()
    config.read([root / ".dvc" / "config", root / ".dvc" / "config.local"])
    cache = (root / ".dvc" / config.get("cache", "dir", fallback="cache")).resolve()
    remote = read_remote(root, config, args.remote)
    outputs = find_outputs(root, args.targets, args.recursive)
    client = syq.Client(executable=args.syq or os.environ.get("SYQ_EXECUTABLE"))

    if args.command == "push":
        push(client, cache, remote, outputs, args)
    else:
        pull(client, root, cache, remote, outputs, args)


if __name__ == "__main__":
    main()
