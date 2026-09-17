#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["syq", "pyyaml"]
# ///
"""Pull and push DVC-tracked data with syq.

    dvc_syq.py pull  [targets]   # download missing objects, then write the workspace
    dvc_syq.py fetch [targets]   # download into DVC's cache only
    dvc_syq.py push  [targets]   # upload objects the remote lacks

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
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

import syq

try:
    from syq import Digest, MappingEntry
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
    def expected_digest(self) -> Digest | None:
        """The MD5 the object's bytes must have, when that is knowable.

        DVC 2 hashed text files after normalizing their line endings, so the
        name of a DVC 2 file object is not reliably the MD5 of its bytes.
        """
        if self.legacy and not self.is_listing:
            return None
        return Digest("md5", self.md5.removesuffix(".dir"))


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


def find_outputs(root: Path, targets: list[str]) -> list[Output]:
    """Outputs of the named targets, or of every DVC file in the repository."""
    dvc_files = []
    for target in targets:
        for candidate in (Path(target), Path(f"{target}.dvc")):
            if candidate.is_file() and (candidate.suffix == ".dvc" or candidate.name == "dvc.lock"):
                dvc_files.append(candidate.resolve())
                break
        else:
            sys.exit(f"error: {target} is not a .dvc file, dvc.lock, or tracked path")
    if not targets:
        for directory, subdirectories, names in os.walk(root):
            subdirectories[:] = [d for d in subdirectories if d not in (".git", ".dvc")]
            dvc_files += [Path(directory) / n for n in names if n.endswith(".dvc") or n == "dvc.lock"]
    outputs = [output for dvc_file in sorted(dvc_files) for output in read_outputs(root, dvc_file)]
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
        names = {"endpointurl": "s3_endpoint", "profile": "s3_profile", "region": "s3_region"}
        options = {names[key]: settings[key] for key in names if settings.get(key)}
        custom_endpoint = "s3_endpoint" in options or any(
            os.environ.get(variable) for variable in ("AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL")
        )
        if "s3_region" not in options and not custom_endpoint:
            region = aws_bucket_region(url.netloc)
            if region:
                options["s3_region"] = region
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


def aws_bucket_region(bucket: str) -> str | None:
    """Region of an AWS bucket, which S3 names in a header on every response.

    DVC users rarely configure a region because DVC's S3 library follows
    S3's cross-region redirects by itself.
    """
    request = urllib.request.Request(f"https://s3.amazonaws.com/{bucket}", method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            headers = response.headers
    except urllib.error.HTTPError as error:
        headers = error.headers  # redirects and denials carry the header too
    except OSError:
        return None
    return headers.get("x-amz-bucket-region")


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
        print(f"{label}: nothing to do")
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


def download(client: syq.Client, remote: Remote, cache: Path, label: str, objects: list[CacheObject], dry_run: bool) -> None:
    """Remote to cache. The path is the same on both sides; S3 keys also carry the prefix."""
    prefix = f"{remote.base}/" if remote.is_s3 and remote.base else ""
    entries = [
        MappingEntry(src=prefix + obj.path, dst=obj.path, kind="file", expected_digest=obj.expected_digest)
        for obj in objects
    ]
    source = {"from_": remote.endpoint} if remote.endpoint else {}
    if not remote.is_s3:
        source["cwd"] = remote.base
    copy(client, label, entries, into=cache, only_new=True, dry_run=dry_run, **source, **remote.s3_options)


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
        if modified:
            shown = "\n  ".join(modified[:10])
            sys.exit(f"error: {len(modified)} files have local changes; use --force to replace them\n  {shown}")
    copy(client, "checkout", entries, cwd=cache, into=root, dry_run=dry_run)


# --- Commands ---------------------------------------------------------------


def pull(client: syq.Client, root: Path, cache: Path, remote: Remote, outputs: list[Output], args: argparse.Namespace) -> None:
    # Directory listings first: the files inside a directory are unknown until its listing is here.
    listings = {o.object for o in outputs if o.object.is_listing and not (cache / o.object.path).exists()}
    download(client, remote, cache, "directory listings", sorted(listings, key=lambda o: o.md5), args.dry_run)
    if listings and args.dry_run:
        print("dry run: the files inside those directories are unknown until their listings are downloaded")
        return

    wanted = {obj for _, obj in files_of(cache, outputs)}
    missing = sorted((obj for obj in wanted if not (cache / obj.path).exists()), key=lambda o: o.md5)
    print(f"{len(wanted)} tracked files, {len(missing)} not in the cache")
    download(client, remote, cache, "files", missing, args.dry_run)

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
    parser.add_argument("targets", nargs="*", help=".dvc files, dvc.lock, or tracked paths (default: all)")
    parser.add_argument("--remote", help="DVC remote name (default: the repository's default remote)")
    parser.add_argument("--dry-run", action="store_true", help="show what would be copied")
    parser.add_argument("--force", action="store_true", help="let pull replace files that have local changes")
    parser.add_argument("--syq", help="syq executable (default: the one installed with the syq package)")
    args = parser.parse_args()

    root = next((d for d in [Path.cwd(), *Path.cwd().parents] if (d / ".dvc").is_dir()), None)
    if root is None:
        sys.exit("error: not inside a DVC repository")
    config = configparser.ConfigParser()
    config.read([root / ".dvc" / "config", root / ".dvc" / "config.local"])
    cache = (root / ".dvc" / config.get("cache", "dir", fallback="cache")).resolve()
    remote = read_remote(root, config, args.remote)
    outputs = find_outputs(root, args.targets)
    client = syq.Client(executable=args.syq or os.environ.get("SYQ_EXECUTABLE"))

    if args.command == "push":
        push(client, cache, remote, outputs, args)
    else:
        pull(client, root, cache, remote, outputs, args)


if __name__ == "__main__":
    main()
