#!/usr/bin/env python3
"""Privileged-copy checks confined to the disposable OpenSSH runner container."""
import ctypes
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import tempfile
import time


def run(args, **kwargs):
    return subprocess.run(args, check=True, timeout=30, **kwargs)


def stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        # The test is a subreaper, so helpers orphaned by the killed copier
        # become our children. Reap them before checking group disappearance.
        try:
            while os.waitpid(-process.pid, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        print(f"Waiting for killed copy process group {process.pid} to exit", flush=True)
        time.sleep(0.1)
    raise AssertionError(f"copy process group {process.pid} survived cancellation deadline")


def ownership_only_directories(root):
    """Directories a root copy creates private take their mode back after
    their owner changes to the source's: they end with the source's modes."""
    previous = os.umask(0o022)
    try:
        for uid, gid in [(1001, 1002), (1234, 1234)]:
            source = root / f"owned-{uid}"
            (source / "sub" / "deep").mkdir(parents=True)
            (source / "sub" / "deep" / "file").write_bytes(b"owned")
            for path in [source / "sub" / "deep" / "file", source / "sub" / "deep", source / "sub", source]:
                os.chown(path, uid, gid)
                path.chmod(0o644 if path.is_file() else 0o755)
            for name, args in [
                ("as", ["cp", "--copy-metadata=ownership", str(source), "--as"]),
                ("into", ["cp", "--copy-metadata=ownership", "--srcs-in", str(source), "--into"]),
                ("rsync-rog", ["rsync", "-rog", str(source) + "/"]),
                ("rsync-a", ["rsync", "-a", str(source) + "/"]),
            ]:
                destination = root / f"owned-{uid}-{name}"
                run(["syq", *args, str(destination) + ("/" if name.startswith("rsync") else ""), "--no-progress"])
                for path in [destination, destination / "sub", destination / "sub" / "deep"]:
                    status = path.stat()
                    assert (status.st_mode & 0o7777, status.st_uid, status.st_gid) == (0o755, uid, gid), (
                        name, str(path), oct(status.st_mode), status.st_uid, status.st_gid)
                assert (destination / "sub" / "deep" / "file").read_bytes() == b"owned"
    finally:
        os.umask(previous)
    print("Ownership-only root copies end with the source's directory modes", flush=True)


def planted_files_are_replaced(root):
    """Root never adopts a file another user planted in the destination: a
    file whose size and time match the source's, which the copy would
    otherwise keep, gets neither the source's owner nor its mode; syq
    replaces it, and the planted inode keeps its owner, mode and contents
    (seen here through a second name outside the destination). The same
    holds for --in-place=new, which writes only files it creates, and for a
    hard-link representative, to which syq links no new name."""
    payload = b"source contents\n" * 4096
    planted = b"planted payload\n" * 4096
    for name, args in [
        ("rsync", ["rsync", "-a"]),
        ("native", ["cp", "--copy-metadata=ownership,permissions,mtime"]),
        ("native-mode", ["cp", "--copy-metadata=permissions,mtime"]),
        ("in-place", ["cp", "--in-place=new", "--copy-metadata=permissions"]),
    ]:
        source = root / f"planted-{name}-source"
        destination = root / f"planted-{name}-destination"
        outside = root / f"planted-{name}-outside"
        source.mkdir()
        destination.mkdir()
        (source / "file").write_bytes(payload)
        os.chown(source / "file", 1000, 1000)
        (source / "file").chmod(0o4755)
        os.utime(source / "file", (1_700_000_000, 1_700_000_000))
        target = destination / "file"
        # In place, the planted file's contents differ, so the copy writes
        # them, into a file of its own.
        contents = planted[:1000] if name == "in-place" else planted
        target.write_bytes(contents)
        os.chown(target, 1001, 1001)
        target.chmod(0o644)
        os.utime(target, (1_700_000_000, 1_700_000_000))
        os.link(target, outside)
        before = outside.stat()
        if args[0] == "rsync":
            run(["syq", *args, str(source) + "/", str(destination) + "/", "--no-progress"])
        else:
            run(["syq", *args, "--srcs-in", str(source), "--into", str(destination), "--no-progress"])
        after = outside.stat()
        assert (after.st_ino, after.st_uid, after.st_gid, after.st_mode & 0o7777) == (
            before.st_ino, 1001, 1001, 0o644), (name, after)
        assert outside.read_bytes() == contents, name
        copied = target.stat()
        assert copied.st_ino != before.st_ino, name
        assert target.read_bytes() == payload, name
        owner = 1000 if "ownership" in " ".join(args) or name == "rsync" else 0
        assert copied.st_uid == owner, (name, copied.st_uid)
        assert copied.st_mode & 0o7777 == 0o4755, (name, oct(copied.st_mode))
    print("Planted files are replaced, never adopted, by root copies", flush=True)

    # A planted representative: a group's new name is linked only to the
    # file that replaces it.
    source = root / "planted-group-source"
    destination = root / "planted-group-destination"
    source.mkdir()
    destination.mkdir()
    (source / "a").write_bytes(payload)
    os.link(source / "a", source / "b")
    os.chown(source / "a", 1000, 1000)
    os.utime(source / "a", (1_700_000_000, 1_700_000_000))
    (destination / "a").write_bytes(payload)
    os.chown(destination / "a", 1001, 1001)
    os.utime(destination / "a", (1_700_000_000, 1_700_000_000))
    planted_inode = (destination / "a").stat().st_ino
    run(["syq", "rsync", "-aH", str(source) + "/", str(destination) + "/", "--no-progress"])
    for name in ["a", "b"]:
        status = (destination / name).stat()
        assert status.st_ino != planted_inode, name
        assert status.st_uid == 1000, (name, status.st_uid)
    assert (destination / "a").stat().st_ino == (destination / "b").stat().st_ino
    print("A planted hard-link representative gets no new name", flush=True)


def preview(root, name, source, destination, metadata, *extra):
    """The file traces of a `syq cp` preview."""
    results = root / f"{name}.jsonl"
    run(["syq", "cp", "--dry-run", f"--copy-metadata={metadata}", *extra, "--results", str(results),
         "--srcs-in", str(source), "--into", str(destination), "--no-progress"])
    records = [json.loads(line) for line in results.read_text().splitlines()]
    return [record for record in records if record.get("action") == "transfer_file"]


def root_metadata_repairs(root):
    """Root changes in place the permissions of a file that already has the
    owner and group the copy gives it: `syq rsync -a` keeps the file, with
    an attribute the copy does not select, and a preview counts no content
    work. Without -g, a file whose group a new file would not get is
    replaced, and a preview counts it as rewritten."""
    for size in (100, 1 << 20):  # the small-file copy and the ordinary one
        source = root / f"repair-{size}-source"
        destination = root / f"repair-{size}-destination"
        source.mkdir()
        (source / "file").write_bytes(b"x" * size)
        os.chown(source / "file", 1000, 1000)
        (source / "file").chmod(0o644)
        os.utime(source / "file", (1_700_000_000, 1_700_000_000))
        run(["syq", "rsync", "-a", str(source) + "/", str(destination) + "/", "--no-progress"])
        target = destination / "file"
        os.setxattr(target, "user.keep", b"kept")
        inode = target.stat().st_ino
        (source / "file").chmod(0o600)
        traces = preview(root, f"repair-{size}", source, destination, "ownership,permissions,mtime")
        assert [(t["reason"], t.get("bytes")) for t in traces] == [("metadata_differs", None)], traces
        run(["syq", "rsync", "-a", str(source) + "/", str(destination) + "/", "--no-progress"])
        status = target.stat()
        assert (status.st_ino, status.st_uid, status.st_mode & 0o7777) == (inode, 1000, 0o600), (size, status)
        assert os.getxattr(target, "user.keep") == b"kept", size

        # Without -g, a file's group stays as it is when only its mode changes.
        target.chmod(0o644)
        os.chown(target, 0, 1001)
        traces = preview(root, f"group-{size}", source, destination, "permissions,mtime")
        assert [(t["reason"], t.get("bytes")) for t in traces] == [("metadata_differs", None)], traces
        run(["syq", "cp", "--copy-metadata=permissions,mtime", "--srcs-in", str(source),
             "--into", str(destination), "--no-progress"])
        status = target.stat()
        assert (status.st_ino, status.st_uid, status.st_gid) == (inode, 0, 1001), (size, status)

    # A hard-link group's existing file gets new names only if it already
    # has the owner and group it ends with. Without -g, that is the group a
    # new file gets in its directory: here 0, in a directory of group 0
    # without the set-group-ID bit, so a file of group 1001 is replaced.
    source = root / "group-link-source"
    destination = root / "group-link-destination"
    source.mkdir()
    (source / "a").write_bytes(b"linked" * 1000)
    os.link(source / "a", source / "b")
    os.utime(source / "a", (1_700_000_000, 1_700_000_000))
    run(["syq", "cp", "--copy-metadata=permissions,mtime,hardlinks", "--srcs-in", str(source),
         "--into", str(destination), "--no-progress"])
    os.chown(destination / "a", 0, 1001)
    os.link(source / "a", source / "c")
    inode = (destination / "a").stat().st_ino
    traces = preview(root, "group-link", source, destination, "permissions,mtime,hardlinks")
    assert sorted((t["dst"]["value"], t.get("bytes")) for t in traces) == [("a", 6000), ("b", 0), ("c", 0)], traces
    run(["syq", "cp", "--copy-metadata=permissions,mtime,hardlinks", "--srcs-in", str(source),
         "--into", str(destination), "--no-progress"])
    names = [(destination / name).stat() for name in "abc"]
    assert len({status.st_ino for status in names}) == 1 and names[0].st_ino != inode, names
    assert (names[0].st_uid, names[0].st_gid) == (0, 0), names[0]
    print("Root repairs keep correctly owned files and preview replacements", flush=True)


def root_metadata_by_the_change(root):
    """Root changes in place what a file's owner could change themselves,
    its permission bits and times, also on another user's file, which keeps
    that owner. Another owner, an added set-ID bit or a change to a
    security attribute, here a file capability removed, replaces the file,
    whoever owns it. A preview counts the same files as rewritten."""
    capability = struct.pack("<IIIII", 0x02000001, 1 << 10, 0, 0, 0)
    cases = [
        # name, copy metadata, extra options, source mode, source time,
        # destination owner, destination capability, kept, final owner
        ("mode", "permissions,mtime", (), 0o600, 1_700_000_000, 1001, False, True, 1001),
        ("time", "permissions,mtime", ("--hash",), 0o644, 1_700_000_100, 1001, False, True, 1001),
        ("owner", "ownership,permissions,mtime", (), 0o644, 1_700_000_000, 1001, False, False, 1000),
        ("setid", "permissions,mtime", (), 0o4755, 1_700_000_000, 1001, False, False, 0),
        ("capability", "permissions,mtime,xattrs", (), 0o644, 1_700_000_000, 1001, True, False, 0),
        ("root-capability", "permissions,mtime,xattrs", (), 0o644, 1_700_000_000, 0, True, False, 0),
    ]
    for name, metadata, extra, mode, mtime, owner, has_capability, kept, final in cases:
        source = root / f"change-{name}-source"
        destination = root / f"change-{name}-destination"
        source.mkdir()
        destination.mkdir()
        payload = name.encode() * 1000
        for path in (source / "file", destination / "file"):
            path.write_bytes(payload)
        os.chown(source / "file", 1000, 1000)
        (source / "file").chmod(mode)
        os.utime(source / "file", (mtime, mtime))
        target = destination / "file"
        os.chown(target, owner, owner)
        target.chmod(0o644)
        os.utime(target, (1_700_000_000, 1_700_000_000))
        if has_capability:
            os.setxattr(target, "security.capability", capability)
        inode = target.stat().st_ino
        traces = preview(root, f"change-{name}", source, destination, metadata, *extra)
        assert [(t["reason"], t.get("bytes")) for t in traces] == [
            ("metadata_differs", None if kept else len(payload))], (name, traces)
        run(["syq", "cp", f"--copy-metadata={metadata}", *extra, "--srcs-in", str(source),
             "--into", str(destination), "--no-progress"])
        status = target.stat()
        assert (status.st_ino == inode, status.st_uid) == (kept, final), (name, status)
        assert (status.st_mode & 0o7777, int(status.st_mtime)) == (mode, mtime), (name, status)
        assert "security.capability" not in os.listxattr(target), name
    # The same through syq rsync: `-rpt` changes another user's file's mode
    # in place and leaves it theirs.
    source = root / "change-rsync-source"
    destination = root / "change-rsync-destination"
    source.mkdir()
    (source / "file").write_bytes(b"rsync" * 1000)
    os.utime(source / "file", (1_700_000_000, 1_700_000_000))
    run(["syq", "rsync", "-rpt", str(source) + "/", str(destination) + "/", "--no-progress"])
    os.chown(destination / "file", 1001, 1001)
    inode = (destination / "file").stat().st_ino
    (source / "file").chmod(0o600)
    run(["syq", "rsync", "-rpt", str(source) + "/", str(destination) + "/", "--no-progress"])
    status = (destination / "file").stat()
    assert (status.st_ino, status.st_uid, status.st_mode & 0o7777) == (inode, 1001, 0o600), status
    print("Root changes metadata in place by the change, not the owner", flush=True)


def in_place_update_by_the_change(root):
    """Under --in-place=update, root writes into an existing file only when
    the copy keeps its owner and group. One another user owns, to which the
    copy gives the source's owner, is replaced: someone who had it open
    keeps the old contents, and the summary, --results and a preview say
    why."""
    source = root / "update-source"
    destination = root / "update-destination"
    source.mkdir()
    destination.mkdir()
    payload = b"source contents\n" * 65536
    old = bytearray(payload)
    old[1000] ^= 1
    old = bytes(old)
    for name, owner in (("theirs", 1001), ("mine", 1000)):
        (source / name).write_bytes(payload)
        os.chown(source / name, 1000, 1000)
        (source / name).chmod(0o644)
        os.utime(source / name, (1_700_000_000, 1_700_000_000))
        target = destination / name
        target.write_bytes(old)
        os.chown(target, owner, owner)
        target.chmod(0o644)
        os.utime(target, (1_600_000_000, 1_600_000_000))
    inodes = {name: (destination / name).stat().st_ino for name in ("theirs", "mine")}
    command = ["syq", "cp", "--in-place=update", "--copy-metadata=ownership,permissions,mtime",
               "--srcs-in", str(source), "--into", str(destination), "--no-progress"]

    def replaced(results):
        return json.loads(results.read_text().splitlines()[-1])["replaced_not_in_place"]

    preview = root / "update-preview.jsonl"
    run([*command, "--dry-run", "--results", str(preview)])
    assert replaced(preview) == {"owner": 1}, replaced(preview)
    results = root / "update.jsonl"
    with open(destination / "theirs", "rb") as held:
        output = run([*command, "--results", str(results)], capture_output=True, text=True)
        assert held.read() == old
    summary = "syq: replaced 1 existing file instead of updating it in place: 1 with another owner or group"
    assert summary in output.stdout, output
    assert replaced(results) == {"owner": 1}, replaced(results)
    for name, kept in (("theirs", False), ("mine", True)):
        status = (destination / name).stat()
        assert (status.st_ino == inodes[name], status.st_uid) == (kept, 1000), (name, status)
        assert (destination / name).read_bytes() == payload, name
    print("Root updates in place only files whose owner the copy keeps", flush=True)


def main():
    assert os.geteuid() == 0, "run this check as root only inside the disposable lab"
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER, Linux lab only
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    with tempfile.TemporaryDirectory(prefix="syq-root-security-") as temporary:
        root = Path(temporary)
        ownership_only_directories(root)
        planted_files_are_replaced(root)
        root_metadata_repairs(root)
        root_metadata_by_the_change(root)
        in_place_update_by_the_change(root)
        for interface in ["native", "native-owner", "rsync"]:
            source = root / f"source-{interface}"
            destination = root / f"destination-{interface}"
            source.write_bytes(b"payload\0" * (1 << 20))
            os.chown(source, 1000, 1000)
            if interface == "rsync":
                args = ["syq", "rsync", "-a", "--performance-tuning", "workers=1", "--resource-limits", "bandwidth=1G", str(source), str(destination)]
            else:
                args = ["syq", "cp", "--performance-tuning", "workers=1", "--performance-tuning", "copy-path=ranges", str(source), "--as", str(destination)]
                if interface == "native-owner":
                    args.extend(["--copy-metadata", "ownership,permissions"])
            args.append("--no-progress")
            ready = root / f"partial-ready-{interface}"
            continuation = root / f"partial-continue-{interface}"
            process = subprocess.Popen(args, env={
                **os.environ,
                "SYQ_TEST_PARTIAL_READY_FILE": str(ready),
                "SYQ_TEST_PARTIAL_CONTINUE_FILE": str(continuation),
            }, start_new_session=True)
            deadline = time.monotonic() + 10
            partials = []
            try:
                while time.monotonic() < deadline:
                    if ready.exists():
                        partials = list(root.glob(".*.syq-tmp.*"))
                        break
                    assert process.poll() is None, "copy exited before producing a partial"
                    print(f"Waiting for {interface} partial: {partials}", flush=True)
                    time.sleep(0.1)
                assert len(partials) == 1, f"partial deadline expired: {partials}"
            finally:
                stop_group(process)
            partial = partials[0]
            partial.write_bytes(b"foreign inode must remain untouched")
            os.chown(partial, 1000, 1000)
            partial.chmod(0o666)
            with partial.open("rb") as held:
                old = os.fstat(held.fileno())
                run(args)
                published = destination.stat()
                assert (published.st_dev, published.st_ino) != (old.st_dev, old.st_ino)
                assert published.st_uid == (0 if interface == "native" else 1000)
                assert destination.read_bytes() == source.read_bytes()
                assert held.read() == b"foreign inode must remain untouched"
                after = os.fstat(held.fileno())
                assert after.st_uid == 1000 and after.st_mode & 0o777 == 0o666
                assert partial.exists()
            run(["syq", "clean-partials", str(root)])
            assert not partial.exists()
            print(f"Foreign-owned partial refused; requested ownership preserved: {interface}", flush=True)

        # Only this disposable root runner may exercise privileged namespaces.
        archive = root / "archive-source"
        archive.mkdir()
        file = archive / "executable"
        file.write_bytes(b"privileged metadata fixture")
        os.link(file, archive / "alias")
        os.chown(file, 1000, 1000)
        file.chmod(0o6750)
        capability = struct.pack("<IIIII", 0x02000001, 1 << 10, 0, 0, 0)
        os.setxattr(file, "security.capability", capability)
        os.setxattr(file, "user.binary", b"\x00\xffcapability")
        for options in [[], ["--inplace"], ["--performance-tuning=copy-path=ranges"]]:
            target = root / ("archive-" + str(len(list(root.glob("archive-*")))))
            command = ["syq", "rsync", "-aHAX", "--numeric-ids", *options, str(archive) + "/", str(target) + "/"]
            run(command)
            run(command)
            for name in ["executable", "alias"]:
                copied = target / name
                assert copied.read_bytes() == file.read_bytes()
                assert (copied.stat().st_uid, copied.stat().st_gid) == (1000, 1000)
                assert copied.stat().st_mode & 0o7777 == 0o6750
                assert os.getxattr(copied, "security.capability") == os.getxattr(file, "security.capability")
                assert os.getxattr(copied, "user.binary") == b"\x00\xffcapability"
            assert (target / "executable").stat().st_ino == (target / "alias").stat().st_ino
        print("Privileged xattrs, ownership and set-ID ordering passed", flush=True)

        # A reader without ownership/CAP_FOWNER must warn and copy normally.
        root.chmod(0o755)
        foreign = root / "noatime-foreign"
        foreign.write_bytes(b"readable by another user")
        foreign.chmod(0o644)
        target = root / "noatime-user"
        target.mkdir()
        os.chown(target, 1000, 1000)
        result = run(["runuser", "-u", "syq", "--", "syq", "cp", "--open-noatime", "--copy-metadata=atimes", str(foreign), "--as", str(target / "copied")], capture_output=True, text=True)
        assert "--open-noatime unavailable" in result.stderr, result.stderr
        assert (target / "copied").read_bytes() == foreign.read_bytes()
        print("Nonowner no-atime reads warn and complete", flush=True)

        selected = root / "typed-link"
        destination = root / "typed-link-copy"
        # The ownership opt-out permits a typed directory symlink while
        # subsequent source discovery still uses its retained directory.
        directory = root / "typed-directory"
        directory.mkdir()
        (directory / "file").write_bytes(b"selected")
        selected.symlink_to(directory, target_is_directory=True)
        os.lchown(selected, 1000, 1000)
        refused = subprocess.run(["syq", "rsync", "-a", str(selected) + "/", str(destination)], timeout=10)
        assert refused.returncode != 0
        run(["syq", "rsync", "-a", "--insecure-links", str(selected) + "/", str(destination)])
        assert (destination / "file").read_bytes() == b"selected"
    print("Privileged copy security checks passed", flush=True)


if __name__ == "__main__":
    main()
