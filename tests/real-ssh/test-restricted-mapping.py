"""Mapping and timestamp selection across actual source/destination SSH edges."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def run(argv, *, data=None, expected=0):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if result.returncode != expected:
        raise AssertionError(f"{shlex.join(argv)}: exit {result.returncode}\n{result.stdout.decode(errors='replace')}\n{result.stderr.decode(errors='replace')}")
    return result


def matching_preview(argv, *, data, files):
    with tempfile.TemporaryDirectory(prefix="syq-mapping-preview-") as temporary:
        path = Path(temporary) / "results.ndjson"
        run(argv + ["--dry-run", "--hash", "--results", str(path)], data=data)
        records = [json.loads(line) for line in path.read_text().splitlines()]
        terminal = records[-1]
        assert terminal["type"] == "result" and terminal["status"] == "success", records
        assert terminal["dry_run"] and terminal["errors"] == 0, terminal
        assert terminal["files_unchanged"] == files, terminal
        assert terminal["files_transferred"] == 0, terminal
        assert terminal["symlinks_created"] == terminal["specials_created"] == 0, terminal
        assert not any(r["type"] == "trace" and r.get("bytes") is not None for r in records), records


def ssh(host, script):
    return run(["ssh", host, "python3 -c " + shlex.quote(script)])


def manifest(entries, expected=None):
    records = []
    for src, dst, kind in entries:
        record = {"src": {"encoding": "utf-8", "value": src}, "dst": {"encoding": "utf-8", "value": dst}, "kind": kind}
        if expected is not None:
            record["expected_hash"] = expected
        records.append(json.dumps(record) + "\n")
    return "".join(records).encode()


def hashing(root, source, temporary):
    """Exercise checksum policy on real transports and signed mapping grants."""
    payload = b"hash policy over real SSH\n" * 8192
    local = Path(temporary) / "hash-source"
    local.write_bytes(payload)
    sha256 = hashlib.sha256(payload).hexdigest()
    md5 = hashlib.md5(payload).hexdigest()
    wrong_md5 = hashlib.md5(b"different bytes").hexdigest()
    for name, flags in [("encrypted", []), ("plain", ["--no-tcp-encryption"])]:
        print(f"hash policy: ordinary {name} TCP", flush=True)
        destination = root + "/hash-" + name
        command = ["syq", "cp", "--if-exists=update", "--no-progress", "--performance-tuning", "workers=1", "-C", str(local.parent), "--mapping", "-", "--to", "destination", "--into", root,
                   "--integrity-checking", "compare=xxh3-128", "--integrity-checking=transfer=blake3", "--performance-tuning", "copy-path=ranges"] + flags
        run(command, data=manifest([(local.name, "hash-" + name, "file")], {"algorithm": "sha256", "value": sha256}))
        results = str(Path(temporary) / ("hash-repeat-" + name + ".ndjson"))
        run(command + ["--results", results], data=manifest([(local.name, "hash-" + name, "file")], {"algorithm": "sha256", "value": sha256}))
        summary = json.loads(Path(results).read_text().splitlines()[-1])
        assert summary["files_unchanged"] == 1 and summary["bytes_transferred"] == 0, summary
        # Hash previews read both endpoints, retain mapping identities, and do not publish.
        preview = str(Path(temporary) / ("hash-preview-" + name + ".ndjson"))
        run(command + ["--dry-run", "--results", preview], data=manifest([(local.name, "hash-" + name, "file")]))
        summary = json.loads(Path(preview).read_text().splitlines()[-1])
        assert summary["files_unchanged"] == 1 and summary["files_transferred"] == 0, summary
        ssh("destination", f"from pathlib import Path; import os; p=Path({destination!r}); m=p.stat(); p.write_bytes(b'x'*{len(payload)}); os.utime(p, ns=(m.st_atime_ns,m.st_mtime_ns))")
        preview = str(Path(temporary) / ("hash-preview-changed-" + name + ".ndjson"))
        run(command + ["--dry-run", "--results", preview], data=manifest([(local.name, "hash-" + name, "file")]))
        records = [json.loads(line) for line in Path(preview).read_text().splitlines()]
        assert records[-1]["files_transferred"] == 1 and records[-1]["status"] == "success", records
        assert any(r["type"] == "trace" and r["reason"] == "content_differs" and r["src"]["value"] == local.name for r in records), records
        ssh("destination", f"from pathlib import Path; assert Path({destination!r}).read_bytes()==b'x'*{len(payload)}")
        # compare=xxh3-128 checks the existing file with the selected algorithm.
        run(command, data=manifest([(local.name, "hash-" + name, "file")], {"algorithm": "md5", "value": md5}))
        run(command, data=manifest([(local.name, "hash-" + name, "file")], {"algorithm": "md5", "value": wrong_md5}), expected=23)
        ssh("destination", f"from pathlib import Path; import hashlib; assert hashlib.sha256(Path({destination!r}).read_bytes()).hexdigest()=={sha256!r}")
        # A changed target must remain intact when staged validation fails.
        ssh("destination", f"from pathlib import Path; Path({destination!r}).write_bytes(b'keep existing')")
        run(command, data=manifest([(local.name, "hash-" + name, "file")], {"algorithm": "md5", "value": wrong_md5}), expected=23)
        ssh("destination", f"from pathlib import Path; assert Path({destination!r}).read_bytes()==b'keep existing'")

    print("hash policy: signed mapping with independent expected digest", flush=True)
    destination = root + "/hash-signed"
    expected = {"algorithm": "md5", "value": hashlib.md5(b"mapped contents").hexdigest()}
    selected = [("file", "checked", "file")]
    command = ["syq", "cp", "--if-exists=update", "--no-progress", "--performance-tuning", "workers=1", "--from", "source", "-C", source,
               "--mapping", "-", "--to", "destination", "--into", destination,
               "--integrity-checking", "compare=xxh3-128", "--integrity-checking=transfer=blake3"]
    run(command, data=manifest(selected, expected))
    results = str(Path(temporary) / "hash-repeat-signed.ndjson")
    inode_query = f"from pathlib import Path; print((Path({destination!r})/'checked').stat().st_ino)"
    inode = ssh("destination", inode_query).stdout
    run(command + ["--results", results], data=manifest(selected, expected))
    records = [json.loads(line) for line in Path(results).read_text().splitlines()]
    summary = records[-1]
    # The destination reports no change; the coordinator counts the
    # unchanged file.
    assert summary["bytes_transferred"] == 0 and summary["files_unchanged"] == 1, summary
    assert summary["status"] == "success", summary
    assert not any(r["type"] == "operation_result" for r in records), records
    assert ssh("destination", inode_query).stdout == inode
    wrong = {"algorithm": "sha256", "value": hashlib.sha256(b"different bytes").hexdigest()}
    run(command, data=manifest(selected, wrong), expected=23)
    ssh("destination", f"from pathlib import Path; assert (Path({destination!r})/'checked').read_bytes()==b'mapped contents'")
    ssh("destination", f"from pathlib import Path; (Path({destination!r})/'checked').write_bytes(b'keep signed target')")
    run(command + ["--no-tcp"], data=manifest(selected, wrong), expected=23)
    ssh("destination", f"from pathlib import Path; assert (Path({destination!r})/'checked').read_bytes()==b'keep signed target'")


def direct():
    root = "/tmp/syq-real-ssh/mapping"
    source = root + "/source"
    ssh("destination", f"from pathlib import Path; Path({root!r}).mkdir(parents=True)")
    ssh("source", f"from pathlib import Path; import os; p=Path({source!r}); p.mkdir(parents=True); (p/'file').write_bytes(b'mapped contents'); (p/'directory').mkdir(); (p/'directory'/'unselected').write_bytes(b'exclude'); (p/'link').symlink_to('nested/renamed'); os.utime(p/'file',(1600000000,1600000000))")
    entries = [("file", "nested/renamed", "file"), ("link", "link", "symlink"), ("directory", "directory", "dir")]
    contents = manifest(entries)
    prefix = ["syq", "cp", "--no-progress", "--performance-tuning", "workers=2", "--from", "source", "-C", source]
    with tempfile.TemporaryDirectory(prefix="syq-mapping-") as temporary:
        hashing(root, source, temporary)
        path = Path(temporary) / "manifest.ndjson"
        path.write_bytes(contents)
        routes = [
            ("tcp", [], str(path)),
            ("ssh", ["--no-tcp"], "-"),
            ("fallback", ["--tcp-ports", f"{os.environ['SYQ_REAL_SSH_BLOCKED_TCP_PORT']}-{os.environ['SYQ_REAL_SSH_BLOCKED_TCP_PORT']}"], "-"),
            ("relay", ["--coordinate-at", "local"], "-"),
            ("destination-coordinator", ["--coordinate-at", "dst", "--peer-auth", "broker"], "-"),
        ]
        for name, flags, operand in routes:
            print(f"mapping route: {name}", flush=True)
            destination = root + "/" + name
            results_path = Path(temporary) / f"results-{name}.ndjson"
            result = run(prefix + ["--mapping", operand, "--to", "destination", "--into", destination, "--results", str(results_path)] + flags, data=contents if operand == "-" else None)
            # Every route writes the same ordinary results on this machine.
            records = [json.loads(line) for line in results_path.read_text().splitlines()]
            assert records[0]["type"] == "run" and [r["seq"] for r in records] == list(range(len(records))), records
            assert records[-1]["type"] == "result" and records[-1]["status"] == "success", records[-1]
            changed = sorted(r["dst"]["value"] for r in records if r["type"] == "operation_result" and r["disposition"] == "succeeded")
            assert changed == ["directory", "link", "nested", "nested/renamed"] or changed == ["directory", "link", "nested/renamed"], (name, changed)
            if name == "fallback":
                assert b"data over ssh" in result.stderr, result.stderr
            ssh("destination", f"from pathlib import Path; p=Path({destination!r}); assert (p/'nested'/'renamed').read_bytes()==b'mapped contents'; assert (p/'link').is_symlink(); assert (p/'nested').stat().st_mode & 0o777 == 0o755; assert (p/'directory').is_dir(); assert not (p/'directory'/'unselected').exists()")
        print("mapping destination metadata: ordinary and signed SSH", flush=True)
        selected = json.loads(manifest([("file", "file", "file")]))
        owner = json.loads(ssh("destination", "import os,json; print(json.dumps([os.getuid(),os.getgid()]))").stdout)
        selected["metadata"] = {"mode": 0o640, "mtime": 123, "mtime_nsec": 456, "uid": owner[0], "gid": owner[1]}
        metadata_manifest = (json.dumps(selected) + "\n").encode()
        destination = root + "/metadata"
        command = prefix + ["--mapping", "-", "--to", "destination", "--into", destination, "--no-tcp", "--if-exists=update"]
        # The signed mapping authorizes the metadata it sets itself; the
        # copy options are not needed for it.
        run(command, data=metadata_manifest)
        ssh("destination", f"from pathlib import Path; p=Path({destination!r})/'file'; assert p.read_bytes()==b'mapped contents'; s=p.stat(); assert s.st_mode & 0o7777==0o640; assert s.st_mtime_ns==123000000456; p.chmod(0o600)")
        run(command + ["--copy-metadata=permissions,ownership"], data=metadata_manifest)
        ssh("destination", f"from pathlib import Path; p=Path({destination!r})/'file'; assert p.read_bytes()==b'mapped contents'; s=p.stat(); assert s.st_mode & 0o7777==0o640; assert s.st_mtime_ns==123000000456")
        local_source = Path(temporary) / "metadata-source"
        local_source.mkdir()
        (local_source / "file").write_bytes(b'ordinary mapping')
        run(["syq", "cp", "--if-exists=update", "--no-progress", "-C", str(local_source), "--mapping", "-", "--to", "destination", "--into", destination, "--no-tcp"], data=metadata_manifest)
        ssh("destination", f"from pathlib import Path; p=Path({destination!r})/'file'; assert p.read_bytes()==b'ordinary mapping'; s=p.stat(); assert s.st_mode & 0o7777==0o640; assert s.st_mtime_ns==123000000456")
        if owner[0] != 0:
            selected["metadata"]["uid"] = 4294967294
            denied_manifest = (json.dumps(selected) + "\n").encode()
            run(command + ["--copy-metadata=permissions,ownership"], data=denied_manifest, expected=23)
            ssh("destination", f"from pathlib import Path; assert (Path({destination!r})/'file').read_bytes()==b'ordinary mapping'")
        destination = root + "/tcp"
        matching_preview(prefix + ["--mapping", "-", "--to", "destination", "--into", destination, "--coordinate-at", "local"], data=contents, files=1)
        # Selection uses source mtimes; --only-existing remains independently enforced.
        ssh("destination", f"from pathlib import Path; import os; p=Path({destination!r})/'nested'/'renamed'; p.write_bytes(b'newer destination'); os.utime(p,(1700000000,1700000000))")
        updating = manifest([("file", "nested/renamed", "file"), ("file", "nested/missing", "file")])
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", destination, "--if-exists=update-if-older", "--only-existing"], data=updating)
        ssh("destination", f"from pathlib import Path; p=Path({destination!r}); assert (p/'nested'/'renamed').read_bytes()==b'newer destination'; assert not (p/'nested'/'missing').exists()")
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", destination, "--if-exists=update-if-older"], data=updating)
        ssh("destination", f"from pathlib import Path; p=Path({destination!r}); assert (p/'nested'/'renamed').read_bytes()==b'newer destination'; assert (p/'nested'/'missing').read_bytes()==b'mapped contents'")
        ssh("destination", f"import os; os.utime({destination + '/nested/renamed'!r},(1500000000,1500000000))")
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", destination, "--if-exists=update-if-older"], data=updating)
        ssh("destination", f"from pathlib import Path; assert Path({destination + '/nested/renamed'!r}).read_bytes()==b'mapped contents'")
        # PR #275's only-new policy also preserves existing directory metadata.
        only_new = root + "/only-new"
        ssh("destination", f"from pathlib import Path; import os; p=Path({only_new!r}); p.mkdir(); (p/'kept').write_bytes(b'keep destination'); (p/'directory').mkdir(); (p/'directory').chmod(0o555); os.utime(p/'directory',(1500000000,1500000000))")
        selected = manifest([("file", "kept", "file"), ("file", "fresh", "file"), ("directory", "directory", "dir")])
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", only_new, "--if-exists=keep"], data=selected)
        ssh("destination", f"from pathlib import Path; p=Path({only_new!r}); assert (p/'kept').read_bytes()==b'keep destination'; assert (p/'fresh').read_bytes()==b'mapped contents'; d=(p/'directory').stat(); assert d.st_mode & 0o777 == 0o555; assert d.st_mtime_ns==1500000000000000000; (p/'directory').chmod(0o755)")
        # Implicit parents reopen only as needed, then recover receiver modes.
        for extra in [[], ["--only-existing"], ["--copy-metadata=permissions"]]:
            readonly = root + "/readonly-" + str(len(extra)) + ("-p" if "--copy-metadata=permissions" in extra else "")
            ssh("destination", f"from pathlib import Path; p=Path({readonly!r}); (p/'parent').mkdir(parents=True); (p/'parent'/'item').write_bytes(b'old'); (p/'parent').chmod(0o2550)")
            run(prefix + ["--mapping", "-", "--to", "destination", "--into", readonly, "--no-tcp", "--if-exists=update", "--widen-dirs=rsync"] + extra,
                data=manifest([("file", "parent/item", "file")]))
            ssh("destination", f"from pathlib import Path; p=Path({readonly!r})/'parent'; assert (p/'item').read_bytes()==b'mapped contents'; assert p.stat().st_mode & 0o7777 == 0o2550; p.chmod(0o755)")
        # The grant names how far the receiver may widen. An exact target
        # in a read-only enrolled directory needs `all`, which widens that
        # directory, but nothing above it, and restores it; under `none` or
        # `rsync` the copy fails and names `all`.
        exact_root = root + "/readonly-exact"
        ssh("destination", f"from pathlib import Path; p=Path({exact_root!r}); p.mkdir(); p.chmod(0o555)")
        run(["syq", "receiver", "enroll", "destination:" + exact_root + "/item"])
        for widen in ["none", "rsync", "all"]:
            result = run(prefix + ["file", "--to", "destination", "--as", exact_root + "/item", "--no-tcp", f"--widen-dirs={widen}"],
                         expected=0 if widen == "all" else 23)
            if widen != "all":
                assert b"--widen-dirs=all may help" in result.stderr, result.stderr
        ssh("destination", f"from pathlib import Path; p=Path({exact_root!r}); assert (p/'item').read_bytes()==b'mapped contents'; assert p.stat().st_mode & 0o7777 == 0o555; p.chmod(0o755)")
        # Under `all` the receiver also gives the directories from its
        # enrolled root down to the destination the search permission
        # reaching it needs, here the root itself, and nothing above it;
        # under `rsync` the copy is refused and names `all`.
        unsearchable = root + "/unsearchable-root"
        ssh("destination", f"from pathlib import Path; (Path({unsearchable!r})/'into').mkdir(parents=True)")
        run(["syq", "receiver", "enroll", "destination:" + unsearchable + "/into"])
        ssh("destination", f"from pathlib import Path; Path({unsearchable!r}).chmod(0o600)")
        into = prefix + ["file", "--to", "destination", "--into", unsearchable + "/into", "--no-tcp"]
        refused = run(into + ["--widen-dirs=rsync"], expected=1)
        assert b"--widen-dirs=all may help" in refused.stderr, refused.stderr
        run(into + ["--widen-dirs=all"])
        ssh("destination", f"from pathlib import Path; p=Path({unsearchable!r}); assert p.stat().st_mode & 0o7777 == 0o600; p.chmod(0o755); assert (p/'into'/'file').read_bytes()==b'mapped contents'")
        # A signed preview never changes permissions, with or without the
        # option, so read-only grants need no authority for it. A directory it
        # cannot search is reported rather than treated as empty.
        for mode in [0o500, 0o600]:
            for widen in [False, True]:
                for placement in ["--into", "--as"]:
                    preview_root = root + f"/readonly-preview-{mode:o}-{int(widen)}-{placement[2:]}"
                    ssh("destination", f"from pathlib import Path; p=Path({preview_root!r}); p.mkdir(); (p/'item').write_bytes(b'keep preview')")
                    if placement == "--into":
                        sources = ["--mapping", "-"]
                        destination = preview_root
                        data = manifest([("file", "item", "file")])
                    else:
                        sources = ["file"]
                        destination = preview_root + "/item"
                        data = None
                    # Enrollment is fixture setup, not something a signed
                    # read-only preview may create. Exact-file placement uses
                    # a different enrolled parent from container placement.
                    run(["syq", "receiver", "enroll", "destination:" + destination])
                    before = ssh("destination", f"from pathlib import Path; p=Path({preview_root!r}); p.chmod({mode}); print(p.stat().st_ctime_ns)").stdout.strip()
                    command = prefix + sources + ["--to", "destination", placement, destination,
                                                   "--no-tcp", "--if-exists=update", "--dry-run"]
                    if widen:
                        command.append("--widen-dirs=rsync")
                    expected = 0 if mode == 0o500 else 23 if placement == "--into" else 1
                    preview = run(command, data=data, expected=expected)
                    if mode == 0o600:
                        reported = b"not inspected" if placement == "--into" else b"Permission denied"
                        assert reported in preview.stderr, preview.stderr
                    after = ssh("destination", f"from pathlib import Path; p=Path({preview_root!r}); s=p.stat(); assert s.st_mode & 0o777 == {mode}; print(s.st_ctime_ns); p.chmod(0o700); assert (p/'item').read_bytes()==b'keep preview'; assert list(p.iterdir())==[p/'item']").stdout.strip()
                    assert before == after, (mode, widen, placement, before, after)
        # An untouched writable parent needs no chmod (ctime must stay intact).
        stable = root + "/writable-parent"
        before = ssh("destination", f"from pathlib import Path; p=Path({stable!r})/'parent'; p.mkdir(parents=True); (p/'item').write_bytes(b'mapped contents'); __import__('os').utime(p/'item',(1600000000,1600000000)); print(p.stat().st_ctime_ns)").stdout.strip()
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", stable, "--no-tcp"], data=manifest([("file", "parent/item", "file")]))
        after = ssh("destination", f"from pathlib import Path; print((Path({stable!r})/'parent').stat().st_ctime_ns)").stdout.strip()
        assert before == after, (before, after)
        # A file or symlink where an implicit parent goes is not replaced:
        # each such parent is reported once, as on an ordinary receiver, and
        # blocks only the mapped entries beneath it.
        blocked = root + "/blocked"
        ssh("destination", f"from pathlib import Path; p=Path({blocked!r}); p.mkdir(); (p/'blocked-file').write_bytes(b'keep file'); (p/'protected').mkdir(); (p/'protected'/'sentinel').write_bytes(b'keep target'); (p/'blocked-link').symlink_to('protected')")
        blocked_entries = [("file", "blocked-file/deep/item", "file"), ("file", "blocked-link/item", "file"), ("directory", "blocked-file/directory", "dir")]
        selected = manifest(blocked_entries + [("file", "good/item", "file")])
        preview = run(prefix + ["--mapping", "-", "--to", "destination", "--into", blocked, "--no-tcp", "--dry-run"], data=selected, expected=23)
        assert preview.stderr.count(b"cannot replace non-directory") == 2, preview.stderr
        ssh("destination", f"from pathlib import Path; assert not (Path({blocked!r})/'good').exists()")
        results_path = Path(temporary) / "results-blocked.ndjson"
        result = run(prefix + ["--mapping", "-", "--to", "destination", "--into", blocked, "--no-tcp", "--results", str(results_path)], data=selected, expected=23)
        assert result.stderr.count(b"cannot replace non-directory") == 2, result.stderr
        records = [json.loads(line) for line in results_path.read_text().splitlines()]
        # Planner failures arrive as the coordinator's error records and make
        # the outcome partial.
        assert records[-1]["status"] == "partial", records[-1]
        assert any(r["type"] == "error" and "cannot replace non-directory" in r["message"] for r in records), records
        ssh("destination", f"from pathlib import Path; p=Path({blocked!r}); assert (p/'blocked-file').read_bytes()==b'keep file'; assert (p/'blocked-link').is_symlink(); assert list((p/'protected').iterdir())==[p/'protected'/'sentinel']; assert (p/'protected'/'sentinel').read_bytes()==b'keep target'; assert (p/'good'/'item').read_bytes()==b'mapped contents'")
        # Exceeds both the old grant scope count and one mapping protocol chunk.
        ssh("source", f"from pathlib import Path; import os; p=Path({source!r})/'directory'; p.chmod(0o750); os.utime(p,(1500000000,1500000000))")
        # Even a later explicit directory entry cannot replace an old file.
        # Unrelated implicit-parent conflicts span different scan batches.
        ssh("destination", f"from pathlib import Path; p=Path({root + '/large'!r}); p.mkdir(); (p/'group').write_bytes(b'keep explicit parent'); (p/'blocked').write_bytes(b'keep implicit parent')")
        large = manifest([("file", "blocked/first", "file")] + [("file", f"group/file-{i}", "file") for i in range(10_000)] + [("directory", "group", "dir"), ("file", "blocked/last", "file")])
        assert len(large) > 1024 * 1024
        print("mapping route: large SSH manifest", flush=True)
        results_path = Path(temporary) / "results-large.ndjson"
        result = run(prefix + ["--mapping", "-", "--to", "destination", "--into", root + "/large", "--no-tcp", "--copy-metadata=permissions", "--results", str(results_path)], data=large, expected=23)
        assert result.stderr.count(b"cannot replace non-directory") == 2, result.stderr
        records = [json.loads(line) for line in results_path.read_text().splitlines()]
        assert records[-1]["status"] == "partial", records[-1]
        ssh("destination", f"from pathlib import Path; assert Path({root + '/large/blocked'!r}).read_bytes()==b'keep implicit parent'")
        ssh("destination", f"from pathlib import Path; p=Path({root + '/large/group'!r}); assert p.read_bytes()==b'keep explicit parent'; p.unlink()")
        # Once the fixture obstruction is removed, the late explicit entry
        # supplies directory metadata after all 10,000 mapped files are copied.
        results_path = Path(temporary) / "results-large-unblocked.ndjson"
        result = run(prefix + ["--mapping", "-", "--to", "destination", "--into", root + "/large", "--no-tcp", "--copy-metadata=permissions", "--results", str(results_path)], data=large, expected=23)
        assert result.stderr.count(b"cannot replace non-directory") == 1, result.stderr
        records = [json.loads(line) for line in results_path.read_text().splitlines()]
        assert records[-1]["status"] == "partial", records[-1]
        ssh("destination", f"from pathlib import Path; p=Path({root + '/large/group'!r}); files=list(p.iterdir()); assert len(files)==10000; assert all(f.read_bytes()==b'mapped contents' for f in files); assert p.stat().st_mode & 0o777 == 0o750; assert p.stat().st_mtime_ns == 1500000000000000000")
    print("Restricted mapping and timestamp selection passed", flush=True)


def named():
    source = "/tmp/syq-real-ssh/return-source"
    contents = manifest([("message.txt", "nested/renamed", "file")])
    prefix = ["syq", "cp", "--no-progress", "-C", source, "--mapping", "-", "--to", "@laptop", "--into", "mapped-return"]
    run(prefix, data=contents)
    matching_preview(prefix, data=contents, files=1)
    run(prefix + ["--if-exists=update-if-older", "--only-existing"], data=contents)
    # A file where an implicit parent goes is reported once, as the
    # directory that could not replace it, and blocks the entries beneath.
    blocked = manifest([("message.txt", "nested/renamed/child", "file"), ("message.txt", "nested/good", "file")])
    with tempfile.TemporaryDirectory(prefix="syq-named-mapping-") as temporary:
        results_path = Path(temporary) / "results.ndjson"
        run(prefix + ["--results", str(results_path)], data=blocked, expected=23)
        records = [json.loads(line) for line in results_path.read_text().splitlines()]
        failed = [r for r in records if r.get("disposition") == "failed"]
        assert [r["dst"]["value"] for r in failed] == ["nested/renamed"], failed
        assert records[-1]["status"] == "partial", records[-1]
    matching_preview(prefix, data=contents + manifest([("message.txt", "nested/good", "file")]), files=2)
    print("Named mapping and timestamp selection passed", flush=True)


if __name__ == "__main__":
    (named if sys.argv[1:] == ["named"] else direct)()
