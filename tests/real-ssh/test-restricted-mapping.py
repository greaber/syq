"""Mapping and timestamp selection across actual source/destination SSH edges."""
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


def ssh(host, script):
    return run(["ssh", host, "python3 -c " + shlex.quote(script)])


def manifest(entries):
    return "".join(json.dumps({"src": {"encoding": "utf-8", "value": src}, "dst": {"encoding": "utf-8", "value": dst}, "kind": kind}) + "\n" for src, dst, kind in entries).encode()


def direct():
    root = "/tmp/syq-real-ssh/mapping"
    source = root + "/source"
    ssh("destination", f"from pathlib import Path; Path({root!r}).mkdir(parents=True)")
    ssh("source", f"from pathlib import Path; import os; p=Path({source!r}); p.mkdir(parents=True); (p/'file').write_bytes(b'mapped contents'); (p/'directory').mkdir(); (p/'directory'/'unselected').write_bytes(b'exclude'); (p/'link').symlink_to('nested/renamed'); os.utime(p/'file',(1600000000,1600000000))")
    entries = [("file", "nested/renamed", "file"), ("link", "link", "symlink"), ("directory", "directory", "dir")]
    contents = manifest(entries)
    prefix = ["syq", "cp", "--no-progress", "-j", "2", "--from", "source", "-C", source]
    with tempfile.TemporaryDirectory(prefix="syq-mapping-") as temporary:
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
            result_flags = ["--results", str(results_path)] if name in {"tcp", "ssh", "fallback"} else []
            result = run(prefix + ["--mapping", operand, "--to", "destination", "--into", destination] + flags + result_flags, data=contents if operand == "-" else None)
            if result_flags:
                records = [json.loads(line) for line in results_path.read_text().splitlines()]
                assert records[-1]["type"] == "result" and records[-1]["status"] == "success", records[-1]
            if name == "fallback":
                assert b"data over ssh" in result.stderr, result.stderr
            ssh("destination", f"from pathlib import Path; p=Path({destination!r}); assert (p/'nested'/'renamed').read_bytes()==b'mapped contents'; assert (p/'link').is_symlink(); assert (p/'nested').stat().st_mode & 0o777 == 0o755; assert (p/'directory').is_dir(); assert not (p/'directory'/'unselected').exists()")
        destination = root + "/tcp"
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", destination, "--verify-only"], data=contents)
        # Selection uses source mtimes; --only-existing remains independently enforced.
        ssh("destination", f"from pathlib import Path; import os; p=Path({destination!r})/'nested'/'renamed'; p.write_bytes(b'newer destination'); os.utime(p,(1700000000,1700000000))")
        updating = manifest([("file", "nested/renamed", "file"), ("file", "nested/missing", "file")])
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", destination, "--skip-newer", "--only-existing"], data=updating)
        ssh("destination", f"from pathlib import Path; p=Path({destination!r}); assert (p/'nested'/'renamed').read_bytes()==b'newer destination'; assert not (p/'nested'/'missing').exists()")
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", destination, "--skip-newer"], data=updating)
        ssh("destination", f"from pathlib import Path; p=Path({destination!r}); assert (p/'nested'/'renamed').read_bytes()==b'newer destination'; assert (p/'nested'/'missing').read_bytes()==b'mapped contents'")
        ssh("destination", f"import os; os.utime({destination + '/nested/renamed'!r},(1500000000,1500000000))")
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", destination, "--skip-newer"], data=updating)
        ssh("destination", f"from pathlib import Path; assert Path({destination + '/nested/renamed'!r}).read_bytes()==b'mapped contents'")
        # PR #275's only-new policy also preserves existing directory metadata.
        only_new = root + "/only-new"
        ssh("destination", f"from pathlib import Path; import os; p=Path({only_new!r}); p.mkdir(); (p/'kept').write_bytes(b'keep destination'); (p/'directory').mkdir(); (p/'directory').chmod(0o555); os.utime(p/'directory',(1500000000,1500000000))")
        selected = manifest([("file", "kept", "file"), ("file", "fresh", "file"), ("directory", "directory", "dir")])
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", only_new, "--only-new"], data=selected)
        ssh("destination", f"from pathlib import Path; p=Path({only_new!r}); assert (p/'kept').read_bytes()==b'keep destination'; assert (p/'fresh').read_bytes()==b'mapped contents'; d=(p/'directory').stat(); assert d.st_mode & 0o777 == 0o555; assert d.st_mtime_ns==1500000000000000000; (p/'directory').chmod(0o755)")
        # Implicit parents reopen only as needed, then recover receiver modes.
        for extra in [[], ["--only-existing"], ["--preserve=permissions"]]:
            readonly = root + "/readonly-" + str(len(extra)) + ("-p" if "--preserve=permissions" in extra else "")
            ssh("destination", f"from pathlib import Path; p=Path({readonly!r}); (p/'parent').mkdir(parents=True); (p/'parent'/'item').write_bytes(b'old'); (p/'parent').chmod(0o2550)")
            run(prefix + ["--mapping", "-", "--to", "destination", "--into", readonly, "--no-tcp"] + extra,
                data=manifest([("file", "parent/item", "file")]))
            ssh("destination", f"from pathlib import Path; p=Path({readonly!r})/'parent'; assert (p/'item').read_bytes()==b'mapped contents'; assert p.stat().st_mode & 0o7777 == 0o2550; p.chmod(0o755)")
        # An untouched writable parent needs no chmod (ctime must stay intact).
        stable = root + "/writable-parent"
        before = ssh("destination", f"from pathlib import Path; p=Path({stable!r})/'parent'; p.mkdir(parents=True); (p/'item').write_bytes(b'mapped contents'); __import__('os').utime(p/'item',(1600000000,1600000000)); print(p.stat().st_ctime_ns)").stdout.strip()
        run(prefix + ["--mapping", "-", "--to", "destination", "--into", stable, "--no-tcp"], data=manifest([("file", "parent/item", "file")]))
        after = ssh("destination", f"from pathlib import Path; print((Path({stable!r})/'parent').stat().st_ctime_ns)").stdout.strip()
        assert before == after, (before, after)
        # A protected implicit parent blocks only its mapped descendants.
        blocked = root + "/blocked"
        ssh("destination", f"from pathlib import Path; p=Path({blocked!r}); p.mkdir(); (p/'blocked-file').write_bytes(b'keep file'); (p/'protected').mkdir(); (p/'protected'/'sentinel').write_bytes(b'keep target'); (p/'blocked-link').symlink_to('protected')")
        blocked_entries = [("file", "blocked-file/deep/item", "file"), ("file", "blocked-link/item", "file"), ("directory", "blocked-file/directory", "dir")]
        selected = manifest(blocked_entries + [("file", "good/item", "file")])
        preview = run(prefix + ["--mapping", "-", "--to", "destination", "--into", blocked, "--no-tcp", "--dry-run"], data=selected, expected=23)
        assert preview.stderr.count(b"blocks an implicit mapping parent") == len(blocked_entries), preview.stderr
        ssh("destination", f"from pathlib import Path; assert not (Path({blocked!r})/'good').exists()")
        results_path = Path(temporary) / "results-blocked.ndjson"
        result = run(prefix + ["--mapping", "-", "--to", "destination", "--into", blocked, "--no-tcp", "--results", str(results_path)], data=selected, expected=23)
        assert result.stderr.count(b"blocks an implicit mapping parent") == len(blocked_entries), result.stderr
        records = [json.loads(line) for line in results_path.read_text().splitlines()]
        # Remote-to-remote results attest receiver operations; planner failures
        # are diagnostics and still make the terminal outcome partial.
        assert records[-1]["status"] == "partial", records[-1]
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
        result = run(prefix + ["--mapping", "-", "--to", "destination", "--into", root + "/large", "--no-tcp", "--preserve=permissions", "--results", str(results_path)], data=large, expected=23)
        assert result.stderr.count(b"blocks an implicit mapping parent") == 2, result.stderr
        records = [json.loads(line) for line in results_path.read_text().splitlines()]
        assert records[-1]["status"] == "partial", records[-1]
        ssh("destination", f"from pathlib import Path; assert Path({root + '/large/blocked'!r}).read_bytes()==b'keep implicit parent'")
        assert b"cannot replace non-directory" in result.stderr, result.stderr
        ssh("destination", f"from pathlib import Path; p=Path({root + '/large/group'!r}); assert p.read_bytes()==b'keep explicit parent'; p.unlink()")
        # Once the fixture obstruction is removed, the late explicit entry
        # supplies directory metadata after all 10,000 mapped files are copied.
        result = run(prefix + ["--mapping", "-", "--to", "destination", "--into", root + "/large", "--no-tcp", "--preserve=permissions", "--results", str(results_path)], data=large, expected=23)
        assert result.stderr.count(b"blocks an implicit mapping parent") == 2, result.stderr
        assert b"cannot replace non-directory" not in result.stderr, result.stderr
        records = [json.loads(line) for line in results_path.read_text().splitlines()]
        assert records[-1]["status"] == "partial", records[-1]
        ssh("destination", f"from pathlib import Path; p=Path({root + '/large/group'!r}); files=list(p.iterdir()); assert len(files)==10000; assert all(f.read_bytes()==b'mapped contents' for f in files); assert p.stat().st_mode & 0o777 == 0o750; assert p.stat().st_mtime_ns == 1500000000000000000")
    print("Restricted mapping and timestamp selection passed", flush=True)


def named():
    source = "/tmp/syq-real-ssh/return-source"
    contents = manifest([("message.txt", "nested/renamed", "file")])
    prefix = ["syq", "cp", "--no-progress", "-C", source, "--mapping", "-", "--to", "@laptop", "--into", "mapped-return"]
    run(prefix, data=contents)
    run(prefix + ["--verify-only"], data=contents)
    run(prefix + ["--skip-newer", "--only-existing"], data=contents)
    # Here the source-side caller receives coordinator operation records, so
    # a parent obstruction must produce a retryable per-entry failure too.
    blocked = manifest([("message.txt", "nested/renamed/child", "file"), ("message.txt", "nested/good", "file")])
    with tempfile.TemporaryDirectory(prefix="syq-named-mapping-") as temporary:
        results_path = Path(temporary) / "results.ndjson"
        run(prefix + ["--results", str(results_path)], data=blocked, expected=23)
        records = [json.loads(line) for line in results_path.read_text().splitlines()]
        failed = [r for r in records if r.get("disposition") == "failed"]
        assert [(r["src"]["value"], r["dst"]["value"]) for r in failed] == [("message.txt", "nested/renamed/child")], failed
        assert records[-1]["status"] == "partial", records[-1]
    run(prefix + ["--verify-only"], data=contents + manifest([("message.txt", "nested/good", "file")]))
    print("Named mapping and timestamp selection passed", flush=True)


if __name__ == "__main__":
    (named if sys.argv[1:] == ["named"] else direct)()
