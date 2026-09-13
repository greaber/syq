#!/usr/bin/env python3
"""Privileged-copy checks confined to the disposable OpenSSH runner container."""
import ctypes
import os
from pathlib import Path
import signal
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


def main():
    assert os.geteuid() == 0, "run this check as root only inside the disposable lab"
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER, Linux lab only
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    with tempfile.TemporaryDirectory(prefix="syq-root-security-") as temporary:
        root = Path(temporary)
        for interface in ["native", "native-owner", "rsync"]:
            source = root / f"source-{interface}"
            destination = root / f"destination-{interface}"
            source.write_bytes(b"payload\0" * (1 << 20))
            os.chown(source, 1000, 1000)
            if interface == "rsync":
                args = ["syq", "rsync", "-a", "--syq-connections", "1", "--bwlimit", "1G", str(source), str(destination)]
            else:
                args = ["syq", "cp", "--connections", "1", "--tuning-options", "copy-path=ranges", str(source), "--as", str(destination)]
                if interface == "native-owner":
                    args.extend(["--preserve", "ownership,permissions"])
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
