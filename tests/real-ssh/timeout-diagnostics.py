"""Show what the lab was doing when a real-SSH case's command times out.

Python imports this at startup through a .pth file in the lab image. In the
runner container it wraps subprocess.run: shortly before a command's timeout
expires, while the command is still running, it prints the process table of
all three containers. subprocess.run then kills the command as usual.
"""
import socket
import subprocess
import sys
import threading
import time

PROCESSES = ["ps", "-eo", "pid,ppid,stat,etimes,wchan:32,args"]
# The real ssh client with the lab key only: the tracing wrapper, the case's
# SSH configuration and its agents may be part of what is stuck.
LAB_SSH = [
    "/usr/bin/ssh", "-F", "/dev/null", "-i", "/home/syq/.ssh/id_ed25519",
    "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=3",
]
HOSTS = ("runner", "source", "destination")
_run = subprocess.run


def _processes(host):
    command = PROCESSES if host == "runner" else [*LAB_SSH, f"syq@{host}", *PROCESSES]
    try:
        return _run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, timeout=8).stdout
    except Exception as error:
        return f"{error}\n"


def _dump(command, timeout):
    tables = {}
    threads = [threading.Thread(target=lambda host=host: tables.__setitem__(host, _processes(host)))
               for host in HOSTS]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    lines = [f"real-SSH diagnostics at {time.strftime('%H:%M:%S')}: still running near its "
             f"{timeout}s timeout: {command!r}"]
    for host in HOSTS:
        lines += [f"--- processes on {host} ---", tables.get(host, "no answer\n").rstrip("\n")]
    print("\n".join(lines), file=sys.stderr, flush=True)


def _run_with_diagnostics(*args, timeout=None, **kwargs):
    if timeout is None or timeout < 2:
        return _run(*args, timeout=timeout, **kwargs)
    command = args[0] if args else kwargs.get("args")
    timer = threading.Timer(timeout - min(5, timeout / 10), _dump, (command, timeout))
    timer.daemon = True
    timer.start()
    try:
        return _run(*args, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired:
        # Let a dump that has started finish before the case reports and exits.
        timer.join(15)
        raise
    finally:
        timer.cancel()


if socket.gethostname() == "runner":
    subprocess.run = _run_with_diagnostics
