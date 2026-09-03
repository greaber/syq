"""Synchronous process and native-command clients for syq."""

from __future__ import annotations

import json
import os
import selectors
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .bootstrap import managed_executable
from .errors import (
    SyqInvocationError,
    SyqOperationError,
    SyqOutputError,
    SyqProcessError,
    SyqProtocolError,
)
from .models import (
    AutomationEvent,
    CpResult,
    IgnoreFrom,
    MappingEntry,
    OperationStatus,
    OperationSummary,
    _mapping_json,
)
from .protocol import AutomationDecoder, parse_mapping_line


PathArgument = str | bytes | os.PathLike[str] | os.PathLike[bytes]
Argument = str | bytes
Selector = PathArgument | Iterable[PathArgument]
IgnoreSelector = str | IgnoreFrom | Iterable[str | IgnoreFrom]
_MAX_STREAM_LINE_BYTES = 16 * 1024 * 1024
_MAX_STDERR_BYTES = 8 * 1024


@dataclass(frozen=True, slots=True)
class Result:
    """The complete result of one raw syq process."""

    argv: tuple[Argument, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


def _text_arg(value: str | os.PathLike[str], *, label: str) -> str:
    result = os.fspath(value)
    if not isinstance(result, str):
        raise TypeError(f"{label} must resolve to text, not bytes")
    return result


def _argument(value: PathArgument, *, label: str) -> Argument:
    result = os.fspath(value)
    if not isinstance(result, (str, bytes)):
        raise TypeError(f"{label} must resolve to str or bytes")
    if isinstance(result, bytes) and os.name != "posix":
        raise TypeError(f"{label} may resolve to bytes only on POSIX")
    contains_nul = b"\0" in result if isinstance(result, bytes) else "\0" in result
    if contains_nul:
        raise ValueError(f"{label} may not contain NUL")
    return result


def run(
    args: Sequence[PathArgument],
    *,
    executable: str | os.PathLike[str] | None = None,
    check: bool = True,
    cwd: PathArgument | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    input: bytes | None = None,
) -> Result:
    """Run syq without a shell and capture its complete byte output."""

    if isinstance(args, (str, bytes, os.PathLike)):
        raise TypeError("args must be a sequence of individual arguments")
    executable_text = (
        os.fspath(managed_executable())
        if executable is None
        else _text_arg(executable, label="executable")
    )
    argument_values = tuple(
        _argument(argument, label=f"args[{index}]")
        for index, argument in enumerate(args)
    )
    argv: tuple[Argument, ...] = (executable_text, *argument_values)
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(input=input, timeout=timeout)
    except BaseException:
        _kill_process_group(process)
        process.communicate()
        raise
    result = Result(
        argv=argv,
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
    )
    if check and result.returncode != 0:
        raise SyqProcessError(result)
    return result


def version(*, executable: str | os.PathLike[str] | None = None) -> str:
    """Return the version of the pinned or explicitly overridden executable."""

    result = run(["--version"], executable=executable)
    try:
        output = result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise SyqOutputError("syq --version did not return UTF-8") from error
    prefix = "syq "
    if not output.startswith(prefix) or len(output) == len(prefix):
        raise SyqOutputError(f"unexpected syq --version output: {output!r}")
    return output[len(prefix) :]


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _remaining(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    return max(0.0, deadline - time.monotonic())


class _LineProcess:
    """An owned process whose stdout is consumed as bounded NDJSON lines."""

    def __init__(
        self,
        argv: tuple[Argument, ...],
        *,
        cwd: PathArgument | None,
        env: Mapping[str, str] | None,
        timeout: float | None,
        results_pipe: bool = False,
    ) -> None:
        self.timeout = timeout
        self._deadline = None if timeout is None else time.monotonic() + timeout
        read_fd: int | None = None
        pass_fds: tuple[int, ...] = ()
        stdout = subprocess.PIPE
        if results_pipe:
            # The stream rides a descriptor this process opens and the
            # child inherits (--results-fd); the child's human stdout is
            # discarded so an unread pipe can never stall it.
            read_fd, write_fd = os.pipe()
            argv = (*argv, f"--results-fd={write_fd}")
            pass_fds = (write_fd,)
            stdout = subprocess.DEVNULL
        self.argv = argv
        try:
            self._process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
                pass_fds=pass_fds,
            )
        finally:
            if results_pipe:
                os.close(write_fd)
                if not hasattr(self, "_process"):
                    os.close(read_fd)
        assert self._process.stderr is not None
        if read_fd is not None:
            self._stdout = os.fdopen(read_fd, "rb", buffering=0)
        else:
            assert self._process.stdout is not None
            self._stdout = self._process.stdout
        self._stderr = self._process.stderr
        self._stderr_tail = bytearray()
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr,
            name="syq-stderr-drain",
            daemon=True,
        )
        self._stderr_thread.start()
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._stdout, selectors.EVENT_READ)
        self._buffer = bytearray()
        self._eof = False
        self.returncode: int | None = None
        self.stderr = b""
        self._closed = False

    def next_line(self) -> bytes | None:
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                if newline > _MAX_STREAM_LINE_BYTES:
                    raise SyqProtocolError(
                        "syq emitted a machine-output line larger than 16 MiB"
                    )
                line = bytes(self._buffer[:newline])
                del self._buffer[: newline + 1]
                return line
            if self._eof:
                if self._buffer:
                    if len(self._buffer) > _MAX_STREAM_LINE_BYTES:
                        raise SyqProtocolError(
                            "syq emitted a machine-output line larger than 16 MiB"
                        )
                    line = bytes(self._buffer)
                    self._buffer.clear()
                    return line
                return None
            wait = _remaining(self._deadline)
            if wait == 0 or not self._selector.select(wait):
                raise subprocess.TimeoutExpired(self.argv, self.timeout)
            chunk = os.read(self._stdout.fileno(), 64 * 1024)
            if chunk:
                self._buffer.extend(chunk)
                if (
                    len(self._buffer) > _MAX_STREAM_LINE_BYTES
                    and b"\n" not in self._buffer
                ):
                    raise SyqProtocolError(
                        "syq emitted a machine-output line larger than 16 MiB"
                    )
            else:
                self._eof = True

    def finish(self) -> int:
        if self.returncode is not None:
            return self.returncode
        try:
            self.returncode = self._process.wait(timeout=_remaining(self._deadline))
        except subprocess.TimeoutExpired:
            raise subprocess.TimeoutExpired(self.argv, self.timeout) from None
        self._capture_stderr()
        self._close_files()
        return self.returncode

    def abort(self) -> None:
        if self._closed:
            return
        # Kill the owned group even if the leader just exited: a malformed
        # producer or callback failure must not leave an SSH/helper descendant.
        _kill_process_group(self._process)
        self.returncode = self._process.wait()
        self._capture_stderr()
        self._close_files()

    def _capture_stderr(self) -> None:
        self._stderr_thread.join()
        self.stderr = bytes(self._stderr_tail)

    def _drain_stderr(self) -> None:
        while True:
            chunk = self._stderr.read(64 * 1024)
            if not chunk:
                return
            if len(chunk) >= _MAX_STDERR_BYTES:
                self._stderr_tail[:] = chunk[-_MAX_STDERR_BYTES:]
                continue
            excess = len(self._stderr_tail) + len(chunk) - _MAX_STDERR_BYTES
            if excess > 0:
                del self._stderr_tail[:excess]
            self._stderr_tail.extend(chunk)

    def _close_files(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._selector.close()
        self._stdout.close()
        self._stderr.close()


def _values(value: Selector | None, *, label: str) -> tuple[Argument, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes, os.PathLike)):
        return (_argument(value, label=label),)
    try:
        return tuple(
            _argument(item, label=f"{label}[{index}]")
            for index, item in enumerate(value)
        )
    except TypeError as error:
        raise TypeError(f"{label} must be a path or iterable of paths") from error


def _append_paths(
    argv: list[Argument], option: str, value: Selector | None
) -> int:
    values = _values(value, label=option)
    for item in values:
        argv.extend((option, item))
    return len(values)


def _append_text(argv: list[Argument], option: str, value: object | None) -> None:
    if value is not None:
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            raise SyqInvocationError(f"{option} must be text or an integer")
        argv.extend((option, str(value)))


def _append_remote_arguments(
    argv: list[Argument],
    *,
    coordinate_at: str | None,
    rsh: str | None,
    syq_path: str | os.PathLike[str] | None,
    no_bootstrap: bool,
    tcp_plain: bool,
    no_tcp: bool,
    tcp_ports: str | None,
    tcp_congestion: str | None,
    no_forward_agent: bool,
    unrestricted_agent_forwarding: bool,
    agent_broker_only: bool,
) -> None:
    if coordinate_at is not None:
        if coordinate_at not in {"auto", "local", "src", "dest"}:
            raise SyqInvocationError(
                "--coordinate-at must be auto, local, src, or dest"
            )
        if coordinate_at in {"src", "dest"}:
            # The results stream this library relies on is written by the
            # transfer coordinator, which these placements move to a remote
            # host; syq refuses the combination at argument parsing.
            raise SyqInvocationError(
                "the results stream needs a local transfer coordinator; "
                "use coordinate_at='local' (or run() for a raw invocation)"
            )
        argv.extend(("--coordinate-at", coordinate_at))
    if rsh is not None:
        argv.extend(("--rsh", _text_arg(rsh, label="rsh")))
    if syq_path is not None:
        argv.extend(("--syq-path", _text_arg(syq_path, label="syq_path")))
    for enabled, option in (
        (no_bootstrap, "--no-bootstrap"),
        (tcp_plain, "--tcp-plain"),
        (no_tcp, "--no-tcp"),
    ):
        if enabled:
            argv.append(option)
    if tcp_ports is not None:
        argv.extend(("--tcp-ports", _text_arg(tcp_ports, label="tcp_ports")))
    if tcp_congestion is not None:
        argv.extend(
            (
                "--tcp-congestion",
                _text_arg(tcp_congestion, label="tcp_congestion"),
            )
        )
    for enabled, option in (
        (no_forward_agent, "--no-forward-agent"),
        (unrestricted_agent_forwarding, "--unrestricted-agent-forwarding"),
        (agent_broker_only, "--agent-broker-only"),
    ):
        if enabled:
            argv.append(option)


def _nonnegative_integer(value: int | None, *, option: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SyqInvocationError(f"{option} must be a non-negative integer")
    return value


def _positive_integer(value: int | None, *, option: str) -> int | None:
    value = _nonnegative_integer(value, option=option)
    if value == 0:
        raise SyqInvocationError(f"{option} must be positive")
    return value


def _copy_arguments(
    command: str,
    sources: tuple[PathArgument, ...],
    *,
    src: Selector | None,
    src_src: Selector | None,
    src_file: Selector | None,
    src_dir: Selector | None,
    from_: str | None,
    cwd: PathArgument | None,
    follow: bool,
    follow_src: bool,
    follow_dest: bool,
    to: str | None,
    into: PathArgument | None,
    into_new: PathArgument | None,
    into_existing: PathArgument | None,
    as_: PathArgument | None,
    as_new: PathArgument | None,
    as_existing: PathArgument | None,
    prune: bool,
    dry_run: bool,
    hash: bool,
    no_compress: bool,
    bwlimit: str | int | None,
    connections: int | None,
    max_entries: int | None,
    max_total_bytes: str | int | None,
    max_runtime: str | int | None,
    ignore: IgnoreSelector | None,
    ignore_from: Selector | None,
    preserve: str | Iterable[str] | None,
    inplace: bool,
    max_size: str | int | None,
    min_size: str | int | None,
    max_delete: int | None,
) -> tuple[list[Argument], int]:
    argv: list[Argument] = [command]
    source_count = 0
    contents_count = 0
    for index, source in enumerate(sources):
        argv.append(_argument(source, label=f"sources[{index}]"))
        source_count += 1
    for option, value in (
        ("--src", src),
        ("--src-src", src_src),
        ("--src-file", src_file),
        ("--src-dir", src_dir),
    ):
        appended = _append_paths(argv, option, value)
        source_count += appended
        if option == "--src-src":
            contents_count += appended
    if from_ is not None:
        argv.extend(("--from", _text_arg(from_, label="from_")))
    if cwd is not None:
        argv.extend(("--cwd", _argument(cwd, label="cwd")))
    if follow:
        argv.append("--follow")
    if follow_src:
        argv.append("--follow-src")
    if follow_dest:
        argv.append("--follow-dest")
    if to is not None:
        argv.extend(("--to", _text_arg(to, label="to")))
    placements = [
        ("--into", into),
        ("--into-new", into_new),
        ("--into-existing", into_existing),
        ("--as", as_),
        ("--as-new", as_new),
        ("--as-existing", as_existing),
    ]
    selected_placements = [
        (name, value) for name, value in placements if value is not None
    ]
    if command != "map" and len(selected_placements) != 1:
        raise SyqInvocationError(
            "exactly one of --into, --into-new, --into-existing, --as, "
            "--as-new, or --as-existing is required"
        )
    if command == "map" and len(selected_placements) > 1:
        raise SyqInvocationError("mapping placement options conflict")
    for option, value in selected_placements:
        assert value is not None
        argv.extend((option, _argument(value, label=option)))
        if option.startswith("--as") and source_count and (
            source_count != 1 or contents_count
        ):
            raise SyqInvocationError(
                "--as, --as-new, and --as-existing require exactly one "
                "ordinary source object"
            )
    if prune:
        argv.append("--prune")
    if dry_run:
        argv.append("--dry-run")
    if hash:
        argv.append("--hash")
    if no_compress:
        argv.append("--no-compress")
    _append_text(argv, "--bwlimit", bwlimit)
    connections = _positive_integer(connections, option="--connections")
    if connections is not None:
        argv.extend(("--connections", str(connections)))
    max_entries = _nonnegative_integer(max_entries, option="--max-entries")
    if max_entries is not None:
        argv.extend(("--max-entries", str(max_entries)))
    _append_text(argv, "--max-total-bytes", max_total_bytes)
    _append_text(argv, "--max-runtime", max_runtime)
    if ignore is not None:
        rules = (ignore,) if isinstance(ignore, (str, IgnoreFrom)) else tuple(ignore)
        for rule in rules:
            if isinstance(rule, IgnoreFrom):
                argv.extend(
                    ("--ignore-from", _argument(rule.path, label="--ignore-from"))
                )
            elif isinstance(rule, str):
                argv.extend(("--ignore", rule))
            else:
                raise SyqInvocationError(
                    "--ignore entries must be text or syq.IgnoreFrom"
                )
    _append_paths(argv, "--ignore-from", ignore_from)
    if preserve is not None:
        attributes = (preserve,) if isinstance(preserve, str) else tuple(preserve)
        for attribute in attributes:
            if attribute not in {"permissions", "ownership", "specials"}:
                raise SyqInvocationError(
                    "--preserve must contain permissions, ownership, or specials"
                )
            argv.extend(("--preserve", attribute))
    if inplace:
        argv.append("--inplace")
    _append_text(argv, "--max-size", max_size)
    _append_text(argv, "--min-size", min_size)
    max_delete = _nonnegative_integer(max_delete, option="--max-delete")
    if max_delete is not None:
        if not prune:
            raise SyqInvocationError("--max-delete requires --prune")
        argv.extend(("--max-delete", str(max_delete)))
    return argv, source_count


def _mapping_line(entry: MappingEntry, *, index: int) -> bytes:
    if not isinstance(entry, MappingEntry):
        raise TypeError(f"mapping[{index}] must be a MappingEntry")
    return (
        json.dumps(
            _mapping_json(entry),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _write_mapping_manifest(
    manifest: BinaryIO, mapping: Iterable[MappingEntry]
) -> None:
    for index, entry in enumerate(mapping):
        manifest.write(_mapping_line(entry, index=index))
    manifest.flush()


class MapStream(Iterable[MappingEntry]):
    """A context-managed, streaming ``syq map`` result."""

    def __init__(self, process: _LineProcess, cwd: PathArgument) -> None:
        self._process = process
        self.cwd = cwd
        self._complete = False

    def __iter__(self) -> MapStream:
        return self

    def __next__(self) -> MappingEntry:
        if self._complete:
            raise StopIteration
        try:
            line = self._process.next_line()
            if line is None:
                returncode = self._process.finish()
                self._complete = True
                if returncode != 0:
                    raise SyqProtocolError(
                        f"syq map exited with status {returncode}",
                        returncode=returncode,
                        stderr=self._process.stderr,
                    )
                raise StopIteration
            return parse_mapping_line(line)
        except StopIteration:
            raise
        except BaseException as error:
            self._process.abort()
            self._complete = True
            if isinstance(error, SyqProtocolError):
                error.returncode = self._process.returncode
                error.stderr = self._process.stderr
            raise

    def close(self) -> None:
        if not self._complete:
            self._process.abort()
            self._complete = True

    def __enter__(self) -> MapStream:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class Client:
    """A configured synchronous client for syq's native command surface."""

    def __init__(
        self,
        *,
        executable: str | os.PathLike[str] | None = None,
        cache_dir: str | os.PathLike[str] | None = None,
        process_cwd: PathArgument | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> None:
        self._executable = (
            None if executable is None else _text_arg(executable, label="executable")
        )
        self._cache_dir = cache_dir
        self.process_cwd = process_cwd
        self.env = env
        self.timeout = timeout

    def _executable_value(self) -> str:
        if self._executable is not None:
            return self._executable
        if self._cache_dir is None:
            return os.fspath(managed_executable())
        return os.fspath(managed_executable(cache_dir=self._cache_dir))

    def run(
        self,
        args: Sequence[PathArgument],
        *,
        check: bool = True,
        cwd: PathArgument | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
        input: bytes | None = None,
    ) -> Result:
        return run(
            args,
            executable=self._executable_value(),
            check=check,
            cwd=self.process_cwd if cwd is None else cwd,
            env=self.env if env is None else env,
            timeout=self.timeout if timeout is None else timeout,
            input=input,
        )

    def _typed(
        self,
        argv: list[Argument],
        *,
        prune: bool,
        mapping: bool,
        dry_run: bool,
        on_event: Callable[[AutomationEvent], object] | None,
        timeout: float | None,
        check: bool,
    ) -> OperationSummary:
        command = (self._executable_value(), *argv)
        process = _LineProcess(
            command,
            cwd=self.process_cwd,
            env=self.env,
            timeout=self.timeout if timeout is None else timeout,
            results_pipe=True,
        )
        decoder = AutomationDecoder(
            prune=prune,
            mapping=mapping,
            dry_run=dry_run,
        )
        try:
            while True:
                line = process.next_line()
                if line is None:
                    break
                event = decoder.feed(line)
                if event is not None and on_event is not None:
                    on_event(event)
            returncode = process.finish()
            result = decoder.finish(returncode)
        except BaseException as error:
            process.abort()
            if isinstance(error, SyqProtocolError):
                error.returncode = process.returncode
                error.stderr = process.stderr
            raise
        if check and result.status is not OperationStatus.SUCCESS:
            raise SyqOperationError(result, stderr=process.stderr)
        return result

    def cp(
        self,
        *sources: PathArgument,
        src: Selector | None = None,
        src_src: Selector | None = None,
        src_file: Selector | None = None,
        src_dir: Selector | None = None,
        from_: str | None = None,
        cwd: PathArgument | None = None,
        follow: bool = False,
        follow_src: bool = False,
        follow_dest: bool = False,
        to: str | None = None,
        into: PathArgument | None = None,
        into_new: PathArgument | None = None,
        into_existing: PathArgument | None = None,
        as_: PathArgument | None = None,
        as_new: PathArgument | None = None,
        as_existing: PathArgument | None = None,
        mapping: PathArgument | Iterable[MappingEntry] | None = None,
        prune: bool = False,
        dry_run: bool = False,
        hash: bool = False,
        no_compress: bool = False,
        bwlimit: str | int | None = None,
        connections: int | None = None,
        coordinate_at: str | None = None,
        rsh: str | None = None,
        syq_path: str | os.PathLike[str] | None = None,
        no_bootstrap: bool = False,
        tcp_plain: bool = False,
        no_tcp: bool = False,
        tcp_ports: str | None = None,
        tcp_congestion: str | None = None,
        no_forward_agent: bool = False,
        unrestricted_agent_forwarding: bool = False,
        agent_broker_only: bool = False,
        max_entries: int | None = None,
        max_total_bytes: str | int | None = None,
        max_runtime: str | int | None = None,
        ignore: IgnoreSelector | None = None,
        ignore_from: Selector | None = None,
        preserve: str | Iterable[str] | None = None,
        inplace: bool = False,
        max_size: str | int | None = None,
        min_size: str | int | None = None,
        max_delete: int | None = None,
        on_event: Callable[[AutomationEvent], object] | None = None,
        timeout: float | None = None,
        check: bool = True,
    ) -> CpResult:
        if from_ is not None and to is not None and coordinate_at != "local":
            # A remote-to-remote copy places the coordinator — and the
            # results stream this surface relies on — on a remote host.
            # The local relay topology is never chosen implicitly: routing
            # the transfer through this machine is the operator's call.
            raise SyqInvocationError(
                "a remote-to-remote copy cannot write the local results "
                "stream; pass coordinate_at='local' explicitly to route the "
                "transfer through this machine, or use run() for a raw "
                "invocation"
            )
        argv, source_count = _copy_arguments(
            "cp",
            sources,
            src=src,
            src_src=src_src,
            src_file=src_file,
            src_dir=src_dir,
            from_=from_,
            cwd=cwd,
            follow=follow,
            follow_src=follow_src,
            follow_dest=follow_dest,
            to=to,
            into=into,
            into_new=into_new,
            into_existing=into_existing,
            as_=as_,
            as_new=as_new,
            as_existing=as_existing,
            prune=prune,
            dry_run=dry_run,
            hash=hash,
            no_compress=no_compress,
            bwlimit=bwlimit,
            connections=connections,
            max_entries=max_entries,
            max_total_bytes=max_total_bytes,
            max_runtime=max_runtime,
            ignore=ignore,
            ignore_from=ignore_from,
            preserve=preserve,
            inplace=inplace,
            max_size=max_size,
            min_size=min_size,
            max_delete=max_delete,
        )
        _append_remote_arguments(
            argv,
            coordinate_at=coordinate_at,
            rsh=rsh,
            syq_path=syq_path,
            no_bootstrap=no_bootstrap,
            tcp_plain=tcp_plain,
            no_tcp=no_tcp,
            tcp_ports=tcp_ports,
            tcp_congestion=tcp_congestion,
            no_forward_agent=no_forward_agent,
            unrestricted_agent_forwarding=unrestricted_agent_forwarding,
            agent_broker_only=agent_broker_only,
        )
        if mapping is not None and prune:
            raise SyqInvocationError("--mapping conflicts with --prune")
        if mapping is None:
            if source_count == 0:
                raise SyqInvocationError("syq cp needs a source selector or mapping")
            return self._typed(
                argv,
                prune=prune,
                mapping=False,
                dry_run=dry_run,
                on_event=on_event,
                timeout=timeout,
                check=check,
            )
        if source_count:
            raise SyqInvocationError("--mapping replaces source selectors")
        if any(value is not None for value in (as_, as_new, as_existing)):
            raise SyqInvocationError("--mapping conflicts with --as")
        if isinstance(mapping, (str, bytes, os.PathLike)):
            argv.extend(("--mapping", _argument(mapping, label="mapping")))
            return self._typed(
                argv,
                prune=False,
                mapping=True,
                dry_run=dry_run,
                on_event=on_event,
                timeout=timeout,
                check=check,
            )
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix="syq-python-mapping-", suffix=".ndjson"
        ) as manifest:
            _write_mapping_manifest(manifest, mapping)
            argv.extend(("--mapping", os.path.realpath(manifest.name)))
            return self._typed(
                argv,
                prune=False,
                mapping=True,
                dry_run=dry_run,
                on_event=on_event,
                timeout=timeout,
                check=check,
            )

    def map(
        self,
        *sources: PathArgument,
        src: Selector | None = None,
        src_src: Selector | None = None,
        src_file: Selector | None = None,
        src_dir: Selector | None = None,
        cwd: PathArgument | None = None,
        follow: bool = False,
        follow_src: bool = False,
        as_: PathArgument | None = None,
        timeout: float | None = None,
    ) -> MapStream:
        # Materialize selectors once so generators are not consumed separately
        # while deriving the source base carried by MapStream.cwd.
        src_values = _values(src, label="--src")
        src_src_values = _values(src_src, label="--src-src")
        src_file_values = _values(src_file, label="--src-file")
        src_dir_values = _values(src_dir, label="--src-dir")
        argv, source_count = _copy_arguments(
            "map",
            sources,
            src=src_values,
            src_src=src_src_values,
            src_file=src_file_values,
            src_dir=src_dir_values,
            from_=None,
            cwd=cwd,
            follow=follow,
            follow_src=follow_src,
            follow_dest=False,
            to=None,
            into=None,
            into_new=None,
            into_existing=None,
            as_=as_,
            as_new=None,
            as_existing=None,
            prune=False,
            dry_run=False,
            hash=False,
            no_compress=False,
            bwlimit=None,
            connections=None,
            max_entries=None,
            max_total_bytes=None,
            max_runtime=None,
            ignore=None,
            ignore_from=None,
            preserve=None,
            inplace=False,
            max_size=None,
            min_size=None,
            max_delete=None,
        )
        if source_count == 0:
            raise SyqInvocationError("syq map needs a source selector")
        command = (self._executable_value(), *argv)
        process_base = Path(
            os.fsdecode(
                os.fspath(self.process_cwd)
                if self.process_cwd is not None
                else os.getcwd()
            )
        )
        native_base = Path(os.fsdecode(os.fspath(cwd))) if cwd is not None else Path()
        effective_cwd = (process_base / native_base).resolve()
        if src_src_values:
            if len(src_src_values) != 1 or source_count != 1:
                raise SyqInvocationError(
                    "syq map takes --src-src as its only selector"
                )
            effective_cwd /= os.fsdecode(src_src_values[0])
        return MapStream(
            _LineProcess(
                command,
                cwd=self.process_cwd,
                env=self.env,
                timeout=self.timeout if timeout is None else timeout,
            ),
            effective_cwd,
        )
