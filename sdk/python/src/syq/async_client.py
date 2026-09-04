"""Asyncio process and native-command clients for syq."""

from __future__ import annotations

import asyncio
import inspect
import os
import signal
import tempfile
import threading
from collections.abc import (
    AsyncIterable,
    AsyncIterator,
    Awaitable,
    Callable,
    Iterable,
    Mapping,
    Sequence,
)
from pathlib import Path
from typing import BinaryIO, TypeVar

from .bootstrap import managed_executable
from .client import (
    Argument,
    IgnoreSelector,
    PathArgument,
    Result,
    Selector,
    _append_remote_arguments,
    _argument,
    _copy_arguments,
    _insert_mapping_option,
    _map_stream_cwd,
    _mapping_line,
    _prepare_results_file,
    _rm_arguments,
    _results_pipe,
    _ResultsFileWriter,
    _text_arg,
    _values,
    _version_from_result,
)
from .errors import (
    SyqInvocationError,
    SyqOperationError,
    SyqProcessError,
    SyqProtocolError,
)
from .models import (
    AutomationEvent,
    CpResult,
    MappingEntry,
    OperationStatus,
    OperationSummary,
    RmResult,
)
from .protocol import AutomationDecoder, parse_mapping_line


AsyncEventCallback = Callable[[AutomationEvent], object | Awaitable[object]]
_T = TypeVar("_T")
_LINE_LIMIT = 16 * 1024 * 1024
_STDERR_LIMIT = 8 * 1024


def _kill_process_group(process: asyncio.subprocess.Process) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


async def _complete_task(
    task: asyncio.Task[_T], *, on_cancel: Callable[[], None] | None = None
) -> _T:
    """Let owned cleanup finish, then propagate any intervening cancellation."""

    cancellation: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as error:
            if cancellation is None and on_cancel is not None:
                on_cancel()
            cancellation = error
    result = task.result()
    if cancellation is not None:
        raise cancellation
    return result


async def _wait_for_exit(process: asyncio.subprocess.Process) -> int:
    return await _complete_task(asyncio.create_task(process.wait()))


async def _read_stderr_tail(stderr: asyncio.StreamReader) -> bytes:
    tail = bytearray()
    while True:
        chunk = await stderr.read(64 * 1024)
        if not chunk:
            return bytes(tail)
        if len(chunk) >= _STDERR_LIMIT:
            tail[:] = chunk[-_STDERR_LIMIT:]
            continue
        excess = len(tail) + len(chunk) - _STDERR_LIMIT
        if excess > 0:
            del tail[:excess]
        tail.extend(chunk)


async def _write_async_mapping_manifest(
    manifest: BinaryIO, mapping: AsyncIterable[MappingEntry]
) -> None:
    chunk = bytearray()
    index = 0
    async for entry in mapping:
        chunk.extend(_mapping_line(entry, index=index))
        index += 1
        if len(chunk) >= 256 * 1024:
            write = asyncio.create_task(
                asyncio.to_thread(manifest.write, bytes(chunk))
            )
            await _complete_task(write)
            chunk.clear()
    if chunk:
        write = asyncio.create_task(asyncio.to_thread(manifest.write, bytes(chunk)))
        await _complete_task(write)
    flush = asyncio.create_task(asyncio.to_thread(manifest.flush))
    await _complete_task(flush)


def _write_sync_mapping_manifest(
    manifest: BinaryIO,
    mapping: Iterable[MappingEntry],
    cancelled: threading.Event,
) -> None:
    iterator = iter(mapping)
    index = 0
    while not cancelled.is_set():
        try:
            entry = next(iterator)
        except StopIteration:
            break
        if cancelled.is_set():
            break
        manifest.write(_mapping_line(entry, index=index))
        index += 1
    if not cancelled.is_set():
        manifest.flush()


async def _run(
    args: Sequence[PathArgument],
    *,
    executable: str | os.PathLike[str],
    check: bool,
    cwd: PathArgument | None,
    env: Mapping[str, str] | None,
    timeout: float | None,
    input: bytes | None,
) -> Result:
    if isinstance(args, (str, bytes, os.PathLike)):
        raise TypeError("args must be a sequence of individual arguments")
    executable_text = _text_arg(executable, label="executable")
    argument_values = tuple(
        _argument(argument, label=f"args[{index}]")
        for index, argument in enumerate(args)
    )
    argv: tuple[Argument, ...] = (executable_text, *argument_values)
    spawn = asyncio.create_task(
        asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            env=env,
            stdin=(
                asyncio.subprocess.PIPE
                if input is not None
                else asyncio.subprocess.DEVNULL
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    )
    try:
        process = await _complete_task(spawn)
    except asyncio.CancelledError:
        if spawn.done() and not spawn.cancelled() and spawn.exception() is None:
            process = spawn.result()
            _kill_process_group(process)
            await _wait_for_exit(process)
        raise
    try:
        communication = process.communicate(input)
        if timeout is None:
            stdout, stderr = await communication
        else:
            stdout, stderr = await asyncio.wait_for(communication, timeout)
    except BaseException:
        _kill_process_group(process)
        await _wait_for_exit(process)
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


class _AsyncLineProcess:
    """An owned asyncio process with a bounded machine-output stream."""

    def __init__(
        self,
        argv: tuple[Argument, ...],
        process: asyncio.subprocess.Process,
        timeout: float | None,
        output: asyncio.StreamReader,
        output_transport: asyncio.ReadTransport | None = None,
    ) -> None:
        self.argv = argv
        self.timeout = timeout
        loop = asyncio.get_running_loop()
        self._deadline = None if timeout is None else loop.time() + timeout
        self._process = process
        assert process.stderr is not None
        self._output = output
        self._output_transport = output_transport
        self._stderr_task = asyncio.create_task(
            _read_stderr_tail(process.stderr),
            name="syq-stderr-drain",
        )
        self.returncode: int | None = None
        self.stderr = b""
        self._closed = False
        self._aborted = False

    @classmethod
    async def start(
        cls,
        argv: tuple[Argument, ...],
        *,
        cwd: PathArgument | None,
        env: Mapping[str, str] | None,
        timeout: float | None,
    ) -> _AsyncLineProcess:
        try:
            spawn = asyncio.create_task(
                asyncio.create_subprocess_exec(
                    *argv,
                    cwd=cwd,
                    env=env,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                    limit=_LINE_LIMIT,
                )
            )
            process = await _complete_task(spawn)
        except asyncio.CancelledError:
            if spawn.done() and not spawn.cancelled() and spawn.exception() is None:
                process = spawn.result()
                _kill_process_group(process)
                await _wait_for_exit(process)
            raise
        assert process.stdout is not None
        return cls(argv, process, timeout, process.stdout)

    @classmethod
    async def start_results(
        cls,
        argv: tuple[Argument, ...],
        *,
        cwd: PathArgument | None,
        env: Mapping[str, str] | None,
        timeout: float | None,
    ) -> _AsyncLineProcess:
        read_fd, write_fd = _results_pipe()
        read_pipe = os.fdopen(read_fd, "rb", buffering=0)
        output = asyncio.StreamReader(limit=_LINE_LIMIT)
        protocol = asyncio.StreamReaderProtocol(output)
        transport: asyncio.ReadTransport | None = None
        command = (*argv, f"--results-fd={write_fd}")
        try:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.connect_read_pipe(
                lambda: protocol, read_pipe
            )
            spawn = asyncio.create_task(
                asyncio.create_subprocess_exec(
                    *command,
                    cwd=cwd,
                    env=env,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                    pass_fds=(write_fd,),
                )
            )
            try:
                process = await _complete_task(spawn)
            except asyncio.CancelledError:
                if (
                    spawn.done()
                    and not spawn.cancelled()
                    and spawn.exception() is None
                ):
                    process = spawn.result()
                    _kill_process_group(process)
                    await _wait_for_exit(process)
                raise
        except BaseException:
            if transport is None:
                read_pipe.close()
            else:
                transport.close()
            raise
        finally:
            os.close(write_fd)
        return cls(command, process, timeout, output, transport)

    def _remaining(self) -> float | None:
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - asyncio.get_running_loop().time())

    async def _before_deadline(self, awaitable: Awaitable[_T]) -> _T:
        remaining = self._remaining()
        if remaining is None:
            return await awaitable
        return await asyncio.wait_for(awaitable, remaining)

    async def next_line(self) -> bytes | None:
        try:
            line = await self._before_deadline(self._output.readline())
        except ValueError as error:
            raise SyqProtocolError(
                f"syq output line exceeds the {_LINE_LIMIT}-byte limit"
            ) from error
        if not line:
            return None
        return line[:-1] if line.endswith(b"\n") else line

    async def callback(self, awaitable: Awaitable[object]) -> None:
        await self._before_deadline(awaitable)

    async def finish(self) -> int:
        if self.returncode is not None:
            return self.returncode
        self.returncode = await self._before_deadline(self._process.wait())
        self.stderr = await self._before_deadline(
            asyncio.shield(self._stderr_task)
        )
        self._close_output()
        self._closed = True
        return self.returncode

    async def abort(self) -> None:
        if not self._aborted:
            self._aborted = True
            _kill_process_group(self._process)
        if self.returncode is None:
            self.returncode = await _wait_for_exit(self._process)
        if not self._closed:
            self.stderr = await _complete_task(self._stderr_task)
            self._close_output()
            self._closed = True

    def _close_output(self) -> None:
        if self._output_transport is not None:
            self._output_transport.close()
            self._output_transport = None


class AsyncMapStream(AsyncIterator[MappingEntry]):
    """A lazy, context-managed, streaming ``syq map`` result."""

    def __init__(
        self,
        client: AsyncClient,
        argv: list[Argument],
        cwd: Path,
        timeout: float | None,
    ) -> None:
        self._client = client
        self._argv = argv
        self.cwd = cwd
        self._timeout = timeout
        self._process: _AsyncLineProcess | None = None
        self._start_lock = asyncio.Lock()
        self._complete = False

    async def _ensure_started(self) -> _AsyncLineProcess:
        async with self._start_lock:
            if self._process is None:
                self._process = await self._client._start_line(
                    self._argv, timeout=self._timeout
                )
        return self._process

    def __aiter__(self) -> AsyncMapStream:
        return self

    async def __anext__(self) -> MappingEntry:
        if self._complete:
            raise StopAsyncIteration
        process = await self._ensure_started()
        try:
            line = await process.next_line()
            if line is None:
                returncode = await process.finish()
                self._complete = True
                if returncode != 0:
                    raise SyqProtocolError(
                        f"syq map exited with status {returncode}",
                        returncode=returncode,
                        stderr=process.stderr,
                    )
                raise StopAsyncIteration
            return parse_mapping_line(line)
        except StopAsyncIteration:
            raise
        except BaseException as error:
            await process.abort()
            self._complete = True
            if isinstance(error, SyqProtocolError):
                error.returncode = process.returncode
                error.stderr = process.stderr
            raise

    async def aclose(self) -> None:
        if self._complete:
            return
        if self._process is not None:
            await self._process.abort()
        self._complete = True

    async def __aenter__(self) -> AsyncMapStream:
        await self._ensure_started()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()


class AsyncClient:
    """A configured asyncio client for syq's native command surface."""

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

    async def _executable_value(self) -> str:
        if self._executable is not None:
            return self._executable
        if self._cache_dir is None:
            executable = await asyncio.to_thread(managed_executable)
        else:
            executable = await asyncio.to_thread(
                managed_executable, cache_dir=self._cache_dir
            )
        return os.fspath(executable)

    async def run(
        self,
        args: Sequence[PathArgument],
        *,
        check: bool = True,
        cwd: PathArgument | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
        input: bytes | None = None,
    ) -> Result:
        return await _run(
            args,
            executable=await self._executable_value(),
            check=check,
            cwd=self.process_cwd if cwd is None else cwd,
            env=self.env if env is None else env,
            timeout=self.timeout if timeout is None else timeout,
            input=input,
        )

    async def version(self) -> str:
        """Return the selected syq executable's version."""

        return _version_from_result(await self.run(["--version"]))

    async def _start_line(
        self, argv: list[Argument], *, timeout: float | None
    ) -> _AsyncLineProcess:
        command = (await self._executable_value(), *argv)
        return await _AsyncLineProcess.start(
            command,
            cwd=self.process_cwd,
            env=self.env,
            timeout=self.timeout if timeout is None else timeout,
        )

    async def _start_results(
        self, argv: list[Argument], *, timeout: float | None
    ) -> _AsyncLineProcess:
        command = (await self._executable_value(), *argv)
        return await _AsyncLineProcess.start_results(
            command,
            cwd=self.process_cwd,
            env=self.env,
            timeout=self.timeout if timeout is None else timeout,
        )

    async def _typed(
        self,
        argv: list[Argument],
        *,
        mode: str,
        prune: bool,
        mapping: bool,
        dry_run: bool,
        selectors_total: int | None,
        on_event: AsyncEventCallback | None,
        results: BinaryIO | None,
        timeout: float | None,
        check: bool,
    ) -> OperationSummary:
        process = await self._start_results(argv, timeout=timeout)
        writer = _ResultsFileWriter(results)
        decoder = AutomationDecoder(
            mode=mode,
            prune=prune,
            mapping=mapping,
            dry_run=dry_run,
            selectors_total=selectors_total,
        )
        terminal_line: bytes | None = None
        try:
            while True:
                line = await process.next_line()
                if line is None:
                    break
                event = decoder.feed(line)
                if isinstance(event, OperationSummary):
                    terminal_line = line
                else:
                    if writer.append(line):
                        await _complete_task(
                            asyncio.create_task(asyncio.to_thread(writer.drain))
                        )
                if event is not None and on_event is not None:
                    callback_result = on_event(event)
                    if inspect.isawaitable(callback_result):
                        await process.callback(callback_result)
            returncode = await process.finish()
            result = decoder.finish(returncode)
            assert terminal_line is not None
            writer.append(terminal_line)
            await _complete_task(
                asyncio.create_task(asyncio.to_thread(writer.drain))
            )
            await _complete_task(
                asyncio.create_task(asyncio.to_thread(writer.flush))
            )
        except BaseException as error:
            await process.abort()
            if isinstance(error, SyqProtocolError):
                error.returncode = process.returncode
                error.stderr = process.stderr
            raise
        if check and result.status is not OperationStatus.SUCCESS:
            raise SyqOperationError(result, stderr=process.stderr)
        return result

    async def cp(
        self,
        *sources: PathArgument,
        src: Selector | None = None,
        src_src: Selector | None = None,
        src_file: Selector | None = None,
        src_dir: Selector | None = None,
        from_: str | None = None,
        cwd: PathArgument | None = None,
        root: PathArgument | None = None,
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
        mapping: (
            PathArgument
            | Iterable[MappingEntry]
            | AsyncIterable[MappingEntry]
            | None
        ) = None,
        results: BinaryIO | None = None,
        prune: bool = False,
        dry_run: bool = False,
        hash: bool = False,
        no_compress: bool = False,
        bwlimit: str | int | None = None,
        connections: int | None = None,
        coordinate_at: str | None = None,
        rsh: str | None = None,
        pscope: PathArgument | None = None,
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
        receipt: str | None = None,
        ignore: IgnoreSelector | None = None,
        ignore_from: Selector | None = None,
        preserve: str | Iterable[str] | None = None,
        inplace: bool = False,
        max_size: str | int | None = None,
        min_size: str | int | None = None,
        max_delete: int | None = None,
        on_event: AsyncEventCallback | None = None,
        timeout: float | None = None,
        check: bool = True,
    ) -> CpResult:
        if (
            from_ is not None
            and to is not None
            and dry_run
            and coordinate_at != "local"
        ):
            # Mirrors the CLI's usage-lane refusal: a dry run's traces exist
            # only on the coordinator, which these placements move remote.
            raise SyqInvocationError(
                "a remote-to-remote dry run cannot produce the results "
                "stream this surface relies on; pass coordinate_at='local'"
            )
        results = await _complete_task(
            asyncio.create_task(asyncio.to_thread(_prepare_results_file, results))
        )
        argv, source_count, source_end = _copy_arguments(
            "cp",
            sources,
            src=src,
            src_src=src_src,
            src_file=src_file,
            src_dir=src_dir,
            from_=from_,
            cwd=cwd,
            root=root,
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
            receipt=receipt,
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
            pscope=pscope,
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
            result = await self._typed(
                argv,
                mode="cp",
                prune=prune,
                mapping=False,
                dry_run=dry_run,
                selectors_total=None,
                on_event=on_event,
                results=results,
                timeout=timeout,
                check=check,
            )
            assert isinstance(result, CpResult)
            return result
        if source_count:
            raise SyqInvocationError("--mapping replaces source selectors")
        if any(value is not None for value in (as_, as_new, as_existing)):
            raise SyqInvocationError("--mapping conflicts with --as")
        if isinstance(mapping, (str, bytes, os.PathLike)):
            _insert_mapping_option(
                argv, source_end, _argument(mapping, label="mapping")
            )
            result = await self._typed(
                argv,
                mode="cp",
                prune=False,
                mapping=True,
                dry_run=dry_run,
                selectors_total=None,
                on_event=on_event,
                results=results,
                timeout=timeout,
                check=check,
            )
            assert isinstance(result, CpResult)
            return result
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix="syq-python-mapping-", suffix=".ndjson"
        ) as manifest:
            if isinstance(mapping, AsyncIterable):
                await _write_async_mapping_manifest(manifest, mapping)
            else:
                cancelled = threading.Event()
                materialize = asyncio.create_task(
                    asyncio.to_thread(
                        _write_sync_mapping_manifest,
                        manifest,
                        mapping,
                        cancelled,
                    )
                )
                await _complete_task(materialize, on_cancel=cancelled.set)
            _insert_mapping_option(
                argv, source_end, os.path.realpath(manifest.name)
            )
            result = await self._typed(
                argv,
                mode="cp",
                prune=False,
                mapping=True,
                dry_run=dry_run,
                selectors_total=None,
                on_event=on_event,
                results=results,
                timeout=timeout,
                check=check,
            )
            assert isinstance(result, CpResult)
            return result

    async def rm(
        self,
        *sources: PathArgument,
        src: Selector | None = None,
        src_src: Selector | None = None,
        src_file: Selector | None = None,
        src_dir: Selector | None = None,
        from_: str | None = None,
        cwd: PathArgument | None = None,
        root: PathArgument | None = None,
        follow: bool = False,
        follow_src: bool = False,
        results: BinaryIO | None = None,
        dry_run: bool = False,
        connections: int | None = None,
        syq_path: str | os.PathLike[str] | None = None,
        no_bootstrap: bool = False,
        pscope: PathArgument | None = None,
        on_event: AsyncEventCallback | None = None,
        timeout: float | None = None,
        check: bool = True,
    ) -> RmResult:
        results = await _complete_task(
            asyncio.create_task(asyncio.to_thread(_prepare_results_file, results))
        )
        argv, selectors_total = _rm_arguments(
            sources,
            src=src,
            src_src=src_src,
            src_file=src_file,
            src_dir=src_dir,
            from_=from_,
            cwd=cwd,
            root=root,
            follow=follow,
            follow_src=follow_src,
            dry_run=dry_run,
            connections=connections,
            syq_path=syq_path,
            no_bootstrap=no_bootstrap,
            pscope=pscope,
        )
        result = await self._typed(
            argv,
            mode="rm",
            prune=False,
            mapping=False,
            dry_run=dry_run,
            selectors_total=selectors_total,
            on_event=on_event,
            results=results,
            timeout=timeout,
            check=check,
        )
        assert isinstance(result, RmResult)
        return result

    def map(
        self,
        *sources: PathArgument,
        src: Selector | None = None,
        src_src: Selector | None = None,
        src_file: Selector | None = None,
        src_dir: Selector | None = None,
        cwd: PathArgument | None = None,
        root: PathArgument | None = None,
        follow: bool = False,
        follow_src: bool = False,
        as_: PathArgument | None = None,
        timeout: float | None = None,
    ) -> AsyncMapStream:
        src_values = _values(src, label="--src")
        src_src_values = _values(src_src, label="--src-src")
        src_file_values = _values(src_file, label="--src-file")
        src_dir_values = _values(src_dir, label="--src-dir")
        argv, source_count, _source_end = _copy_arguments(
            "map",
            sources,
            src=src_values,
            src_src=src_src_values,
            src_file=src_file_values,
            src_dir=src_dir_values,
            from_=None,
            cwd=cwd,
            root=root,
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
            receipt=None,
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
        selected_base = root if root is not None else cwd
        contents_selector = None
        if src_src_values:
            if len(src_src_values) != 1 or source_count != 1:
                raise SyqInvocationError(
                    "syq map takes --src-src as its only selector"
                )
            contents_selector = src_src_values[0]
        effective_cwd = _map_stream_cwd(
            self.process_cwd,
            self.env,
            selected_base,
            contents_selector,
        )
        return AsyncMapStream(self, argv, effective_cwd, timeout)
