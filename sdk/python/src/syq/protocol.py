"""Strict decoders for syq's versioned machine formats."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from .errors import SyqProtocolError
from .models import (
    CpPruneResult,
    CpResult,
    Disposition,
    EntryKind,
    ErrorEvent,
    MappingEntry,
    OperationResult,
    OperationStatus,
    OperationSummary,
    PathValue,
    Retryability,
    RmResult,
    RunEvent,
    WarningEvent,
)


SCHEMA = "syq.automation"
SCHEMA_VERSION = 1


def _object(line: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SyqProtocolError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise SyqProtocolError(f"{label} must be a JSON object")
    return value


def _string(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str):
        raise SyqProtocolError(f"automation field {key!r} must be a string")
    return value


def _integer(record: dict[str, Any], key: str, *, nonnegative: bool = True) -> int:
    value = record.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise SyqProtocolError(f"automation field {key!r} must be an integer")
    if nonnegative and value < 0:
        raise SyqProtocolError(f"automation field {key!r} must not be negative")
    return value


def _optional_integer(record: dict[str, Any], key: str) -> int | None:
    if key not in record:
        return None
    return _integer(record, key)


def _boolean(record: dict[str, Any], key: str) -> bool:
    value = record.get(key)
    if not isinstance(value, bool):
        raise SyqProtocolError(f"automation field {key!r} must be a boolean")
    return value


def _optional_string(record: dict[str, Any], key: str) -> str | None:
    if key not in record:
        return None
    return _string(record, key)


def _tagged(value: Any, *, label: str) -> PathValue:
    if not isinstance(value, dict):
        raise SyqProtocolError(f"{label} must be a tagged path object")
    encoding = value.get("encoding")
    encoded = value.get("value")
    if not isinstance(encoded, str):
        raise SyqProtocolError(f"{label}.value must be a string")
    if encoding == "utf-8":
        try:
            raw = encoded.encode("utf-8")
        except UnicodeEncodeError as error:
            raise SyqProtocolError(
                f"{label}.value is not valid Unicode"
            ) from error
    elif encoding == "base64":
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise SyqProtocolError(f"{label}.value is not valid base64") from error
        if base64.b64encode(raw).decode("ascii") != encoded:
            raise SyqProtocolError(f"{label}.value is not canonical base64")
    else:
        raise SyqProtocolError(f"{label}.encoding is unsupported")
    display = value.get("display", encoded if encoding == "utf-8" else None)
    if not isinstance(display, str):
        raise SyqProtocolError(f"{label}.display must be a string")
    return PathValue(raw=raw, display=display)


def parse_mapping_line(line: bytes) -> MappingEntry:
    record = _object(line, label="mapping record")
    unknown = set(record) - {"src", "dst", "kind", "size", "mtime"}
    if unknown:
        raise SyqProtocolError(
            f"mapping record has unknown field {sorted(unknown)[0]!r}"
        )
    src = _tagged(record.get("src"), label="src")
    dst = _tagged(record.get("dst"), label="dst")
    try:
        kind = EntryKind(record["kind"]) if "kind" in record else None
    except (TypeError, ValueError) as error:
        raise SyqProtocolError("mapping field 'kind' is unsupported") from error
    size = _optional_integer(record, "size")
    mtime = (
        _integer(record, "mtime", nonnegative=False) if "mtime" in record else None
    )
    try:
        return MappingEntry(src.raw, dst.raw, kind, size, mtime)
    except (TypeError, ValueError) as error:
        raise SyqProtocolError(f"mapping path is invalid: {error}") from error


class AutomationDecoder:
    """Validate one complete automation-v1 NDJSON stream incrementally."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.run: RunEvent | None = None
        self.result: OperationSummary | None = None
        self._next_seq = 0

    def feed(self, line: bytes):
        if self.result is not None:
            raise SyqProtocolError("automation stream has a record after its result")
        record = _object(line, label="automation record")
        if record.get("schema") != SCHEMA:
            raise SyqProtocolError("unsupported automation schema")
        if _integer(record, "schema_version") != SCHEMA_VERSION:
            raise SyqProtocolError("unsupported automation schema version")
        run_id = _string(record, "run_id")
        if not run_id:
            raise SyqProtocolError("automation run_id may not be empty")
        seq = _integer(record, "seq")
        if seq != self._next_seq:
            raise SyqProtocolError(
                f"automation sequence is {seq}, expected {self._next_seq}"
            )
        self._next_seq += 1
        elapsed_ms = _integer(record, "elapsed_ms")
        record_type = _string(record, "type")
        common = {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "seq": seq,
            "elapsed_ms": elapsed_ms,
        }
        if self.run is None:
            if record_type != "run":
                raise SyqProtocolError("automation stream must begin with a run record")
            mode = _string(record, "mode")
            if mode != self.mode:
                raise SyqProtocolError(
                    f"automation mode is {mode!r}, expected {self.mode!r}"
                )
            event = RunEvent(
                **common,
                syq_version=_string(record, "syq_version"),
                mode=mode,
                dry_run=_boolean(record, "dry_run"),
                mapping=_boolean(record, "mapping"),
            )
            self.run = event
            return event
        if run_id != self.run.run_id:
            raise SyqProtocolError("automation stream changed run_id")
        if record_type == "run":
            raise SyqProtocolError("automation stream contains more than one run record")
        if record_type == "operation_result":
            try:
                disposition = Disposition(_string(record, "disposition"))
                retryable = (
                    Retryability(_string(record, "retryable"))
                    if "retryable" in record
                    else None
                )
            except ValueError as error:
                raise SyqProtocolError("unsupported operation result enum value") from error
            if self.run.dry_run != (disposition is Disposition.PLANNED):
                raise SyqProtocolError(
                    "operation disposition disagrees with the run's dry_run mode"
                )
            src = _tagged(record["src"], label="src") if "src" in record else None
            return OperationResult(
                **common,
                action=_string(record, "action"),
                dst=_tagged(record.get("dst"), label="dst"),
                src=src,
                kind=_string(record, "kind"),
                disposition=disposition,
                bytes=_optional_integer(record, "bytes"),
                attempts=_optional_integer(record, "attempts"),
                retryable=retryable,
                message=_optional_string(record, "message"),
            )
        if record_type == "warning":
            return WarningEvent(
                **common,
                code=_string(record, "code"),
                count=_integer(record, "count"),
                message=_string(record, "message"),
            )
        if record_type == "error":
            try:
                retryable = Retryability(_string(record, "retryable"))
            except ValueError as error:
                raise SyqProtocolError("unsupported error retryability") from error
            return ErrorEvent(
                **common,
                error_class=_string(record, "class"),
                retryable=retryable,
                message=_string(record, "message"),
            )
        if record_type == "result":
            try:
                status = OperationStatus(_string(record, "status"))
            except ValueError as error:
                raise SyqProtocolError("unsupported operation status") from error
            result_type = {
                "cp": CpResult,
                "cp-prune": CpPruneResult,
                "rm": RmResult,
            }[self.mode]
            result = result_type(
                **common,
                status=status,
                exit_code=_integer(record, "exit_code"),
                dry_run=self.run.dry_run,
                files_planned=_integer(record, "files_planned"),
                files_completed=_integer(record, "files_completed"),
                files_unchanged=_integer(record, "files_unchanged"),
                files_excluded=_integer(record, "files_excluded"),
                directories_planned=_integer(record, "directories_planned"),
                directories_completed=_integer(record, "directories_completed"),
                symlinks_planned=_integer(record, "symlinks_planned"),
                symlinks_completed=_integer(record, "symlinks_completed"),
                specials_planned=_integer(record, "specials_planned"),
                specials_completed=_integer(record, "specials_completed"),
                deletions_planned=_integer(record, "deletions_planned"),
                deletions_completed=_integer(record, "deletions_completed"),
                deletions_blocked=_boolean(record, "deletions_blocked"),
                errors=_integer(record, "errors"),
                bytes_planned=_integer(record, "bytes_planned"),
                bytes_completed=_integer(record, "bytes_completed"),
                bytes_unchanged=_integer(record, "bytes_unchanged"),
            )
            if (result.status is OperationStatus.SUCCESS) != (result.exit_code == 0):
                raise SyqProtocolError(
                    "automation status disagrees with the terminal exit_code"
                )
            for planned, completed, label in (
                (result.files_planned, result.files_completed, "files"),
                (
                    result.directories_planned,
                    result.directories_completed,
                    "directories",
                ),
                (result.symlinks_planned, result.symlinks_completed, "symlinks"),
                (result.specials_planned, result.specials_completed, "specials"),
                (result.deletions_planned, result.deletions_completed, "deletions"),
                (result.bytes_planned, result.bytes_completed, "bytes"),
            ):
                if completed > planned:
                    raise SyqProtocolError(
                        f"automation completed {label} exceed planned {label}"
                    )
            if result.dry_run and any(
                (
                    result.files_completed,
                    result.directories_completed,
                    result.symlinks_completed,
                    result.specials_completed,
                    result.deletions_completed,
                    result.bytes_completed,
                )
            ):
                raise SyqProtocolError(
                    "a dry-run result reports completed mutations"
                )
            self.result = result
            return result
        raise SyqProtocolError(f"unsupported automation record type {record_type!r}")

    def finish(self, returncode: int) -> OperationSummary:
        if self.run is None:
            raise SyqProtocolError("automation stream is empty")
        if self.result is None:
            raise SyqProtocolError("automation stream has no terminal result")
        if self.result.exit_code != returncode:
            raise SyqProtocolError(
                "automation result exit_code does not match the process status"
            )
        return self.result
