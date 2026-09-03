"""Strict decoders for syq's versioned machine formats."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any, TypeVar

from .errors import SyqProtocolError
from .models import (
    AutomationEvent,
    CpResult,
    Disposition,
    Endpoint,
    EndpointKind,
    EndpointRole,
    EntryKind,
    ErrorClass,
    ErrorEvent,
    AttestedDigest,
    FinalObjectState,
    FinalStateEvent,
    ObjectMetadata,
    MappingEntry,
    OperationAction,
    OperationResult,
    OperationStatus,
    OperationSummary,
    OsKind,
    ReceiptCode,
    PathValue,
    ProgressEvent,
    Retryability,
    RunEvent,
    TraceEvent,
    TraceReason,
)


SCHEMA = "syq.automation"
SCHEMA_VERSION = 1
_MAX_U64 = (1 << 64) - 1
_EnumT = TypeVar("_EnumT")


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
    if nonnegative and value > _MAX_U64:
        raise SyqProtocolError(
            f"automation field {key!r} exceeds the unsigned 64-bit range"
        )
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


def _enum(record: dict[str, Any], key: str, enum_type: type[_EnumT]) -> _EnumT:
    try:
        return enum_type(_string(record, key))
    except ValueError as error:
        raise SyqProtocolError(f"automation field {key!r} is unsupported") from error


def _optional_enum(
    record: dict[str, Any], key: str, enum_type: type[_EnumT]
) -> _EnumT | None:
    if key not in record:
        return None
    return _enum(record, key, enum_type)


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
            raise SyqProtocolError(f"{label}.value is not valid Unicode") from error
    elif encoding == "base64":
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise SyqProtocolError(f"{label}.value is not valid base64") from error
        if base64.b64encode(raw).decode("ascii") != encoded:
            raise SyqProtocolError(f"{label}.value is not canonical base64")
    else:
        raise SyqProtocolError(f"{label}.encoding is unsupported")
    return PathValue(raw=raw)


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


def _endpoints(record: dict[str, Any]) -> tuple[Endpoint, ...]:
    values = record.get("endpoints")
    if not isinstance(values, list):
        raise SyqProtocolError("automation field 'endpoints' must be an array")
    endpoints: list[Endpoint] = []
    for index, value in enumerate(values):
        if not isinstance(value, dict):
            raise SyqProtocolError(f"endpoints[{index}] must be an object")
        kind = _enum(value, "kind", EndpointKind)
        host = _optional_string(value, "host")
        user = _optional_string(value, "user")
        if kind is EndpointKind.LOCAL and (host is not None or user is not None):
            raise SyqProtocolError("a local endpoint may not contain host or user")
        if kind is EndpointKind.SSH and not host:
            raise SyqProtocolError("an SSH endpoint must contain a host")
        endpoints.append(
            Endpoint(
                role=_enum(value, "role", EndpointRole),
                kind=kind,
                host=host,
                user=user,
            )
        )
    return tuple(endpoints)


class AutomationDecoder:
    """Validate one complete automation-v1 cp stream incrementally."""

    def __init__(self, *, prune: bool, mapping: bool, dry_run: bool) -> None:
        self.expected_prune = prune
        self.expected_mapping = mapping
        self.expected_dry_run = dry_run
        self.run: RunEvent | None = None
        self.result: OperationSummary | None = None
        self._next_seq = 0

    def feed(self, line: bytes) -> AutomationEvent | None:
        if self.result is not None:
            raise SyqProtocolError("automation stream has a record after its result")
        record = _object(line, label="automation record")
        if record.get("schema") != SCHEMA:
            raise SyqProtocolError("unsupported automation schema")
        if _integer(record, "schema_version") != SCHEMA_VERSION:
            raise SyqProtocolError("unsupported automation schema version")
        seq = _integer(record, "seq")
        if seq != self._next_seq:
            raise SyqProtocolError(
                f"automation sequence is {seq}, expected {self._next_seq}"
            )
        self._next_seq += 1
        record_type = _string(record, "type")
        common = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, "seq": seq}

        if self.run is None:
            if record_type != "run":
                raise SyqProtocolError("automation stream must begin with a run record")
            run_id = _string(record, "run_id")
            if not run_id:
                raise SyqProtocolError("automation run_id may not be empty")
            mode = _string(record, "mode")
            prune = _boolean(record, "prune")
            mapping = _boolean(record, "mapping")
            dry_run = _boolean(record, "dry_run")
            if mode != "cp":
                raise SyqProtocolError(
                    f"automation mode is {mode!r}, expected 'cp'"
                )
            for actual, expected, label in (
                (prune, self.expected_prune, "prune"),
                (mapping, self.expected_mapping, "mapping"),
                (dry_run, self.expected_dry_run, "dry_run"),
            ):
                if actual != expected:
                    raise SyqProtocolError(
                        f"automation run {label} disagrees with the invocation"
                    )
            event = RunEvent(
                **common,
                run_id=run_id,
                started_at=_integer(record, "started_at"),
                syq_version=_string(record, "syq_version"),
                mode=mode,
                prune=prune,
                mapping=mapping,
                dry_run=dry_run,
                endpoints=_endpoints(record),
            )
            self.run = event
            return event

        if record_type == "run":
            raise SyqProtocolError("automation stream contains more than one run record")
        if record_type == "progress":
            return ProgressEvent(
                **common,
                bytes_done=_integer(record, "bytes_done"),
                bytes_total=_integer(record, "bytes_total"),
                bytes_unchanged=_integer(record, "bytes_unchanged"),
                files_done=_integer(record, "files_done"),
                files_total=_integer(record, "files_total"),
                files_unchanged=_integer(record, "files_unchanged"),
                files_excluded=_integer(record, "files_excluded"),
                scanned=_integer(record, "scanned"),
                scan_done=_boolean(record, "scan_done"),
                elapsed_ms=_integer(record, "elapsed_ms"),
            )
        if record_type == "trace":
            if not self.run.dry_run:
                raise SyqProtocolError("a live automation stream contains a trace")
            return TraceEvent(
                **common,
                action=_enum(record, "action", OperationAction),
                dst=_tagged(record.get("dst"), label="dst"),
                src=_tagged(record["src"], label="src") if "src" in record else None,
                kind=_enum(record, "kind", EntryKind),
                bytes=_optional_integer(record, "bytes"),
                reason=_enum(record, "reason", TraceReason),
            )
        if record_type == "operation_result":
            if self.run.dry_run:
                raise SyqProtocolError(
                    "a dry-run automation stream contains an operation result"
                )
            return OperationResult(
                **common,
                action=_enum(record, "action", OperationAction),
                dst=_tagged(record.get("dst"), label="dst"),
                src=_tagged(record["src"], label="src") if "src" in record else None,
                kind=_optional_enum(record, "kind", EntryKind),
                disposition=_enum(record, "disposition", Disposition),
                bytes=_optional_integer(record, "bytes"),
                attempts=_optional_integer(record, "attempts"),
                retryable=_optional_enum(record, "retryable", Retryability),
                class_=_optional_enum(record, "class", ErrorClass),
                os_kind=_optional_enum(record, "os_kind", OsKind),
                message=_optional_string(record, "message"),
                provenance=_optional_string(record, "provenance"),
                scope=_optional_integer(record, "scope"),
                code=_optional_enum(record, "code", ReceiptCode),
            )
        if record_type == "error":
            return ErrorEvent(
                **common,
                message=_string(record, "message"),
                class_=_optional_enum(record, "class", ErrorClass),
                os_kind=_optional_enum(record, "os_kind", OsKind),
                provenance=_optional_string(record, "provenance"),
                code=_optional_enum(record, "code", ReceiptCode),
            )
        if record_type == "final_state":
            state = record.get("object")
            if not isinstance(state, dict):
                raise SyqProtocolError("final_state record has no object")
            digest_record = state.get("digest")
            digest = None
            if digest_record is not None:
                if not isinstance(digest_record, dict):
                    raise SyqProtocolError("final_state digest is not an object")
                digest = AttestedDigest(
                    algorithm=_string(digest_record, "algorithm"),
                    value=_string(digest_record, "value"),
                )
            metadata_record = state.get("metadata")
            metadata = None
            if metadata_record is not None:
                if not isinstance(metadata_record, dict):
                    raise SyqProtocolError("final_state metadata is not an object")
                metadata = ObjectMetadata(
                    mode=_integer(metadata_record, "mode"),
                    uid=_integer(metadata_record, "uid"),
                    gid=_integer(metadata_record, "gid"),
                    mtime=_integer(metadata_record, "mtime"),
                    mtime_nsec=_integer(metadata_record, "mtime_nsec"),
                    rdev=_integer(metadata_record, "rdev"),
                )
            return FinalStateEvent(
                **common,
                provenance=_string(record, "provenance"),
                scope=_integer(record, "scope"),
                dst=_tagged(record.get("dst"), label="dst"),
                state=_enum(state, "state", FinalObjectState),
                kind=_optional_string(state, "kind"),
                size=_optional_integer(state, "size"),
                metadata=metadata,
                digest=digest,
                symlink_target=(
                    _tagged(state["symlink_target"], label="symlink_target")
                    if "symlink_target" in state
                    else None
                ),
                observation_error=_optional_string(state, "observation_error"),
                code=_optional_enum(state, "code", ReceiptCode),
                message=_optional_string(state, "message"),
            )
        if record_type == "result":
            status = _enum(record, "status", OperationStatus)
            exit_code = _integer(record, "exit_code")
            allowed_exit_codes = {
                OperationStatus.SUCCESS: {0},
                OperationStatus.PARTIAL: {23},
                OperationStatus.REFUSED: {25},
                OperationStatus.ABORTED: {1},
                OperationStatus.FAILED: {1},
            }
            if exit_code not in allowed_exit_codes[status]:
                raise SyqProtocolError(
                    "automation status disagrees with the terminal exit_code"
                )
            dry_run = _boolean(record, "dry_run")
            if dry_run != self.run.dry_run:
                raise SyqProtocolError(
                    "automation result dry_run disagrees with the run record"
                )
            deletion_values = tuple(
                _optional_integer(record, field)
                for field in (
                    "deletions_planned",
                    "deletions_completed",
                    "deletions_blocked",
                )
            )
            attested = record.get("provenance") == "receiver_attested"
            if attested:
                # A receipt attests settled deletions (deletions_completed);
                # it cannot vouch for planning or --max-delete blocking, so
                # the other two totals never appear.
                if deletion_values[0] is not None or deletion_values[2] is not None:
                    raise SyqProtocolError(
                        "a receiver-attested result may only contain deletions_completed"
                    )
            elif self.run.prune and any(value is None for value in deletion_values):
                raise SyqProtocolError(
                    "a prune result must contain every deletion total"
                )
            elif not self.run.prune and any(
                value is not None for value in deletion_values
            ):
                raise SyqProtocolError(
                    "a non-prune result may not contain deletion totals"
                )
            result = CpResult(
                **common,
                status=status,
                exit_code=exit_code,
                dry_run=dry_run,
                files_transferred=_integer(record, "files_transferred"),
                files_unchanged=_integer(record, "files_unchanged"),
                files_excluded=_integer(record, "files_excluded"),
                directories_created=_integer(record, "directories_created"),
                symlinks_created=_integer(record, "symlinks_created"),
                specials_created=_integer(record, "specials_created"),
                errors=_integer(record, "errors"),
                bytes_transferred=_integer(record, "bytes_transferred"),
                bytes_unchanged=_integer(record, "bytes_unchanged"),
                elapsed_ms=_integer(record, "elapsed_ms"),
                deletions_planned=deletion_values[0],
                deletions_completed=deletion_values[1],
                deletions_blocked=deletion_values[2],
                provenance=_optional_string(record, "provenance"),
                receipt_status=_optional_string(record, "receipt_status"),
                operations=_optional_integer(record, "operations"),
                final_states=_optional_integer(record, "final_states"),
                receipt_records=_optional_integer(record, "receipt_records"),
            )
            self.result = result
            return result

        # New record types are additive within schema v1. Their envelope and
        # sequence position are validated above, then older SDKs ignore them.
        return None

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
