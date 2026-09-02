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
    FinalObjectKind,
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
    ReceiptStatus,
    PathValue,
    ProgressEvent,
    Retryability,
    RmResult,
    RunEvent,
    SelectionResult,
    SelectionStatus,
    RemovalDisposition,
    RemovalResult,
    RemovalTrace,
    TraceEvent,
    TraceReason,
)


SCHEMA = "syq.automation"
SCHEMA_VERSION = 1
_MAX_U64 = (1 << 64) - 1
_MAX_I64 = (1 << 63) - 1
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
    if nonnegative:
        if value < 0:
            raise SyqProtocolError(f"automation field {key!r} must not be negative")
        if value > _MAX_U64:
            raise SyqProtocolError(
                f"automation field {key!r} exceeds the unsigned 64-bit range"
            )
    elif not -_MAX_I64 - 1 <= value <= _MAX_I64:
        raise SyqProtocolError(
            f"automation field {key!r} exceeds the signed 64-bit range"
        )
    return value


def _attested_provenance(record: dict[str, Any], label: str) -> str | None:
    provenance = _optional_string(record, "provenance")
    if provenance is not None and provenance != "receiver_attested":
        raise SyqProtocolError(
            f"a {label}'s provenance can only be receiver_attested"
        )
    return provenance


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


def _destination_index(record: dict[str, Any], run: RunEvent) -> int | None:
    index = _optional_integer(record, "destination_index")
    if index is None:
        return None
    destinations = sum(
        endpoint.role is EndpointRole.DESTINATION for endpoint in run.endpoints
    )
    if index < 0 or index >= destinations:
        raise SyqProtocolError(
            "automation destination_index does not name a run destination"
        )
    return index


class AutomationDecoder:
    """Validate one complete automation-v1 typed-operation stream incrementally."""

    def __init__(
        self,
        *,
        dry_run: bool,
        mode: str = "cp",
        prune: bool = False,
        mapping: bool = False,
        selectors_total: int | None = None,
    ) -> None:
        if mode not in {"cp", "rm"}:
            raise ValueError("automation decoder mode must be 'cp' or 'rm'")
        self.expected_mode = mode
        self.expected_prune = prune
        self.expected_mapping = mapping
        self.expected_dry_run = dry_run
        self.expected_selectors_total = selectors_total
        self.run: RunEvent | None = None
        self.result: OperationSummary | None = None
        self._next_seq = 0
        self._rm_selections: dict[int, SelectionStatus] = {}
        self._rm_removal_started = False
        self._rm_entries = {
            RemovalDisposition.WOULD_REMOVE: 0,
            RemovalDisposition.REMOVED: 0,
            RemovalDisposition.ALREADY_ABSENT: 0,
            RemovalDisposition.FAILED: 0,
        }
        self._rm_error_records = 0

    def _validate_removal_selector(self, selector: int) -> None:
        status = self._rm_selections.get(selector)
        if status is None:
            raise SyqProtocolError(
                f"rm removal outcome references selector {selector} before resolution"
            )
        if status is not SelectionStatus.RESOLVED:
            raise SyqProtocolError(
                f"rm removal outcome references missing selector {selector}"
            )

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
            dry_run = _boolean(record, "dry_run")
            if mode != self.expected_mode:
                raise SyqProtocolError(
                    f"automation mode is {mode!r}, expected {self.expected_mode!r}"
                )
            if mode == "cp":
                prune = _boolean(record, "prune")
                mapping = _boolean(record, "mapping")
                expected_values = (
                    (prune, self.expected_prune, "prune"),
                    (mapping, self.expected_mapping, "mapping"),
                    (dry_run, self.expected_dry_run, "dry_run"),
                )
            else:
                if "prune" in record or "mapping" in record:
                    raise SyqProtocolError(
                        "an rm run record may not contain copy-mode fields"
                    )
                prune = None
                mapping = None
                expected_values = (
                    (dry_run, self.expected_dry_run, "dry_run"),
                )
            for actual, expected, label in expected_values:
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
            if mode == "rm" and (
                len(event.endpoints) != 1
                or event.endpoints[0].role is not EndpointRole.SOURCE
            ):
                raise SyqProtocolError(
                    "an rm run must contain exactly one source endpoint"
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
            if self.run.mode != "cp":
                raise SyqProtocolError("an rm automation stream contains a cp trace")
            if not self.run.dry_run:
                raise SyqProtocolError("a live automation stream contains a trace")
            return TraceEvent(
                **common,
                destination_index=_destination_index(record, self.run),
                action=_enum(record, "action", OperationAction),
                dst=_tagged(record.get("dst"), label="dst"),
                src=_tagged(record["src"], label="src") if "src" in record else None,
                kind=_enum(record, "kind", EntryKind),
                bytes=_optional_integer(record, "bytes"),
                reason=_enum(record, "reason", TraceReason),
            )
        if record_type == "operation_result":
            if self.run.mode != "cp":
                raise SyqProtocolError(
                    "an rm automation stream contains a cp operation result"
                )
            if self.run.dry_run:
                raise SyqProtocolError(
                    "a dry-run automation stream contains an operation result"
                )
            provenance = _attested_provenance(record, "operation result")
            if provenance is None:
                for field in ("scope", "code"):
                    if field in record:
                        raise SyqProtocolError(
                            f"receipt field {field!r} appears on an operation "
                            "result without receiver_attested provenance"
                        )
            elif "scope" not in record:
                raise SyqProtocolError(
                    "a receiver-attested operation result must carry its scope"
                )
            return OperationResult(
                **common,
                destination_index=_destination_index(record, self.run),
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
                provenance=provenance,
                scope=_optional_integer(record, "scope"),
                code=_optional_enum(record, "code", ReceiptCode),
            )
        if record_type == "selection_result":
            if self.run.mode != "rm":
                raise SyqProtocolError(
                    "a cp automation stream contains an rm selection result"
                )
            status = _enum(record, "status", SelectionStatus)
            kind = _optional_enum(record, "kind", EntryKind)
            selector = _integer(record, "selector")
            if self._rm_removal_started:
                raise SyqProtocolError(
                    "an rm selection result appears after removal outcomes"
                )
            if selector in self._rm_selections:
                raise SyqProtocolError(
                    f"rm selector {selector} has more than one selection result"
                )
            if (
                self.expected_selectors_total is not None
                and selector >= self.expected_selectors_total
            ):
                raise SyqProtocolError(
                    f"rm selector {selector} exceeds the invocation's selector count"
                )
            if status is SelectionStatus.RESOLVED and kind is None:
                raise SyqProtocolError("a resolved selector must contain its kind")
            if status is SelectionStatus.MISSING and kind is not None:
                raise SyqProtocolError("a missing selector may not contain a kind")
            self._rm_selections[selector] = status
            return SelectionResult(
                **common,
                selector=selector,
                path=_tagged(record.get("path"), label="path"),
                status=status,
                kind=kind,
            )
        if record_type == "removal_trace":
            if self.run.mode != "rm":
                raise SyqProtocolError(
                    "a cp automation stream contains an rm removal trace"
                )
            if not self.run.dry_run:
                raise SyqProtocolError("a live rm stream contains a removal trace")
            disposition = _enum(record, "disposition", RemovalDisposition)
            if disposition is not RemovalDisposition.WOULD_REMOVE:
                raise SyqProtocolError(
                    "a removal trace disposition must be would_remove"
                )
            selector = _integer(record, "selector")
            self._validate_removal_selector(selector)
            self._rm_removal_started = True
            self._rm_entries[disposition] += 1
            return RemovalTrace(
                **common,
                selector=selector,
                path=_tagged(record.get("path"), label="path"),
                kind=_enum(record, "kind", EntryKind),
                disposition=disposition,
            )
        if record_type == "removal_result":
            if self.run.mode != "rm":
                raise SyqProtocolError(
                    "a cp automation stream contains an rm removal result"
                )
            disposition = _enum(record, "disposition", RemovalDisposition)
            if disposition is RemovalDisposition.WOULD_REMOVE:
                raise SyqProtocolError(
                    "a removal result disposition may not be would_remove"
                )
            if self.run.dry_run and disposition is not RemovalDisposition.FAILED:
                raise SyqProtocolError(
                    "a dry-run rm stream contains a successful live removal result"
                )
            selector = _integer(record, "selector")
            self._validate_removal_selector(selector)
            kind = _optional_enum(record, "kind", EntryKind)
            retryable = _optional_enum(record, "retryable", Retryability)
            class_ = _optional_enum(record, "class", ErrorClass)
            os_kind = _optional_enum(record, "os_kind", OsKind)
            message = _optional_string(record, "message")
            failure_fields = (retryable, class_, os_kind, message)
            if disposition is RemovalDisposition.FAILED:
                if retryable is None or class_ is None or message is None:
                    raise SyqProtocolError(
                        "a failed removal result needs retryability, class, and message"
                    )
            elif kind is None:
                raise SyqProtocolError("a successful removal result needs its kind")
            elif any(value is not None for value in failure_fields):
                raise SyqProtocolError(
                    "a successful removal result may not contain failure fields"
                )
            self._rm_removal_started = True
            self._rm_entries[disposition] += 1
            return RemovalResult(
                **common,
                selector=selector,
                path=_tagged(record.get("path"), label="path"),
                kind=kind,
                disposition=disposition,
                attempts=_integer(record, "attempts"),
                retryable=retryable,
                class_=class_,
                os_kind=os_kind,
                message=message,
            )
        if record_type == "error":
            provenance = _attested_provenance(record, "error record")
            if provenance is None and "code" in record:
                raise SyqProtocolError(
                    "a receipt code appears on an error record without "
                    "receiver_attested provenance"
                )
            event = ErrorEvent(
                **common,
                destination_index=_destination_index(record, self.run),
                message=_string(record, "message"),
                class_=_optional_enum(record, "class", ErrorClass),
                os_kind=_optional_enum(record, "os_kind", OsKind),
                provenance=provenance,
                code=_optional_enum(record, "code", ReceiptCode),
            )
            if self.run.mode == "rm":
                self._rm_error_records += 1
            return event
        if record_type == "final_state":
            if self.run.mode != "cp":
                raise SyqProtocolError(
                    "an rm automation stream contains a receiver final state"
                )
            state = record.get("object")
            if not isinstance(state, dict):
                raise SyqProtocolError("final_state record has no object")
            variant = _enum(state, "state", FinalObjectState)
            # Each state admits exactly its own fields (spec: automation v1).
            allowed, required = {
                FinalObjectState.PRESENT: (
                    {
                        "state",
                        "kind",
                        "size",
                        "metadata",
                        "digest",
                        "symlink_target",
                        "observation_error",
                    },
                    {"kind", "size", "metadata"},
                ),
                FinalObjectState.ABSENT: ({"state"}, set()),
                FinalObjectState.OBSERVATION_FAILED: (
                    {"state", "code", "message"},
                    {"code"},
                ),
            }[variant]
            known = {
                "state",
                "kind",
                "size",
                "metadata",
                "digest",
                "symlink_target",
                "observation_error",
                "code",
                "message",
            }
            extra = (set(state) & known) - allowed
            if extra:
                raise SyqProtocolError(
                    f"final_state object carries fields from another state "
                    f"variant than {variant.value!r}: {sorted(extra)}"
                )
            missing = required - set(state)
            if missing:
                raise SyqProtocolError(
                    f"final_state {variant.value!r} object is missing "
                    f"{sorted(missing)}"
                )
            digest_record = state.get("digest")
            digest = None
            if digest_record is not None:
                if not isinstance(digest_record, dict):
                    raise SyqProtocolError("final_state digest is not an object")
                algorithm = _string(digest_record, "algorithm")
                if algorithm != "blake3":
                    raise SyqProtocolError(
                        "final_state digest algorithm is not blake3"
                    )
                value = _string(digest_record, "value")
                if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                    raise SyqProtocolError(
                        "final_state digest value is not 64 lowercase hex digits"
                    )
                digest = AttestedDigest(algorithm=algorithm, value=value)
            metadata_record = state.get("metadata")
            metadata = None
            if metadata_record is not None:
                if not isinstance(metadata_record, dict):
                    raise SyqProtocolError("final_state metadata is not an object")
                metadata = ObjectMetadata(
                    mode=_integer(metadata_record, "mode"),
                    uid=_integer(metadata_record, "uid"),
                    gid=_integer(metadata_record, "gid"),
                    mtime=_integer(metadata_record, "mtime", nonnegative=False),
                    mtime_nsec=_integer(metadata_record, "mtime_nsec"),
                    rdev=_integer(metadata_record, "rdev"),
                )
            provenance = _string(record, "provenance")
            if provenance != "receiver_attested":
                raise SyqProtocolError(
                    "final_state records carry receiver_attested provenance"
                )
            return FinalStateEvent(
                **common,
                provenance=provenance,
                scope=_integer(record, "scope"),
                dst=_tagged(record.get("dst"), label="dst"),
                state=variant,
                kind=_optional_enum(state, "kind", FinalObjectKind),
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
            if self.run.mode == "rm":
                if _string(record, "mode") != "rm":
                    raise SyqProtocolError("an rm terminal result must carry mode 'rm'")
                if status not in {
                    OperationStatus.SUCCESS,
                    OperationStatus.PARTIAL,
                    OperationStatus.FAILED,
                }:
                    raise SyqProtocolError(
                        "an rm terminal result has an unsupported status"
                    )
                selectors_total = _integer(record, "selectors_total")
                selectors_resolved = _integer(record, "selectors_resolved")
                selectors_missing = _integer(record, "selectors_missing")
                entries_planned = _integer(record, "entries_planned")
                entries_removed = _integer(record, "entries_removed")
                entries_already_absent = _integer(
                    record, "entries_already_absent"
                )
                entries_failed = _integer(record, "entries_failed")
                errors = _integer(record, "errors")
                if (
                    self.expected_selectors_total is not None
                    and selectors_total != self.expected_selectors_total
                ):
                    raise SyqProtocolError(
                        "rm selectors_total disagrees with the invocation"
                    )
                if selectors_resolved + selectors_missing > selectors_total:
                    raise SyqProtocolError(
                        "rm selector totals exceed selectors_total"
                    )
                if any(selector >= selectors_total for selector in self._rm_selections):
                    raise SyqProtocolError(
                        "an rm selection result exceeds terminal selectors_total"
                    )
                if status is not OperationStatus.FAILED and (
                    selectors_resolved + selectors_missing != selectors_total
                ):
                    raise SyqProtocolError(
                        "a settled rm result does not account for every selector"
                    )
                observed_resolved = sum(
                    status is SelectionStatus.RESOLVED
                    for status in self._rm_selections.values()
                )
                observed_missing = sum(
                    status is SelectionStatus.MISSING
                    for status in self._rm_selections.values()
                )
                if (
                    selectors_resolved != observed_resolved
                    or selectors_missing != observed_missing
                ):
                    raise SyqProtocolError(
                        "rm terminal selector totals disagree with selection results"
                    )
                expected_entries = {
                    "entries_planned": self._rm_entries[
                        RemovalDisposition.WOULD_REMOVE
                    ],
                    "entries_removed": self._rm_entries[
                        RemovalDisposition.REMOVED
                    ],
                    "entries_already_absent": self._rm_entries[
                        RemovalDisposition.ALREADY_ABSENT
                    ],
                    "entries_failed": self._rm_entries[RemovalDisposition.FAILED],
                }
                actual_entries = {
                    "entries_planned": entries_planned,
                    "entries_removed": entries_removed,
                    "entries_already_absent": entries_already_absent,
                    "entries_failed": entries_failed,
                }
                for field, expected in expected_entries.items():
                    if actual_entries[field] != expected:
                        raise SyqProtocolError(
                            f"rm terminal {field} disagrees with per-path records"
                        )
                if errors != self._rm_error_records:
                    raise SyqProtocolError(
                        "rm terminal errors disagree with error records"
                    )
                if dry_run and (
                    entries_removed != 0
                    or entries_already_absent != 0
                ):
                    raise SyqProtocolError(
                        "a dry-run rm result contains live removal totals"
                    )
                if not dry_run and entries_planned != 0:
                    raise SyqProtocolError(
                        "a live rm result contains planned removal totals"
                    )
                if entries_failed > errors:
                    raise SyqProtocolError(
                        "rm entries_failed exceeds its error count"
                    )
                if status is OperationStatus.SUCCESS and errors != 0:
                    raise SyqProtocolError(
                        "a successful rm result contains errors"
                    )
                if status is OperationStatus.PARTIAL and entries_failed == 0:
                    raise SyqProtocolError(
                        "a partial rm result contains no failed entries"
                    )
                if (
                    status is OperationStatus.PARTIAL
                    and errors != entries_failed
                ):
                    raise SyqProtocolError(
                        "a partial rm result has errors not attributable to failed entries"
                    )
                if status is OperationStatus.FAILED and errors == 0:
                    raise SyqProtocolError(
                        "a failed rm result contains no error"
                    )
                result = RmResult(
                    **common,
                    status=status,
                    exit_code=exit_code,
                    dry_run=dry_run,
                    selectors_total=selectors_total,
                    selectors_resolved=selectors_resolved,
                    selectors_missing=selectors_missing,
                    entries_planned=entries_planned,
                    entries_removed=entries_removed,
                    entries_already_absent=entries_already_absent,
                    entries_failed=entries_failed,
                    errors=errors,
                    elapsed_ms=_integer(record, "elapsed_ms"),
                )
                self.result = result
                return result
            if "mode" in record:
                raise SyqProtocolError(
                    "a cp terminal result may not contain an rm mode field"
                )
            deletion_values = tuple(
                _optional_integer(record, field)
                for field in (
                    "deletions_planned",
                    "deletions_completed",
                    "deletions_blocked",
                )
            )
            provenance = _attested_provenance(record, "result")
            attested = provenance is not None
            if attested:
                # A receipt attests settled deletions (deletions_completed);
                # it cannot vouch for planning or --max-delete blocking, so
                # the other two totals never appear.
                if deletion_values[0] is not None or deletion_values[2] is not None:
                    raise SyqProtocolError(
                        "a receiver-attested result may only contain deletions_completed"
                    )
                if deletion_values[1] is None:
                    raise SyqProtocolError(
                        "a receiver-attested result must contain deletions_completed"
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
            if not attested:
                stray = [
                    field
                    for field in (
                        "receipt_status",
                        "operations",
                        "final_states",
                        "receipt_records",
                    )
                    if field in record
                ]
                if stray:
                    raise SyqProtocolError(
                        "receipt bookkeeping appears on a result without "
                        f"receiver_attested provenance: {stray}"
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
                provenance=provenance,
                receipt_status=(
                    _enum(record, "receipt_status", ReceiptStatus)
                    if attested
                    else None
                ),
                operations=_integer(record, "operations") if attested else None,
                final_states=_integer(record, "final_states") if attested else None,
                receipt_records=(
                    _integer(record, "receipt_records") if attested else None
                ),
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
