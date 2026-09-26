"""Shared helpers for the repository's Python tooling (standard library only).

The release, CI-scope, and status scripts read GitHub and registry JSON and
write reports and release metadata. These helpers keep their JSON handling
identical to the jq programs they replaced: numbers keep their literal
spelling, missing object fields read as null, and output uses jq's layout.
"""
import decimal
import hashlib
import json
import re
import subprocess
import sys


class JqError(Exception):
    """A failure that jq reported with an exit status (1 for a false or null
    `-e` result, 4 for no output, 5 for unreadable input or a type error)."""

    def __init__(self, status, message=""):
        super().__init__(message)
        self.status = status


def decoder():
    """A JSON decoder that reads numbers as jq 1.8 does: literals keep their
    value and spelling, NaN is null, and infinities are the largest doubles."""
    constants = {"NaN": None, "Infinity": decimal.Decimal("1.7976931348623157E+308"),
                 "-Infinity": decimal.Decimal("-1.7976931348623157E+308")}
    return json.JSONDecoder(parse_float=decimal.Decimal, parse_int=decimal.Decimal,
                            parse_constant=constants.__getitem__)


def loads(text):
    """Parse one JSON document as jq reads it."""
    text = text.removeprefix("\ufeff")
    start = _skip_whitespace(text, 0)
    if start == len(text):
        raise JqError(4, "no JSON input")
    try:
        value, end = decoder().raw_decode(text, start)
    except json.JSONDecodeError as error:
        raise JqError(5, f"invalid JSON: {error}") from None
    end = _skip_whitespace(text, end)
    if end != len(text):
        # jq would process each document of a stream in turn. No input to these
        # tools legitimately holds more than one, so reject rather than guess.
        try:
            decoder().raw_decode(text, end)
        except json.JSONDecodeError as error:
            raise JqError(5, f"invalid JSON: {error}") from None
        raise JqError(1, "expected a single JSON document")
    return value


def load_stream(text):
    """Every JSON document in a stream such as NDJSON, as `jq -s` reads it."""
    values = []
    index = _skip_whitespace(text, 0)
    while index < len(text):
        try:
            value, index = decoder().raw_decode(text, index)
        except json.JSONDecodeError as error:
            raise JqError(5, f"invalid JSON: {error}") from None
        values.append(value)
        index = _skip_whitespace(text, index)
    return values


def _skip_whitespace(text, index):
    while index < len(text) and text[index] in " \t\n\r":
        index += 1
    return index


def load_file(path):
    with open(path, encoding="utf-8", errors="replace") as source:
        return loads(source.read())


def is_number(value):
    return isinstance(value, (int, float, decimal.Decimal)) and not isinstance(value, bool)


def get(value, *path):
    """Follow a jq path such as `.a.b[0]`: null propagates, a missing field or
    index is null, and indexing another type is jq's error 5."""
    for key in path:
        if value is None:
            continue
        if isinstance(key, str):
            if not isinstance(value, dict):
                raise JqError(5, f"cannot index {kind(value)} with {key!r}")
            value = value.get(key)
        else:
            if not isinstance(value, list):
                raise JqError(5, f"cannot index {kind(value)} with a number")
            value = value[key] if -len(value) <= key < len(value) else None
    return value


def items(value):
    """Iterate like jq's `.[]?`: arrays and object values; nothing otherwise."""
    if isinstance(value, list):
        return list(value)
    if isinstance(value, dict):
        return list(value.values())
    return []


def iterate(value):
    """Iterate like jq's `.[]`, which fails on scalars (null included)."""
    if isinstance(value, (list, dict)):
        return items(value)
    raise JqError(5, f"cannot iterate over {kind(value)}")


def truthy(value):
    return value is not None and value is not False


def alt(value, default):
    """jq's `value // default`."""
    return value if truthy(value) else default


def require(value):
    """jq -e: a null or false result fails with status 1."""
    if not truthy(value):
        raise JqError(1, "required value is null or false")
    return value


def kind(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if is_number(value):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def order(value):
    """A sort key for jq's ordering: null < false < true < numbers < strings
    < arrays < objects."""
    if value is None:
        return (0,)
    if value is False:
        return (1,)
    if value is True:
        return (2,)
    if is_number(value):
        return (3, value)
    if isinstance(value, str):
        return (4, value)
    if isinstance(value, list):
        return (5, [order(item) for item in value])
    return (6, sorted(value), [order(value[key]) for key in sorted(value)])


def number_text(value):
    if isinstance(value, float):
        value = decimal.Decimal(repr(value))
    return str(value)


def string_text(value):
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


def dumps(value, indent=None, sort_keys=False):
    """Serialize like jq: `indent=2` matches its default output and `None`
    matches `-c`. No trailing newline."""
    def encode(value, level):
        if value is None:
            return "null"
        if value is True:
            return "true"
        if value is False:
            return "false"
        if is_number(value):
            return number_text(value)
        if isinstance(value, str):
            return string_text(value)
        if isinstance(value, dict):
            keys = sorted(value) if sort_keys else list(value)
            if not keys:
                return "{}"
            separator = ": " if indent else ":"
            members = [string_text(key) + separator + encode(value[key], level + 1) for key in keys]
            return wrap("{", members, "}", level)
        if isinstance(value, (list, tuple)):
            if not value:
                return "[]"
            return wrap("[", [encode(item, level + 1) for item in value], "]", level)
        raise TypeError(f"cannot serialize {type(value).__name__}")

    def wrap(opening, members, closing, level):
        if not indent:
            return opening + ",".join(members) + closing
        inner = "\n" + " " * (indent * (level + 1))
        return opening + inner + ("," + inner).join(members) + "\n" + " " * (indent * level) + closing

    return encode(value, 0)


def json_text(value):
    """jq's default output of one result, without its newline."""
    return dumps(value, indent=2)


def text(value):
    """jq -r rendering of one result, without its newline."""
    return value if isinstance(value, str) else dumps(value, indent=2)


def captured(value):
    """The value of `$(jq -r ...)`: command substitution drops trailing newlines."""
    return text(value).rstrip("\n")


def test(value, pattern):
    """jq's `test(pattern)`: Perl-style search in which `$` also matches before
    a final newline, as with Python's re without MULTILINE."""
    if not isinstance(value, str):
        raise JqError(5, f"{kind(value)} cannot be matched, as it is not a string")
    return re.search(pattern, value) is not None


class CommandFailed(Exception):
    """A command failed; the caller exits with its status, as `set -e` did."""

    def __init__(self, status):
        super().__init__(f"command failed with exit status {status}")
        self.status = status


def command(*args, **kwargs):
    """stdout of a command that must succeed, as `$(command)` under `set -e`.
    Pass stdout=None to let the command write to this process's stdout."""
    kwargs.setdefault("stdout", subprocess.PIPE)
    if kwargs["stdout"] is None:
        sys.stdout.flush()
    completed = subprocess.run(list(args), text=True, **kwargs)
    if completed.returncode:
        raise CommandFailed(completed.returncode)
    return completed.stdout


def command_json(*args, **kwargs):
    return loads(command(*args, **kwargs))


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def cargo_version(path):
    """The first `version = "..."` line, as `sed -n 's/^version = "\\(.*\\)"/\\1/p'
    | head -1` extracts it; empty when there is none."""
    with open(path, encoding="utf-8", errors="surrogateescape") as source:
        for line in source.read().split("\n"):
            match = re.match(r'version = "(.*)"', line)
            if match:
                return match.group(1) + line[match.end():]
    return ""


def awk_fields(value, *numbers):
    """awk's `{print $N " " $M}` over each line of `value` (a here-string), as
    `$(...)` captures it: fields split on blanks and tabs."""
    lines = []
    for line in value.split("\n"):
        fields = [""] + [field for field in re.split(r"[ \t]+", line) if field]
        lines.append(" ".join(fields[number] if number < len(fields) else "" for number in numbers))
    return "\n".join(lines).rstrip("\n")


def exit_on_failure(main):
    """Run `main`, turning command and jq failures into their exit status."""
    try:
        return main()
    except CommandFailed as error:
        return error.status
    except JqError as error:
        if str(error):
            print(f"jq: error: {error}", file=sys.stderr)
        return error.status


def comma_fields(value):
    """Bash's `IFS=, read -ra fields`: a final empty field is dropped."""
    fields = value.split(",")
    return fields[:-1] if fields[-1] == "" else fields


def check_conclusion(check_runs, name):
    """The latest conclusion of the named check run in a GitHub check-runs
    response: `missing` when absent and `pending` while incomplete."""
    runs = [run for run in iterate(get(check_runs, "check_runs")) if get(run, "name") == name]
    runs.sort(key=lambda run: order([alt(alt(get(run, "started_at"), get(run, "completed_at")), ""),
                                     alt(get(run, "id"), 0)]))
    if not runs:
        return "missing"
    return captured(alt(get(runs[-1], "conclusion"), "pending"))


def join(values, separator):
    """jq's `join(separator)`: null joins as empty text, and numbers and
    booleans as their JSON text."""
    parts = []
    for value in iterate(values):
        if value is None:
            parts.append("")
        elif isinstance(value, (str, bool)) or is_number(value):
            parts.append(text(value))
        else:
            raise JqError(5, f"cannot join {kind(value)}")
    return separator.join(parts)
