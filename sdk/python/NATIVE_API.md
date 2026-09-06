<a id="python-native-api"></a>

<a id="positioning"></a>

<a id="scope"></a>

<a id="product-readiness"></a>

# API reference

Module functions `syq.cp`, `syq.rm`, and `syq.map` use a default `Client`.
`AsyncClient` has the same arguments and result types; await its operations
except `map`, which returns an async context manager.

<a id="synchrony-asyncio-and-resource-ownership"></a>

<a id="compatibility-and-versioning"></a>

## Client and executable selection

`Client(*, executable=None, cache_dir=None, process_cwd=None, env=None, timeout=None)`
and `AsyncClient(...)` accept:

| Argument | Meaning |
|---|---|
| `executable` | Custom executable path, or name to find on `PATH`; default: managed syq |
| `cache_dir` | Managed executable cache root |
| `process_cwd` | Local subprocess working directory; default: inherit |
| `env` | Subprocess environment mapping; default: inherit |
| `timeout` | Operation timeout in seconds; default: no limit |

`client.version()` returns the executable version as text.
`syq.version(executable=None)` does the same without a client.
`syq.managed_executable(cache_dir=None)` returns the verified executable path,
downloading it if needed. See
[Compatibility](https://greaber.github.io/syq/sdk-compatibility.html) for version
selection and caching.

<a id="the-native-vocabulary-is-the-python-vocabulary"></a>

## Arguments and validation

Options use CLI names with hyphens replaced by underscores. Python keywords
get a trailing underscore: `from_`, `as_`. Paths accept `str`, `bytes`, or
`os.PathLike`; selector keywords accept one path or an iterable of paths.
Use `src=["a", "b"]` for CLI `--srcs a b`, and likewise `src_file` and `src_dir`.

| Shared by `cp`, `rm`, and `map` | Meaning |
|---|---|
| `*sources`, `src` | Select named objects |
| `srcs_in` | Select a directory's contents |
| `src_file`, `src_dir` | Require non-directory objects or directories |
| `cwd` | Source resolution base; may be remote for `cp` and `rm` |
| `root` | Confine source resolution beneath this directory; requires relative selectors; conflicts with `cwd` |
| `follow`, `follow_src` | Follow source symlinks; `follow` also enables destination following for `cp` |
| `timeout` | Override the client timeout in seconds; `None` uses the client default |

Boolean flags default to `False`; other optional arguments default to `None`,
except `check=True`. Invalid argument combinations raise `SyqInvocationError`;
filesystem and remote checks happen in syq.

<a id="a-normal-copy"></a>

<a id="copy-and-prune"></a>

<a id="dry-runs"></a>

## cp

`cp(*sources, **options) → CpResult` copies files. Choose one placement option.
In addition to the shared arguments above, it accepts:

| Options | Values / purpose |
|---|---|
| `from_`, `to` | SSH endpoint strings; omitted endpoints are local |
| `into`, `into_new`, `into_existing` | Destination directory paths |
| `as_`, `as_new`, `as_existing` | Exact destination paths |
| `mapping` | Manifest path or iterable of `MappingEntry`; replaces selectors; conflicts with `as_*` and `prune` |
| `follow_dst` | Boolean: follow destination symlinks |
| `prune`, `dry_run`, `hash`, `verify_only` | Boolean: mirror, preview, compare content, or verify without copying |
| `ignore_existing`, `existing`, `update` | Boolean: skip existing, require existing, or skip newer destination files |
| `ignore` | Pattern string, `IgnoreFrom(path)`, or ordered iterable of either |
| `ignore_from` | Rule file path or iterable of paths; applied after `ignore` |
| `preserve` | Preservation string or iterable of strings |
| `inplace`, `no_compress` | Boolean: update destination files in place or disable compression |
| `bwlimit`, `min_size`, `max_size` | Native rate/size strings or integers |
| `max_delete` | Nonnegative integer deletion limit; requires `prune=True` |
| `connections` | Positive integer connection count |
| `auth_from`, `via` | Credential source string; aliases, so use only one |
| `coordinate_at`, `rsh`, `peer_auth` | Coordinator, SSH command, and peer authentication strings |
| `pscope`, `syq_path` | SSH persistence scope path and remote executable path |
| `no_bootstrap`, `tcp_plain`, `no_tcp` | Boolean remote/transport controls |
| `tcp_ports`, `tcp_congestion` | Port range and congestion-control strings |
| `receiver_max_entries`, `receiver_max_bytes` | Receiver ceilings: integer entries, native size string or integer bytes |
| `receiver_receipt` | `"sizes"` or `"digests"` |
| `on_event`, `results`, `check` | See events and failures below |

Option behavior is covered in [Copy files](https://greaber.github.io/syq/reference.html)
and [Remote copy details](https://greaber.github.io/syq/remote-reference.html).
Typed remote-to-remote copies require an enrolled receiver or
`coordinate_at="local"`. With `dry_run=True` or `verify_only=True`, they require
`coordinate_at="local"`. Use `run` for detached commands and human output options.

To interleave rule files and inline patterns:
`ignore=[syq.IgnoreFrom("rules"), "!keep.tmp"]`. The last matching rule wins.

## Removal

`rm(*sources, **options) → RmResult` removes selected entries. Besides the shared
arguments, it accepts `from_`, `dry_run`, `connections`, `syq_path`,
`no_bootstrap`, `pscope`, `on_event`, `results`, and `check` with the types above.
It supports local and ordinary SSH endpoints. Command-restricted receivers
reject removal. See [Remove files](https://greaber.github.io/syq/remove.html).

<a id="complete-input-guarantee"></a>

## Mapping, transformation, and copy

`map(*sources, **options) → MapStream` lists local mapping entries without
copying. Besides the shared arguments, it accepts `as_` to rename a selected
object. `srcs_in` must be the sole selector when used.

| Type / member | Meaning |
|---|---|
| `MapStream` | Iterable context manager yielding `MappingEntry`; use `with` |
| `AsyncMapStream` | Async iterable context manager; use `async with` |
| `mapping.cwd` | Absolute source-base spelling to pass unchanged to `cp(cwd=...)` |
| `MappingEntry(src, dst, kind=None, size=None, mtime=None)` | Frozen dataclass; `src` and `dst` are `RelativePath`; size and mtime are informational |
| `EntryKind` | `FILE`, `DIR`, `SYMLINK`, or `SPECIAL` |
| `RelativePath(value)` | Mapping-relative path from text, bytes, or a path-like object; `/` joins components; `.raw` gives bytes; `.text` decodes UTF-8 strictly |
| `PathValue` | Event path; `.raw` gives bytes, `.text` decodes UTF-8 strictly, `.display` provides readable text |

Normal end of iteration checks the mapping process status. Leaving the context
early stops the process. Pass `mapping.cwd` through without normalizing it.
A consuming copy resolves that path again; `map(root=...)` does not transfer its
confinement to the copy. Pass `follow_src=True` to both calls when the source
base requires following symlinks.

For `cp(mapping=iterable)`, the entire iterable is saved to a temporary manifest
before copying starts. An iteration or serialization failure starts no copy.
`AsyncClient.cp` also accepts async iterables. Passing a manifest path uses that
file directly. See [mapping rules](https://greaber.github.io/syq/mappings.html).

<a id="retry-data-not-automatic-retry-policy"></a>

## Events and terminal results

`cp` and `rm` return frozen dataclasses after validating the complete results
stream and process exit status. A truncated stream raises even if the process
exits successfully. Dry runs return the same types, with planned totals.

| Result | Attributes |
|---|---|
| Both | `status`, `exit_code`, `dry_run`, `errors`, `elapsed_ms`, `schema`, `schema_version`, `seq`, `type` |
| `CpResult` | `files_transferred`, `files_unchanged`, `files_excluded`, `directories_created`, `symlinks_created`, `specials_created`, `bytes_transferred`, `bytes_unchanged` |
| Copy deletion totals | `deletions_planned`, `deletions_completed`, `deletions_blocked`; `None` when inapplicable |
| Receiver-attested copy fields | `provenance`, `receipt_status`, `operations`, `final_states`, `receipt_records`; `None` on ordinary results |
| `RmResult` | `selectors_total`, `selectors_resolved`, `selectors_missing`, `entries_planned`, `entries_removed`, `entries_already_absent`, `entries_failed`, `mode` |

`status` is `OperationStatus.SUCCESS`, `PARTIAL`, `REFUSED`, `ABORTED`, or `FAILED`.
Ordinary prune results have all three deletion totals; receiver-attested
results have only `deletions_completed`.

`on_event(event)` receives an `AutomationEvent` in stream order. Events are not
stored in the result. `AsyncClient` accepts synchronous or awaitable callbacks;
awaitable callbacks count toward the timeout.

| Event types | Content |
|---|---|
| `RunEvent`, `ProgressEvent` | Run description and sampled progress |
| `TraceEvent`, `OperationResult` | Planned or completed copy operation |
| `SelectionResult` | Removal selector resolution |
| `RemovalTrace`, `RemovalResult` | Planned removal or settled entry, including preview inspection failures |
| `ErrorEvent` | Diagnostic |
| `FinalStateEvent` | Receiver-attested final object state |
| `CpResult`, `RmResult` | Terminal totals |

See [Automation results](https://greaber.github.io/syq/automation.html) for field
meanings. Python exposes `class` as `class_`, paths as `PathValue`, and enum
values as string enums.

`results=` accepts a binary file-like object with `write(bytes)` returning a
positive byte count for nonempty writes, and optional `flush()`. The client
copies validated NDJSON records, flushes after completion, and leaves it open.
It withholds the terminal record if stream validation, process completion, or
a callback fails. Sink failures raise and abort the operation.

`OperationResult.is_retryable` identifies retryable failures; `retry_entry()`
returns a `MappingEntry` when a complete mapping identity is available, otherwise
`None`. Only use collected entries after the call returns a validated `success`
or `partial` result. A terminal callback alone does not establish completion.
The client does not retry automatically.

## Failure model

| Exception | Meaning / useful attributes |
|---|---|
| `SyqInstallError` | Managed executable installation or verification failed |
| `SyqInvocationError` | Invalid Python arguments |
| `SyqOperationError` | Typed operation was unsuccessful; `.result` and `.stderr` (last 8 KiB) |
| `SyqProtocolError` | Invalid, unsupported, inconsistent, or incomplete results; `.returncode`, `.stderr` |
| `SyqProcessError` | Raw `run` exited nonzero; `.result` contains complete output |
| `SyqOutputError` | A helper such as `version()` received unexpected output |

For `cp` and `rm`, `check=False` returns unsuccessful typed results; for `run`,
it returns nonzero process results. It does not suppress other errors.
Spawn failures and timeouts use standard Python exceptions. Callback exceptions
are re-raised after stopping the operation.

Timeout, cancellation, early mapping exit, and streaming failures terminate and
reap the local process group, including SSH children. Filesystem changes already
completed are not rolled back.

<a id="deliberate-exclusions"></a>

## Raw execution

`client.run(args, *, check=True, cwd=None, env=None, timeout=None, input=None)`
returns `Result(argv, returncode, stdout, stderr)`. `stdout` and `stderr` are
fully captured bytes; `input` accepts bytes. `args` is a sequence of arguments
after the executable name, passed without a shell.

Here, `cwd` is the local subprocess directory. `cwd`, `env`, and `timeout`
use the client defaults when omitted or `None`. Module-level `syq.run` takes
the same arguments plus `executable=None`.
