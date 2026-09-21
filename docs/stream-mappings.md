# Stream-mapping protocol

A program can supply or consume several byte streams in one `syq cp` process.
Entries share transfer connections and resource limits. This is the subprocess
interface used by [Python callback mappings](https://greaber.github.io/syq/python-streams.html#callback-mappings).
Ordinary shell pipelines use [`--src-fd` or `--as-fd`](commands/cp.md#file-descriptors).

## Start a session

Create a connected Unix stream socket pair. Pass one end to the child, keeping
it open across exec, and close that end in the parent after spawning. Start:

```sh
syq cp --mapping entries.jsonl --stream-mapping-fd FD \
  --stream-concurrency 8 --results-fd RESULTS_FD \
  --to server --into archives
```

`FD` must be greater than 2 and distinct from the results descriptor. These
programmatic options are hidden from help. `--stream-concurrency` defaults to
4 and accepts 1–256 active entries. Each entry can have a producer, a consumer,
or both. Payload bytes use separate descriptors; they never enter JSON messages.
Drain the control connection and results while producers and consumers run.

The manifest uses the [existing mapping format](mappings.md), extended with a
stream endpoint in place of either tagged pathname:

```json
{"src":{"stream":0},"dst":{"encoding":"utf-8","value":"first.tar"}}
{"src":{"stream":1,"size":1024},"dst":{"encoding":"utf-8","value":"second.bin"}}
```

`stream` is the zero-based physical line index, not an OS descriptor number.
Blank lines still count toward indices. An optional source `size` promises the
exact byte count; a mismatch fails the entry before publication. `kind` can be
omitted or `file`. `expected_hash` checks the transferred bytes. Explicit
`metadata` applies to a named destination without requiring `--preserve`.

Syq reads and validates the whole manifest before copying. This catches malformed
entries, duplicate destinations, and conflicts with declared file kinds. As with
pathname mappings, actual source kinds are checked during execution. Ordinary
pathname entries run first, followed by stream entries; mixed batches therefore
have a separate endpoint setup for each phase. Already successful entries are
not rolled back when another entry fails.

## Control framing and version

Every frame contains:

1. The single byte `S`, received with `recvmsg` so attached `SCM_RIGHTS`
   descriptors are collected with this byte.
2. A four-byte unsigned big-endian JSON byte length, between 1 and 65,536.
3. That many UTF-8 JSON bytes, containing one object.

Read exactly one byte with `recvmsg`, then read the length and body normally.
Do not read ahead across frame boundaries: that could lose an attached descriptor.
Reject truncated ancillary data and close every descriptor on rejected frames.
Received descriptors belong to the client; mark them close-on-exec promptly.
Linux clients can use `MSG_CMSG_CLOEXEC`. On macOS, avoid launching subprocesses
concurrently with receiving and marking descriptors.

Syq first sends `{"type":"hello","version":1}` without descriptors. The client
replies `{"version":1}` using the same framing, also without descriptors. Reject
unsupported versions before producing bytes. Version 1 is the contract for this
interface; incompatible changes require a different version. Clients should
ignore unknown optional JSON fields, but reject unknown message types or
unexpected attached descriptors. A failed handshake may end without an `end`
message; the process exit and results still need checking.

## Entry lifecycle

| Message from syq | Attached descriptors | Meaning |
|---|---|---|
| `{"type":"start","entry":N,"direction":"produce"}` | payload, completion | Write this entry's bytes |
| `{"type":"start","entry":N,"direction":"consume"}` | payload, completion | Read this entry's bytes |
| `{"type":"transferred","entry":N,"error":null}` | none | Byte transfer and requested validation succeeded |
| `{"type":"transferred","entry":N,"error":"..."}` | none | Transfer failed |
| `{"type":"end"}` | none | No further control messages |

Each selected direction starts at most once. A skipped or dry-run entry has no
`start` message. Its outcome appears in the results stream. Descriptors are
independent streams and may be processed concurrently. Their numeric values are
chosen by the receiving OS, unrelated to the manifest index.

A producer writes and closes its payload descriptor. Only after its work has
succeeded does it write the single byte `C` to its completion descriptor and
close it. EOF without `C` fails the entry. Syq publishes a named destination
only after producer success and transfer validation; upload `transferred`
arrives after publication. Closing a buffering wrapper alone must not authorize
publication.

A consumer reads through payload EOF and checks `transferred` before reporting
success. On success, close the payload, write `C` to completion, and close
completion. A consumer that returns early must drain the remaining payload to
allow validation to finish. A consumer may acknowledge its own processing before
`transferred` if it postpones publishing any output until the complete session
succeeds. A stream-to-stream entry reports `transferred` after producer success
and before waiting for consumer acknowledgement. Syq cannot undo a consumer's
side effects; extract archives into a staging directory.

A client-side failure closes completion without `C`. To cancel the entire
session, send SIGTERM to the coordinator, allowing it to abort staged files and
multipart uploads. Continue draining outputs while it exits; a caller's deadline
may require killing its subprocess group. Neither lost control connections nor
payload EOF establishes successful completion. Non-replayable streams cannot be
automatically retried: the caller must regenerate the entry.

## Results and applicable options

Use [automation schema version 3](automation.md). Each stream entry has one
`stream_result` with its index and outcome. Successful completion requires the
terminal result and process status to agree, and all expected entry results to
be present. Entry errors can yield a partial result and exit 23. Setup errors
may terminate before all entries have results. Application-level failures must
also fail the caller even if it has already consumed a terminal record.

Placement, preview, existence policies, compression, reporting, transfer tuning,
and resource limits apply. Stream entries share limits across endpoint sessions;
`--stream-concurrency` limits archive jobs separately from network workers.

Streams run on the invoking machine. Remote coordinator placement, detached
execution, and named receiver grants are unavailable for these entries: they
cannot inherit the caller's live stream, and named grants authorize pathnames.
`--inplace` cannot provide publication after producer success. Pruning and tree
filters require a source tree; select entries in the calling program. Source
metadata policies require actual source attributes; generated streams have none.
Content comparison and size filters are unavailable in a stream-mapping batch;
use a known expected hash or select promised sizes in the caller. These
restrictions also apply to pathname entries in a mixed batch; use separate calls
when their options differ.
