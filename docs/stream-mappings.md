# Stream-mapping protocol

Use this subprocess interface when your program supplies or consumes several
byte streams in one `syq cp` process; [Python callback mappings](https://greaber.github.io/syq/python-streams.html#callback-mappings)
use it for you. For a single stream in a shell pipeline, use
[`--src-fd` or `--as-fd`](commands/cp.md#file-descriptors).

## Start a session

Create a connected Unix stream socket pair, pass one end to syq across exec,
and close that end in the parent after spawning:

```sh
syq cp --mapping entries.jsonl --stream-mapping-fd FD \
  --stream-concurrency 8 --results-fd RESULTS_FD \
  --to server --into archives
```

`FD` must be above 2 and differ from the results descriptor.
`--stream-concurrency` sets how many entries are active at once, from 1 to 256
(default 4), separately from network workers. Each entry can have a producer, a
consumer, or both, with its own descriptors. Keep reading the control
connection and results while they run.

The manifest uses the [mapping format](mappings.md), with a stream endpoint in
place of either tagged path:

```json
{"src":{"stream":0},"dst":{"encoding":"utf-8","value":"first.tar"}}
{"src":{"stream":1,"size":1024},"dst":{"encoding":"utf-8","value":"second.bin"}}
```

`stream` is the entry's zero-based line number in the manifest, counting blank
lines, not a descriptor number. An optional source `size` promises the exact
byte count; a mismatch fails the entry before publication. `kind` can be
omitted or `file`. `expected_hash` checks the transferred bytes, and explicit
`metadata` applies to a named destination without `--copy-metadata`.

Syq rejects an invalid manifest before copying anything. Once copying starts,
entries that succeed stay in place when another fails.

## Control framing and version

Every frame contains:

1. The single byte `S`. Read exactly this byte with `recvmsg`, so that
   attached `SCM_RIGHTS` descriptors arrive with it; reading ahead across
   frames can lose a descriptor.
2. A four-byte unsigned big-endian JSON length, from 1 to 65,536.
3. That many bytes of UTF-8 JSON holding one object.

Reject truncated ancillary data and close every descriptor of a rejected
frame. Received descriptors belong to you: mark them close-on-exec promptly,
with `MSG_CMSG_CLOEXEC` on Linux. On macOS, don't start subprocesses between
receiving a descriptor and marking it close-on-exec.

Syq first sends `{"type":"hello","version":1}` without descriptors, and the
client replies `{"version":1}` the same way. Reject an unsupported version
before producing bytes. Syq changes the version for any incompatible change.
Ignore unknown optional JSON fields, but reject unknown message types and
unexpected descriptors. A failed handshake can end without an `end` message, so
still check the process exit and results.

## Entry lifecycle

| Message from syq | Attached descriptors | Meaning |
|---|---|---|
| `{"type":"start","entry":N,"direction":"produce"}` | payload, completion | Write this entry's bytes |
| `{"type":"start","entry":N,"direction":"consume"}` | payload, completion | Read this entry's bytes |
| `{"type":"transferred","entry":N,"error":null}` | none | Byte transfer and requested validation succeeded |
| `{"type":"transferred","entry":N,"error":"..."}` | none | Transfer failed |
| `{"type":"end"}` | none | No further control messages |

Each direction of an entry gets at most one `start`; a skipped or dry-run entry
gets none. Handle each descriptor independently; their numbers are unrelated to
manifest indexes.

A producer writes its payload and closes that descriptor. Only after its work
has succeeded does it write the single byte `C` to the completion descriptor
and close it; EOF without `C` fails the entry. Don't write `C` just because a
buffered writer was closed. Syq publishes a named destination only after the
producer succeeds and the transfer is validated, and sends an upload's
`transferred` after publishing it.

A consumer reads through payload EOF and checks `transferred` before reporting
success: then it closes the payload, writes `C` to completion, and closes that.
A consumer that stops early must drain the rest of the payload so validation
can finish. It may acknowledge before `transferred` only if it publishes
nothing until the whole session succeeds. Syq can't undo a consumer's side
effects, so extract archives into a staging directory.

To fail an entry, close completion without writing `C`. To cancel the whole
session, send SIGTERM to syq so it can remove partly written files and abort
multipart uploads, and keep draining its output while it exits; if your
deadline passes, kill its process group. A lost control connection or payload
EOF never means success. Streams that can't be replayed aren't retried
automatically; regenerate the entry.

## Results and applicable options

Each stream entry gets one [`stream_result`](automation.md#stream_result) in
schema version 5. The session succeeded only when the terminal result and exit
status agree and every expected entry has a result. A failure in your own
processing must fail the caller even after the terminal record.

Placement, preview, existence policies, compression, reporting, transfer
tuning, and resource limits apply. Stream entries can't use a remote
coordinator, `--detach`, a [receiving machine](receive.md) (`@NAME`),
`--in-place`, pruning, tree filters, source metadata policies, content
comparison, or size filters; use an expected hash instead of comparison. These
limits also apply to pathname entries in the same mapping, so run separate
commands when they need different options.
