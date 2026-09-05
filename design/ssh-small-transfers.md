# SSH startup and small-copy measurements, 2026-09-05

The implementation measured here is `ae93e4b` (PR #217), based on master
`1704425`. The baseline is the published Linux x86-64 v0.3.1 executable
(release commit `2903fd8`), checked against its published SHA-256 file.
These are observations from one development-host-to-`j5` route, not a general
performance guarantee or a reproduction of the reporter's Mac network.

## Failure diagnosis

The reported Mac persistence scope was 71 bytes long. Appending the 20-byte
endpoint socket component produces a 91-byte control path. OpenSSH appends a
dot and 16 random characters before binding that socket; the temporary name
therefore needs 108 bytes plus its terminating NUL. It exceeds both Darwin's
104-byte `sockaddr_un.sun_path` and Linux's 108-byte buffer. See
[OpenSSH's socket creation](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/mux.c#L1260-L1327).

A direct real-SSH reproduction used a disposable 91-byte control path under
`/tmp`, `ControlMaster=yes`, and `ControlPersist=no` to run `true` on `j5`.
After authentication, OpenSSH reported that the temporary socket path was too
long and returned 255. This confirms the defect; the original report did not
include SSH's underlying diagnostic, so it does not independently establish
that every reported exit 255 had this cause.

A separate immediate-failure shell stub isolated syq's retry policy. v0.3.1
invoked it six times and returned in 6.210 seconds; the candidate invoked it
once and returned in 0.003 seconds. Both returned failure and preserved the
stub's stderr. The old backoff alone was 0.2 + 0.4 + 0.8 + 1.6 + 3.2 = 6.2
seconds. Actual connection failures add their own SSH runtime.

The implementation checks the complete socket budget before spawning SSH,
uses a short default runtime parent on macOS, and limits initial control
connection setup to one attempt. Concurrent worker admission retains its
existing retry policy. `SYQ_DEBUG` enables ordinary SSH startup diagnostics;
signed receiver commands are excluded because they contain authorization
material.

## Small-file method

The payload was one 5,992-byte random regular file. Each destination was seeded
with `scp -p` so the timed syq invocations performed an unchanged-file copy,
matching the original report. The comparison used native
`syq cp work.md --to j5 --into DEST --syq-path BINARY --no-progress` and
`scp -q -p work.md j5:DEST/work.md`. Every command was timed from process
startup to exit, with debug logging disabled. There were five repetitions per
case; syq order alternated. Scp retransmitted the file every time.

Both syq binaries were staged under a unique disposable remote directory.
Bootstrap and binary upload were excluded from timing. Persistence used
separate ephemeral scopes for each binary, with one untimed command to start
each scope's connection and helper pool. The cold runs used an isolated empty
configuration. The scopes were closed and the remote fixtures removed afterward.

The candidate was built in the repository's pinned `rust:1.94.1-bookworm`
container with `cargo build --locked --release --bin syq`, using the source
inputs of `ae93e4b`. Its container build identity was
`v0.3.1+dev.source.1788620104836502161` and its binary SHA-256 was
`ef8ff0b753f61eb66e3443f97da40247ca709c4b78024bb8ee7975c868e5859d`.
The baseline binary SHA-256 was
`211739bb05f75049bcfeeba5f3499039dc2eca498be26d88125996215934cfef`.
A host-built candidate could not run on `j5` because it required glibc 2.39;
that failed attempt supplied no performance samples.

## Results

| Executable | Persistence | Median | Range |
|---|---|---:|---:|
| baseline | off | 7.169 s | 7.149–7.316 s |
| candidate | off | 5.600 s | 5.518–5.763 s |
| scp | off | 7.220 s | 7.118–7.290 s |
| baseline | on | 1.924 s | 1.923–1.926 s |
| candidate | on | 0.319 s | 0.318–0.843 s |

The candidate reduced the unchanged-file median by about 22% with fresh SSH
setup and 83% with persistence. Warm candidate times clustered near 0.32 s
and 0.84 s. The slower samples immediately followed another candidate command;
this is consistent with waiting for the pool's replacement session, though
this campaign did not trace individual packets or pool events.

No TCP-fallback warning appeared on this development-host route. These numbers
therefore do not quantify the additional benefit of skipping unreachable TCP
probes on the reporter's route. The real-SSH container suite separately checks
that fresh, unchanged, and updated small native pushes skip TCP setup, while
its larger-transfer cases still exercise firewall-triggered SSH fallback.

The bounded path sends the small source contents in the control request, even
when the receiver quick-checks the file as unchanged. It avoids data transport
setup and destination rewrites; it does not claim zero network payload. Bounds
remain 64 explicit regular files, 1 MiB per file and 4 MiB total. Directory
sources, missing destination directories, non-file targets, restricted
receivers, and ineligible options continue through the general engine.
