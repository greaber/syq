# Real-SSH integration tests

This local-only suite runs the candidate syq build through live OpenSSH clients
and servers. Docker Compose creates three containers on an internal network:

```text
runner --SSH--> source --SSH--> destination
   |                              ^
   +----------- enrollment ------+
```

The source and destination have separate filesystems, homes, host keys, sshd
processes, and network namespaces. The runner generates a new test-only client
key for every invocation. Only its public key enters the endpoint containers;
the source has no independent destination credential. A successful default
direct transfer therefore exercises syq's constrained forwarded-agent path.
The destination's network namespace also rejects one dedicated TCP port with a
real firewall rule; a transfer aimed at that port must automatically fall back
to SSH data connections.

Run the suite from any syq checkout:

```sh
scripts/test-real-ssh.sh
```

The host runner requires Bash 4 or newer. In particular, the Bash 3.2 shipped
with macOS is not supported; install a current Bash and invoke the script with
it when running the lab on macOS.

Use the alternate destination sshd profile to exercise syq's fallback from a
rejected multiplexed worker channel to independent SSH connections. The
profile keeps every fixture file below syq's 4 MiB multiplexing threshold and
requires evidence of both a rejected real OpenSSH multiplexed attempt and a
successful `ControlPath=none` retry:

```sh
scripts/test-real-ssh.sh --profile max-sessions-1
```

OpenSSH normally hides this condition by opening an independent connection
inside the original client process. In this profile, the test's thin `ssh`
wrapper gives only multiplexed destination workers a failing `ProxyCommand`.
The live control socket is still tried over real SSH, but OpenSSH's internal
fallback returns 255 so syq must issue the independently authenticated retry.
All successful connections continue to run through `/usr/bin/ssh`.

The first build downloads the pinned Rust toolchain image, Debian packages, and
Cargo dependencies. Test execution itself uses only the Compose project's
internal Docker network: no ports are published and no real SSH configuration,
agent, keys, homes, or remote hosts are used. The destination service alone gets
`NET_ADMIN`, solely to install the test's port-specific firewall rule.

Endpoint helper caches start empty. The suite copies a file to each endpoint
using the source build, exercising automatic executable upload over real SSH
before the remaining scenarios reuse those helpers.

The source sshd permits remote Unix socket forwarding for named return transfers
(OpenSSH 9.2 also requires remote TCP forwarding permission). The destination
keeps forwarding disabled. The runner has no SSH server. Return scenarios cover
copies from independent source shells without a forwarded agent, destination
background startup through persistence, `--root` traversal refusal, unconfined
`--cwd` paths, conflicting names, reconnection after killing the owned SSH
transport, and stopping receiving with persistence. Approval cases cover local
allow/deny, one-use IDs, disconnect and settings cancellation, and explicit
automatic approval. An isolated D-Bus notification service exercises the real
Linux `notify-send` client with Allow, Deny, dismissal, unexpected actions, and
service failure; only Allow starts a copy. This does not exercise a particular desktop's visual
layout or the macOS dialog.

The smoke suite also checks that pooled helpers keep the spawning command’s
`SendEnv` values, while direct sessions and restarted persistence use the new
values. A remote wrapper records one test variable and executes the candidate
helper, so the check exercises real OpenSSH environment forwarding.

The smoke suite currently covers rejection of a restricted destination that
overlaps the receiver's SSH control plane, source-side direct coordination with
automatic restricted-destination enrollment over encrypted TCP, source-side
coordination with constrained authentication, firewall-triggered TCP fallback,
explicitly selected SSH data channels, destination-side coordination through
the reversed constrained-agent edge, and an explicit local relay. Every path
uses real SSH for control and bootstrap, and the suite compares the complete
source and destination manifests afterward.

Range-transfer checks also copy a large file with a 64-request pipeline and
2 MiB requests with average bandwidth pacing over TCP and SSH, then through
source, destination, and local coordinators. Batch overrides also run through
a restricted receiver. Each result is compared byte for byte with the original.

This suite is intentionally outside `cargo test` and CI. Run it after changing
SSH, remote-helper, enrollment, restricted-receiver, transport, or remote
topology behavior, and before cutting a release. For release preparation, use
`scripts/release-readiness.py v<version> --check-ssh` after committing: it records
successful default-profile validation for the complete clean tree, reusable
across an identical-tree merge. See `RELEASING.md` for the evidence rules.
A failure retains public logs
under `target/real-ssh.*`; the ephemeral private key is always removed.

The default suite also runs interactive Bash, Zsh, and fish completion checks
in disposable PTYs. They verify that the detail view shows metadata while
completion inserts only the pathname. To run the Bash check locally:

```sh
python3 tests/real-ssh/test-completion-display.py --syq target/debug/syq
```

The shell dependencies are installed only in the test image.

The source-shell remote-copy checks use `--via @laptop` without a source key or
agent. They cover local approval despite automatic local receiving, denial,
direct TCP, cached and missing helper startup, a second approval during slow
SSH setup, preview/verification, protected destination authority files,
unreachable data ports, and revocation followed by an approved retry.

The suite also runs the standalone interactive benchmark in noninteractive
push and pull modes, with both synthetic workloads and scratch paths containing
spaces and quotes. These are correctness and cleanup checks using the lab's
debug binary, not performance measurements.

A cancellation case waits for an active remote partial file, interrupts the
benchmark, and checks that scratch is removed while an unrelated file remains.
