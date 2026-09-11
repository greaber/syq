# Remote copy reference

For the usual setup and copy commands, start with
[Copy between servers](remote-to-remote.md).

## SSH configurations

Host-certificate-only trust, `KnownHostsCommand`, and `RevokedHostKeys` are
unsupported by the broker. Custom known-hosts paths must be unambiguous:
one absolute, whitespace-free filename per configured user/global directive.
The default known-hosts file list works. Syq reports unsupported configurations
instead of relaxing host verification.

Your local SSH configuration selects hostB's login, address, port, and trusted
host keys. HostA's SSH configuration does not override those choices.

## Enrollment

Enrollment needs normal command authority on the destination during setup.
Use a real directory, not a symlink. Transfers cannot overwrite the receiver's
SSH configuration, programs, or enrollment state. Manage that state with
`syq receiver` commands; it is not a disposable cache.

Repeating `enroll` updates the receiver to match your local build. A pending
enrollment can be retried or revoked. Revoke and enroll again to rotate its
receipt key. Revocation stops active receivers before removing their state;
see [access management](remote-to-remote.md#first-copy-and-access-management)
for interruption and retry behavior.

Stop active copies before upgrading: replacing the executable does not update
running receivers. Repeat `syq receiver enroll hostB:/destination` afterward
to refresh the installed receiver. Compatible enrollment keys and replay records
are preserved. Different client builds cannot share one installed receiver
concurrently; each needs a matching receiver.

An incompatible enrollment requires fresh setup, which needs ordinary SSH
access. Eligible copies install it automatically, or you can use `enroll`.
Incompatible old enrollments are not listed or removed by the new build;
they require manual cleanup on both machines.

Enrollment detects the destination platform and installs a matching executable.
Source builds require compatible platforms; `--syq-path` does not select the
restricted receiver. See [Developing syq](development.md#direct-server-to-server-copies)
for testing source builds.

## Limits and unsupported options

Default limits are 100 million entries and 8 TiB of file data. Override them
for one transfer with `--receiver-max-entries N` and
`--receiver-max-bytes SIZE`. Values can raise or lower the defaults within the
allowed ranges. The transfer must start within 24 hours of authorization and
finish within seven days of authorization.

| Option or combination | Restricted receiver |
|---|---|
| `--no-tcp` | Use SSH workers directly from source to destination |
| `--tcp-congestion` | The receiver enforces the algorithm authorized for TCP |
| `--tcp-plain` | Unsupported; data connections must be encrypted |
| `--mapping` | Listed destinations and necessary parent creation are authorized |
| `--skip-newer` | Timestamp selection uses source-reported modification times |
| `--min-size` | Unsupported |
| `--max-size` with `--prune` | Unsupported |
| Fixed `--connections` above 64 | Unsupported |
| `--inplace` with `--as-new` | Unsupported |
| `--detach` | Unsupported; the local broker must remain attached |
| Native `rm` | Unsupported; use a normal SSH login |

Restricted copies use encrypted TCP when reachable and otherwise use SSH
workers from the source to the destination. Both transports share the same
copy authorization, limits, revocation, and signed receipt. A failed direct
connection never selects a relay through your machine; choose
`--coordinate-at local` explicitly to send data through it.

## Signed results

The destination signs a receipt and your machine verifies it before reporting
results. Use `-v` for totals or `--results FILE` for
[automation](automation.md). These results arrive after verification, rather
than as live per-file progress. For `--dry-run --results`, use
`--coordinate-at local` to get the preview stream.

`--receiver-receipt digests` adds BLAKE3 hashes of affected regular files.
Receipts allow up to four million records and 512 MiB of plaintext. Reaching
a cap stops further changes and reports an incomplete outcome.

A receipt does not prove that the source supplied every intended file or the
right contents. See the [threat model](security.md#a-compromised-source-server).

## Other authentication modes

| Option | Authority available to the coordinating server |
|---|---|
| `--peer-auth own-credentials` | Credentials already on that server |
| `--peer-auth broker` | Your full destination-account authority, limited to that host and user |
| `--peer-auth full-agent` | Ordinary, unrestricted agent forwarding |
| `--rsh COMMAND` | Whatever your supplied SSH command permits |

To make hostB pull from hostA using credentials already on hostB:

```sh
syq cp --coordinate-at dst --peer-auth own-credentials --from hostA data --to hostB --into /archive
```

There is no restricted source receiver, so direct pulls require one of these
alternatives to the default authentication.

## Detached copies

`--detach` leaves the copy running after your command exits. It requires
`--peer-auth own-credentials` or an explicit `--rsh` policy, so the coordinating
server can authenticate independently. It cannot use the restricted receiver
or `--results`.

Save the reported remote log location. The log is not a signed receipt.
If printing the location fails, the command reports an error but the job may
still be running. The coordinating server needs `/bin/kill` and either
`setsid` or `perl`.

## Authorization selection

For `syq cp` with local sources and an SSH destination, `--auth-from auto`
tries live receiving machines in alphabetical order, allowing up to two seconds
for each reply. Offline or unsupported connections are skipped. With none
available, or with unsupported options, it uses the source machine's SSH access.
Once approval is requested, refusal or failure ends the attempt.

`--auth-from @NAME` and its alias `--via @NAME` require that receiving machine
to authorize the copy. `--auth-from ssh` uses the source machine's SSH access.
These options choose authorization, not the destination: `--to host` names an
SSH destination, while `--to @NAME` sends files to a receiving machine.


Authorization through a receiving machine does not support `--detach`, custom
`--rsh` or `--syq-path`, `--no-bootstrap`, `--pscope`, alternative `--peer-auth`
or `--coordinate-at`, `--no-tcp`, or `--tcp-plain`. It requires direct encrypted
TCP from source to destination. Destination completion does not request
permission through a receiving machine; use `--auth-from ssh` for completion
through the source's own SSH access.

On this route, quoted `~` and `~/archive` select the destination account's home
directory. Use `./~/archive` for a literal directory called `~`. Avoid
`~//archive`: explicit receiving authorization keeps it under the home directory,
but automatic selection uses ordinary SSH, where it resolves to `/archive`.

## Verification

For comparisons between two servers, `--coordinate-at local` uses ordinary
SSH access from your machine to both endpoints. It needs no restricted receiver
enrollment and supports `--verify-only --results FILE`. Files are hashed on
the servers; your machine compares their hashes and receives listings and
results, not the full file contents.

Direct restricted verification requires an existing enrollment and cannot
produce `--results`; a receiver receipt cannot attest to the source's comparison.
Verification never installs an enrollment.

`--verify-only` cannot combine with `--dry-run`, `--prune`, `--inplace`, or
overwrite policies. Filters and size limits select the entries to compare;
special files require `--preserve=specials`. Metadata is not compared, but device
identity is. A requested results file may still be written, and remote setup may
[install syq](install.md#automatic-installation-on-ssh-servers).
