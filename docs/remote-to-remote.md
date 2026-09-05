# Copy between servers

Start a copy from your machine while the data travels directly between two
servers:

```sh
syq cp --from hostA --srcs-in big --to hostB --into big
```

```text
Your machine ── starts the copy and displays results
                       │
                    hostA ───── file data ─────▶ hostB
```

The default uses a restricted receiver on hostB. HostA receives permission
for this copy, without your SSH agent or a reusable credential for hostB.
Two endpoints with the same host and user run a local copy on that host.

`syq rsync` does not accept two remote endpoints; use native `cp`.

## Requirements

- SSH access from your machine to hostA and hostB. Enrollment can reach hostB
  through hostA using `--via` if needed.
- OpenSSH 8.9 or newer on your machine, hostA's SSH client, and hostB's server;
  a local `SSH_AUTH_SOCK`.
- Already trusted, exact host keys for both hosts in your local known-hosts
  files. Establish first-contact trust with ordinary SSH before copying.
- A reachable encrypted TCP data port on hostB, normally in `47600–47699`.
  The restricted receiver does not fall back to SSH data transport.
- An existing destination parent directory for enrollment.

Host-certificate-only trust, `KnownHostsCommand`, and `RevokedHostKeys` are
unsupported by the broker. Custom known-hosts paths must be unambiguous:
one absolute, whitespace-free filename per configured user/global directive.
The default known-hosts file list works. Syq reports unsupported configurations
instead of relaxing host verification.

Your local SSH configuration selects hostB's login, address, port, and trusted
host keys. HostA's SSH configuration does not override those choices.

## Enrollment lifecycle

The first real copy automatically enrolls the destination parent. This adds a
managed restricted key to hostB's `authorized_keys` and installs a receiver.
The private enrollment key stays on your machine. Enrollment is reused for
later copies inside that parent.

You can enroll ahead of time, inspect state, or revoke access:

```sh
syq receiver enroll hostB:/archive
syq receiver enroll hostB:/archive --via hostA
syq receiver list
syq receiver revoke ID
```

Use the ID printed by `list`. Repeating `enroll` refreshes the receiver to
match your local build. A `pending` enrollment can be retried or revoked.
Revoke and enroll again to rotate its receipt key.

Enrollment requires normal command authority on hostB during setup. Later
copies use only the restricted key. It refuses a symlink as the enrolled
root: enroll the real directory instead. Copies that overlap receiver SSH
configuration, installed programs, or enrollment state are refused.

Manage enrollment through these commands. Its state is not a disposable
helper cache. Revocation prevents new sessions; work already in progress may
finish. `revoke` also accepts `--via`.

## Preview and mirror

A dry run needs an existing enrollment; it does not create one:

```sh
syq receiver enroll hostB:/archive
syq cp --dry-run -v --from hostA --srcs-in data --to hostB --into /archive
```

Pruning requires an explicit deletion cap:

```sh
syq cp --prune --max-delete 100 --from hostA --srcs-in data --to hostB --into-existing /archive
```

If more than 100 deletions are planned, none are performed and the command
exits 25. Ignored paths remain protected. The receiver independently checks
that changes are permitted by the transfer's authorization.

## Limits and unsupported options

Default limits are 100 million entries and 8 TiB of file data. Override them
for one transfer with `--receiver-max-entries N` and
`--receiver-max-bytes SIZE`. Values can raise or lower the defaults within the
allowed ranges. The transfer must start within 24 hours of authorization and
finish within seven days of authorization.

| Option or combination | Restricted receiver |
|---|---|
| `--no-tcp`, `--tcp-plain`, `--tcp-congestion` | Unsupported; encrypted TCP is required |
| `--mapping`, `--min-size` | Unsupported |
| `--max-size` with `--prune` | Unsupported |
| Fixed `--connections` above 64 | Unsupported |
| `--inplace` with `--as-new` | Unsupported |
| `--detach` | Unsupported; the local broker must remain attached |
| Native `rm` | Unsupported; use a normal SSH login |

## Receipts and results

The destination signs a receipt describing the operations it saw and the
final state of paths they could have changed. Your machine verifies it before
reporting trusted results. Use `-v` for verified totals, or `--results FILE`
for [machine-readable records](automation.md).

Add `--receiver-receipt digests` to include BLAKE3 hashes of affected regular
files at completion. Receipt size is capped at four million records and
512 MiB of plaintext; reaching a cap stops further changes and reports an
incomplete outcome.

A receipt proves what the destination reported, not that the source supplied
every file or the right contents. It provides no rollback and cannot protect
against a compromised destination. See [Security](security.md).

Direct receiver-attested results arrive after receipt verification, rather
than as live per-file progress. For `--dry-run --results`, use
`--coordinate-at local`; only that mode supplies the preview stream.

## Other routes and authentication

If hostA cannot reach hostB, relay through your machine explicitly:

```sh
syq cp --coordinate-at local --from hostA --srcs-in data --to hostB --into /archive
```

This uses your machine's bandwidth. Syq never switches to this route silently.

A direct pull makes hostB connect to hostA. It requires another authentication
choice because there is no restricted source receiver. For example, when
hostB already holds credentials for hostA:

```sh
syq cp --coordinate-at dst --peer-auth own-credentials --from hostA data --to hostB --into /archive
```

Other choices are `--peer-auth broker` (your destination account's authority,
limited to that host and user), `--peer-auth full-agent` (ordinary agent
forwarding), or `--rsh COMMAND` (your complete policy). Their
[security tradeoffs](security.md#a-compromised-source-server) differ.

## Detached copies

To leave a direct copy running after your command exits, use `--detach` with
`--peer-auth own-credentials`, or an explicit `--rsh` policy. The coordinator
must be able to authenticate independently. The restricted receiver and
`--results` do not support detached operation.

The launcher reports the coordinator and log location after checking that the
job is ready. Save that location; the job continues remotely. If printing it
fails, the launcher reports an error but the job may still be running.
Detached launch needs `/bin/kill` and either `setsid` or `perl` on the
coordinator. Its remote log is not a signed receipt.
