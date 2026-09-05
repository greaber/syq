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
receipt key.

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
