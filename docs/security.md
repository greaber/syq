# Security

Syq limits where a copy or removal can operate, checks transferred data, and
verifies the release helpers it installs. It still depends on the machines
and accounts you trust.

Report vulnerabilities using
[SECURITY.md](https://github.com/greaber/syq/blob/master/SECURITY.md).

## Symlinks and shared directories

Native commands refuse symlink traversal by default. Selected links are copied
or removed as links. Follow options allow traversal only in paths you name;
links discovered inside a selected tree are never followed. Use `--root` to
confine source selection or removal to a directory. The
[command reference](reference.md#symlinks) explains the options.

Syq keeps the selected directories open so renaming a path cannot redirect
work to another tree. This protects the boundary; it does not freeze the tree
or prevent other authorized users from changing entries inside it.

**Do not run privileged copies into directories writable by untrusted users.**
Resume uses predictable partial-file names. File checks cannot prove who
created a partial file in a shared writable directory. This restriction
applies by default, as it does to rsync's optional partial directories.

In rsync mode, supplied paths may traverse links owned by root or the local
endpoint's user. `--insecure-links` disables that ownership check for source,
destination, and control paths on the invoking machine. It also allows source
traversal through symlinked parents. A source-side need therefore relaxes
checks on destination and control paths too. The flag is never passed to a
remote endpoint.

Native copy does not preserve owner, group, modes, or special files unless
requested with `--preserve`. Leave these off when you do not need them.

## What a compromised source can do

For a default direct remote-to-remote copy, syq installs a restricted receiver
on the destination. The source receives permission for one transfer; it
receives neither your SSH agent nor a reusable destination credential.

The receiver limits changes to the authorized destination and enforces the
transfer's options and resource limits. The source cannot enlarge that
permission or replay it for another transfer. Receiver SSH configuration,
programs, and enrollment state are protected from overlapping copy operations.

**This protects the destination from the source; it does not prove the source
is honest.** A compromised source can omit files, invent content or metadata,
or stop. The destination machine, receiver, and account remain trusted.

The destination signs a receipt of what it did, verified on your machine.
A forged, missing, or incomplete receipt cannot report a clean success. The
receipt does not prove that every intended source file arrived, roll back a
failure, or freeze the destination afterward.

See [Copy between servers](remote-to-remote.md) for setup, limits, receipts,
and alternatives. Other authentication modes provide different protection:

| Choice | Authority available to the source host |
|---|---|
| Default restricted receiver | One authorized copy within its destination and limits |
| `--peer-auth broker` | Your destination account's full authority during the session, restricted to that host and user |
| `--peer-auth own-credentials` | Whatever its existing credentials permit |
| `--peer-auth full-agent` | Your forwarded agent, as with `ssh -A` |
| `--rsh COMMAND` | Whatever your supplied command permits |

Relaying with `--coordinate-at local` keeps destination authentication on your
machine; file data passes through it too. Syq never silently selects a weaker
authentication mode. Host identity is based on host keys: machines sharing a
private host key cannot be distinguished by the broker.

## Interrupted and changing files

By default, complete files replace their old versions by rename. `--inplace`
exposes partial updates. Neither mode makes the whole copy transactional.

Stop other writers or copy a snapshot when consistency matters. A file
modified during copying may contain data from different moments despite
change detection and retries. Syq does not `fsync` transfer data; successful
completion does not guarantee survival across power loss.

Removal cannot be rolled back. When another process renames entries during
removal, syq avoids following replacement links or descending into unexpected
directories, but a single replacement entry can still be unlinked. Use
exclusive access when the exact set of removed objects must remain fixed.

## Persistent connections

`syq persist on` keeps authenticated connections and a ready helper session
for repeated commands. The reuse window can last up to ten minutes after the
last command. During it, processes acting as the same local user can use
those logins without another key touch or agent approval.

Use `syq persist off` to close them. Leave persistence off where that window
is unacceptable. It does not apply to restricted receiver authentication.

## Release and bootstrap integrity

Official helpers and self-updates are checked against a signed release
manifest before use. Your client chooses the matching helper version;
source builds upload their running executable over SSH to compatible hosts
instead of downloading a release. Other platforms need
[matching remote builds](install.md#remote-hosts-with-source-builds).
Updates are explicit and never happen as a side effect of copying.

Verification protects the downloaded artifact. It cannot protect a machine
whose trusted account or installed programs have already been compromised.

For engineering evidence, see the
[path-safety design](https://github.com/greaber/syq/tree/master/design) and
[release procedure](https://github.com/greaber/syq/blob/master/RELEASING.md).
The syq process protocol has not been fuzzed as extensively as rsync's.
