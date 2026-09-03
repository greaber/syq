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

Use the alternate destination sshd profile to exercise syq's fallback from a
rejected multiplexed worker channel to independent SSH connections:

```sh
scripts/test-real-ssh.sh --profile max-sessions-1
```

The first build downloads the pinned Rust toolchain image, Debian packages, and
Cargo dependencies. Test execution itself uses only the Compose project's
internal Docker network: no ports are published and no real SSH configuration,
agent, keys, homes, or remote hosts are used. The destination service alone gets
`NET_ADMIN`, solely to install the test's port-specific firewall rule.

Managed bootstrap rejects unpublished development identities, so endpoint
startup seeds the exact candidate binary into its expected helper-cache path.
The scenarios still use normal SSH control, constrained agent forwarding, and
destination enrollment; they do not substitute a fake remote shell.

The smoke suite currently covers source-side direct coordination with automatic
restricted-destination enrollment over encrypted TCP, source-side coordination
with constrained authentication, firewall-triggered TCP fallback, explicitly
selected SSH data channels, destination-side coordination through the reversed
constrained-agent edge, and an explicit local relay. Every path uses real SSH
for control and bootstrap, and the suite compares the complete source and
destination manifests afterward.

This suite is intentionally outside `cargo test` and CI. Run it after changing
SSH, remote-helper, enrollment, restricted-receiver, transport, or remote
topology behavior, and before cutting a release. A failure retains public logs
under `target/real-ssh.*`; the ephemeral private key is always removed.

## Known findings from bringing up the suite

- A restricted copy to a missing directory with `--preserve=permissions` is
  currently rejected because root creation requests a receiver-managed mode
  that the grant does not authorize. The passing restricted case pre-creates
  its root and uses `--into-existing`; descendant modes are still compared.
- The first signed TCP worker can currently receive a connection reset and
  recover on its built-in retry. The suite requires final success and leaves
  this diagnostic visible rather than treating the recovered run as clean.
