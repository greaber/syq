# Server setup

Start by checking TCP access and the source and destination filesystems.
Use test data when comparing settings.

## Make TCP reachable

Syq listens on one available port in `47600–47699` during a copy. Choose another
range with `--tcp-ports LO-HI`. For a server using ufw, an administrator can allow
a trusted client:

```sh
sudo ufw allow from <trusted-client-address> to any port 47600:47699 proto tcp
```

Allow the range in any cloud firewall too. Check the transport with
`syq cp -vv --stats`. Ordinary copies fall back to SSH on the same route when
TCP is blocked. To [Run the copy from a server](remote-to-remote.md#run-the-copy-from-a-server)
with your laptop’s approval, direct encrypted TCP must be reachable.

On Linux, syq can also discover TCP addresses on IP over InfiniBand (IPoIB)
interfaces.

### Tailscale

[Tailscale](https://tailscale.com/kb/1181/firewalls) can make servers reachable
across NAT and firewalls. Allow syq's data ports through the host firewall and
tailnet rules; syq can discover Tailscale addresses. Use `tailscale status` to
check whether the connection is direct or relayed. See
[Tailscale's performance guide](https://tailscale.com/docs/reference/best-practices/performance).

## Test congestion control

On Linux, check which TCP congestion-control algorithms are available and allowed
on both endpoints:

```sh
sysctl net.ipv4.tcp_available_congestion_control
sysctl net.ipv4.tcp_allowed_congestion_control
```

If `bbr` is listed in both, compare it with `cubic` on your route:

```sh
syq cp --tcp-congestion bbr --stats data --to server --into /backup
```

Use the same data, a fresh destination, and both transfer directions.
The option applies to syq's TCP sockets. If BBR is missing, see the
[administrator setup guidance](https://github.com/google/bbr/blob/master/Documentation/bbr-faq.md#how-can-i-try-out-linux-tcp-bbr).

## Let SSH connections start promptly

OpenSSH's `MaxStartups` limit can slow parallel logins. For servers handling
parallel transfers, an administrator can consider:

```text
MaxStartups 100:30:200
```

This allows 100 unauthenticated connections before random rejection begins,
and rejects all new ones at 200. It also admits larger bursts from unrelated
clients. `MaxSessions` controls channels sharing a connection; very low values
can force extra logins.

Validate changes with `sshd -t`, then reload SSH using your system's procedure.
Keep an administrative session open. See [OpenSSH's settings](https://man.openbsd.org/sshd_config#MaxStartups).

## Check local storage placement

On Linux, inspect the source and destination filesystems:

```sh
findmnt -T /path/to/source -o TARGET,SOURCE,FSTYPE,OPTIONS
findmnt -T /path/to/destination-parent -o TARGET,SOURCE,FSTYPE,OPTIONS
```

Use an existing destination parent and run remote-path checks on the machine
that owns the path. Copies within a filesystem supporting cloning can share
storage while remaining independently writable. See [local copies and NFS](speed.md#local-copies-and-nfs)
for filesystem and mount considerations.

## Measure and track improvements

Use [syq-bench](https://greaber.github.io/syq-bench/reproduce.html) for repeatable
comparisons. Record the commands, versions, mounts, cache state, and other load.
Keep reporting and flush settings consistent across runs. See
[performance tuning](tuning.md) to compare worker counts and request sizes.
