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

<a id="check-local-storage-placement"></a>

## Keep free space available

Leave room for growth and allocation; the useful margin depends on your
filesystem and workload. XFS's [reserved-block pool](https://man7.org/linux/man-pages/man2/ioctl_xfs_setresblks.2.html)
can enforce headroom even for root writes. An enlarged reserve reduces usable
space and must be reapplied after mounting; preserve the original emergency
allowance when lowering it.

## Reduce allocation contention

Concurrent writers can compete for filesystem allocation locks. On XFS,
four-group defaults can limit concurrent SSD transfers. Check with `xfs_info`;
when creating a filesystem, consider [more allocation groups](https://man7.org/linux/man-pages/man8/mkfs.xfs.8.html).
512 is one example, not an optimum: a wide range of higher counts performed
similarly in our tests. Tradeoffs depend on filesystem size and workload,
especially when nearly full. Don't reformat a filesystem that performs well.

## Measure and track improvements

Use [syq-bench](https://greaber.github.io/syq-bench/reproduce.html) for repeatable
comparisons. Record the commands, versions, mounts, cache state, and other load.
Keep reporting and flush settings consistent across runs. Measure copy-command
completion and any subsequent flush separately. See
[performance tuning](tuning.md) to compare worker counts and request sizes.
