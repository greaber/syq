# Server setup

These server settings can make syq copies faster. Start with TCP access, and
use test data when comparing settings.

## Make TCP reachable

During a copy, syq on the server listens for file data on one free port in
`47600–47699`; choose another range with `--tcp-ports LO-HI`. For a server
using ufw, an administrator can allow a trusted client:

```sh
sudo ufw allow from <trusted-client-address> to any port 47600:47699 proto tcp
```

Allow the range in any cloud firewall too. When TCP is blocked, copies fall
back to SSH and say so; `syq cp -vv` shows which one a copy used. On Linux,
syq also uses IP over InfiniBand (IPoIB) addresses.

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
If BBR is missing, see the
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
<a id="keep-free-space-available"></a>

## Reduce allocation contention

XFS divides a filesystem into allocation groups, and the
[`mkfs.xfs` manual](https://man7.org/linux/man-pages/man8/mkfs.xfs.8.html)
notes that more groups allow more blocks and inodes to be allocated in
parallel. A filesystem with only a few groups can therefore slow copies that
write many files at once. The count is set with `-d agcount=N` when the
filesystem is created.

## Measure and track improvements

Use [syq-bench](https://greaber.github.io/syq-bench/reproduce.html) for
repeatable comparisons, and see [performance tuning](tuning.md) to compare
settings.
