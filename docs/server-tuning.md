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

<a id="let-ssh-connections-start-promptly"></a>
<a id="reduce-allocation-contention"></a>
<a id="check-local-storage-placement"></a>
<a id="keep-free-space-available"></a>

## Other server limits

- OpenSSH's [`MaxStartups`](https://man.openbsd.org/sshd_config#MaxStartups)
  limit drops some logins when many start at once, which slows the start of a
  copy with many workers while syq retries them.
- An XFS filesystem with few allocation groups (`agcount` in the
  [`mkfs.xfs` manual](https://man7.org/linux/man-pages/man8/mkfs.xfs.8.html))
  can slow copies that write many files at once.

## Measure and track improvements

Use [syq-bench](https://greaber.github.io/syq-bench/reproduce.html) for
repeatable comparisons, and see [performance tuning](tuning.md) to compare
settings.
