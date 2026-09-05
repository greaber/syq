# Server setup

Syq needs no special server tuning. If a representative copy is slow, use
`-vv --stats` and check CPU, disk, and network use on both ends before changing
host settings. [Speed](speed.md) covers syq's own controls.

## Make TCP reachable

The most useful server change is often allowing syq's TCP data port.
The remote listens on one available port in `47600–47699`, or your
`--tcp-ports LO-HI` range, for the transfer's duration.

For a host using ufw, an administrator can adapt this rule:

```sh
sudo ufw allow from <trusted-client-address> to any port 47600:47699 proto tcp
```

Use the host's existing firewall policy and allow the address family the
client uses. Limit access to the clients or networks that need it, then check
with `syq cp -vv --stats`.

Ordinary copies fall back to SSH if TCP is unreachable. Restricted
remote-to-remote copies require encrypted TCP and fail instead.

## SSH connections are being dropped

If SSH data connections are refused during startup, inspect the server's
unauthenticated-connection limit:

```sh
sudo sshd -T | awk '$1 == "maxstartups" { print }'
```

Prefer making the TCP data route reachable. Raise `MaxStartups` only if
observed connection drops justify it: the limit also affects unrelated logins
and exposure to connection floods. Follow your distribution's configuration
procedure, validate with `sshd -t`, and keep an administrative session open
while reloading. See [OpenSSH's option reference](https://man.openbsd.org/sshd_config#MaxStartups).

## Test congestion control

On a lossy or long-distance Linux path, compare an alternative algorithm per
transfer. First check both endpoints:

```sh
sysctl net.ipv4.tcp_available_congestion_control
sysctl net.ipv4.tcp_allowed_congestion_control
```

The algorithm must be available and permitted on both. Syq changes only its
sockets, not the system default. The restricted receiver does not support
this option.

Use a disposable destination and return it to the same empty or absent state
before each run:

```sh
syq cp --connections 1 --tcp-congestion cubic --stats SOURCE --to HOST --into DISPOSABLE-DESTINATION
syq cp --connections 1 --tcp-congestion bbr --stats SOURCE --to HOST --into DISPOSABLE-DESTINATION
```

Alternate runs and try the reverse direction. Keep the fixed connection count
for comparison, then test the better choice with normal automatic tuning.
A faster result can have fairness costs for other traffic; use `--bwlimit`
when sharing bandwidth matters.

## Stop at the actual bottleneck

More network tuning will not help a saturated disk or CPU. Try one connection
for a spinning disk, or `--no-compress` when compression costs more than the
network bytes it saves. Leave global TCP buffers, MTU, routing, and storage
mount settings to the host or network administrator.
