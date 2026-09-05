# Server setup

A few server settings can make a substantial difference, especially on
long-distance links or when syq must carry data over SSH.

## Make TCP reachable

Allowing syq's encrypted TCP connections often gives the biggest improvement.
The server listens on one available port in `47600–47699` for the duration of
the copy. Choose another range with `--tcp-ports LO-HI`.

For a server using ufw, an administrator can allow a trusted client:

```sh
sudo ufw allow from <trusted-client-address> to any port 47600:47699 proto tcp
```

Allow the port range in any cloud firewall too. Check the selected route with
`syq cp -vv --stats`. Ordinary copies fall back to SSH when TCP is blocked;
the default direct server-to-server mode requires encrypted TCP.

### Tailscale

[Tailscale](https://tailscale.com/kb/1181/firewalls) is a useful way to make
servers reachable across NAT and firewalls without exposing syq's ports to
the public internet. Allow the data ports through the host firewall and your
tailnet's access rules; syq can discover the Tailscale addresses.

TCP over Tailscale can be faster than sending data over SSH without it.
The tunnel can also limit throughput, especially if Tailscale uses a relay.
Compare on your own route, and use `tailscale status` to check whether the
connection is direct. See [Tailscale's performance guide](https://tailscale.com/docs/reference/best-practices/performance).

## Test congestion control

TCP's congestion-control algorithm decides how quickly to send and when to
slow down. On long-distance links with packet loss, **BBR can be dramatically
faster than CUBIC**: loss does not always mean the link is full. It is worth
trying even when copies finish successfully. Results depend on the route and
direction; BBR does not win everywhere.

On Linux, check both endpoints:

```sh
sysctl net.ipv4.tcp_available_congestion_control
sysctl net.ipv4.tcp_allowed_congestion_control
```

If `bbr` is available and permitted on both, try it for a copy:

```sh
syq cp --tcp-congestion bbr --stats data --to server --into /backup
```

This changes only syq's TCP sockets, not the host default. If BBR is missing,
ask the server administrator to enable it; see the
[BBR setup guidance](https://github.com/google/bbr/blob/master/Documentation/bbr-faq.md#how-can-i-try-out-linux-tcp-bbr).
The option cannot tune SSH's own connections and is not supported by the
restricted server-to-server receiver.

Compare with `--tcp-congestion cubic` using the same data and an empty test
destination each time. Try both directions. Use `--bwlimit` if you need to
leave bandwidth for other users.

## Let SSH connections start promptly

When data travels over SSH, syq opens several connections. OpenSSH's usual
`MaxStartups 10:30:100` starts randomly rejecting logins once ten are still
authenticating. Syq retries and reduces simultaneous logins, so the symptom
can be a slow start rather than a failed copy.

For a server handling parallel transfers, an administrator can consider:

```text
MaxStartups 100:30:200
```

This allows 100 simultaneous unauthenticated connections before random
rejection begins, and rejects all new ones at 200. It also allows larger
bursts from unrelated clients, so choose limits that suit the server.

`MaxSessions` is a different limit: channels sharing one SSH connection.
Very low values can force extra logins when syq tries to reuse a connection.
Syq's SSH data workers use independent connections, so raising this limit
alone does not increase their capacity.

Validate configuration changes with `sshd -t`, then reload SSH using your
system's normal procedure. Keep an administrative session open while doing
so. See [OpenSSH's settings](https://man.openbsd.org/sshd_config#MaxStartups).

## Measure and track improvements

Use [syq-bench](https://greaber.github.io/syq-bench/reproduce.html) to compare
settings on your machines and save repeatable results over time. Test the
workloads and transfer directions you actually use.
