# Server performance tuning

syq does not require a specially configured server. It installs its versioned
remote helper automatically, encrypts its TCP data connections by default,
falls back to ssh when a TCP listener cannot be reached, and tunes its worker
count while a copy runs. Start with the defaults and change the host only when
a representative transfer shows a specific bottleneck.

This is deliberately a guide, not an installer. Firewall policy, ssh capacity,
kernel versions, network paths, and storage differ too much for one script to
make safe choices. Most settings below affect every user and service on the
host, not just syq.

## Measure before changing the host

Use the same source, destination, and direction for comparisons. Large files
exercise the network and storage bandwidth; a tree of small files exercises
latency and metadata performance.

```sh
syq rsync -avv --stats SOURCE HOST:DESTINATION
SYQ_DEBUG=1 syq rsync -a --stats SOURCE HOST:DESTINATION
```

`-vv` reports the remote helper and platform, candidate TCP addresses, the
planned data transport, and the initial connection count; `--stats` reports
where automatic connection tuning settled. `SYQ_DEBUG=1` adds engineering
timings showing connection setup and where workers spent their time. Check CPU,
disk, and network utilization on both endpoints at the same time. More network
tuning cannot fix a saturated disk, one busy CPU core, or a slow destination
filesystem.

Change one thing at a time and repeat the same transfer. Record the original
value, the reason for the change, and the before/after result. If the result is
within normal run-to-run variation, revert the change.

## 1. Make TCP data connections reachable

This is usually the most useful server-side change. syq authenticates over ssh,
then asks the remote helper to listen on one available port in
`47600-47699` (or the range given with `--tcp-ports`) for the duration of that
transfer. The default TCP records are encrypted with a key exchanged through
ssh. If no advertised address and port is reachable, syq reports the fallback
once and carries data over separate ssh sessions instead.

Allow the chosen port range only from clients or trusted networks that need it.
For example, an administrator using ufw could adapt one of these rules:

```sh
sudo ufw allow from <trusted-client-address> to any port 47600:47699 proto tcp
sudo ufw allow from <trusted-network/CIDR> to any port 47600:47699 proto tcp
```

Do not paste the placeholders literally. Use the host's existing firewall tool
and policy, and verify the effective rule afterward. Remove the rule with that
tool's normal delete operation to roll it back. Opening the range to the whole
internet creates unnecessary exposure even though syq's protocol requires a
per-transfer token and is encrypted unless `--tcp-plain` was requested.

Trade-offs:

- A reachable TCP path avoids ssh's per-channel flow-control and cipher-process
  limits and avoids starting one ssh process per data worker.
- A firewall exception increases reachable attack surface. A private LAN, VPN,
  or narrowly scoped source rule is preferable to a public allow rule.
- `--tcp-plain` saves encryption work but removes data confidentiality and
  integrity. Use it only on a network whose trust boundary you understand.
- `--no-tcp` requires no additional inbound ports, at the cost of using ssh for
  every data connection.

## 2. Raise sshd `MaxStartups` only after observed drops

This setting matters when data falls back to ssh. It limits concurrent
*unauthenticated* ssh connections; it does not limit established sessions and
does not apply to syq workers using the TCP data path. syq already retries shed
connections and reduces the number of simultaneous handshakes, so the default
is functional but can make connection setup slower.

Inspect the effective value rather than assuming the distribution default:

```sh
sudo sshd -T | awk '$1 == "maxstartups" { print }'
```

OpenSSH accepts either one maximum or `start:rate:full`. In the three-part
form, random refusal begins at `start` concurrent unauthenticated connections,
with `rate` percent refused initially, and reaches 100 percent at `full`. A
value such as `64:30:128` is an example with headroom for syq's connection
bursts and unrelated logins, not a universal recommendation.

If debug output shows ssh connection failures and setup time matters, put the
chosen value in the location your distribution uses for local sshd policy.
Many systems support a drop-in such as:

```text
# /etc/ssh/sshd_config.d/90-syq-performance.conf
MaxStartups 64:30:128
```

Before reloading sshd, keep an existing administrative session open, confirm
that the main configuration includes that directory, validate the complete
configuration with `sudo sshd -t`, and check the effective value again with
`sshd -T`. Reload the service using the name appropriate for the distribution.
To roll back, remove the line or drop-in, validate, reload, and recheck the
effective value.

The cost is additional CPU and memory available to unauthenticated clients and
greater exposure to connection-flood denial of service. Prefer a reachable TCP
data path, source-address restrictions, and ordinary ssh hardening over a large
global limit.

See the OpenSSH [`MaxStartups` documentation][maxstartups] for the exact syntax
and interaction with per-source limits.

## 3. Change TCP buffer ceilings only when the window is limiting throughput

Linux already auto-tunes TCP buffers. syq also uses several flows, so a single
flow's window often is not the transfer limit. Raising global ceilings consumes
no full buffer up front, but it permits each busy connection to consume more
kernel memory; multiplied across many connections and services, that can be
substantial.

The bandwidth-delay product is a useful upper-bound estimate:

```text
per-flow window (MB) ~= bandwidth (Gbit/s) * round-trip time (ms) / 8
```

Use measured per-flow bandwidth, not merely the NIC's advertised rate. Inspect
the current ceilings and live sockets first:

```sh
sysctl net.core.rmem_max net.core.wmem_max
sysctl net.ipv4.tcp_rmem net.ipv4.tcp_wmem
ss -ti
```

Consider a temporary `sysctl -w` experiment only when the observed receive or
send window is consistently below the bandwidth-delay product while the disks
and CPUs have headroom. Record all four old values. If a larger ceiling gives a
repeatable improvement, persist the measured value in the distribution's
sysctl configuration; otherwise restore the old values. Do not copy a fixed
64 MiB or larger value merely because it worked on a different WAN.

The kernel's [IP sysctl documentation][ip-sysctl] describes `tcp_rmem`,
`tcp_wmem`, and the global socket limits. Kernel and distribution defaults
change, which is another reason to inspect the running host.

## 4. Keep host defaults separate from per-transfer congestion experiments

Inspect what the kernel supports and currently uses:

```sh
sysctl net.ipv4.tcp_available_congestion_control
sysctl net.ipv4.tcp_allowed_congestion_control
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.default_qdisc
tc qdisc show
```

BBR with fair queueing can help some long-distance or lossy paths, but it is
not an syq requirement and is not automatically faster on a clean LAN. Changing
`net.ipv4.tcp_congestion_control` affects new TCP connections from every
application. If both endpoints already default to the wanted algorithm, syq's
new direct TCP sockets inherit it and no application option is needed.

For a scoped comparison on Linux, `syq --tcp-congestion ALGO` selects an
algorithm only for syq's direct TCP data sockets, on both the connecting and
listening hosts. It does not change the host default. Both kernels must have
the algorithm registered, and an unprivileged syq process may choose only an
entry in `net.ipv4.tcp_allowed_congestion_control`. A rejected explicit request
stops the transfer rather than silently changing the experiment. Use a fixed
connection count such as `-j 1` when comparing algorithms, repeat and alternate
the runs, and inspect the effective algorithms and loss/window telemetry with
`--stats`.

Congestion control is sender-side: the server setting governs bulk downloads,
while the uploading client setting governs bulk uploads. The per-socket option
does not attach or replace a queueing discipline. Changing
`net.core.default_qdisc` alone may not replace qdiscs already attached to live
interfaces, and virtual or multiqueue devices can have different behavior.

Only test these settings when network measurements point to congestion, loss,
or queueing rather than CPU or storage. Confirm kernel support, follow the
operating system or network provider's guidance, record the prior algorithm and
qdisc, and have an out-of-band recovery path before changing a remote host.

## 5. Leave MTU, RDMA, and interface addressing to the network owner

syq uses TCP; it does not require RDMA or RoCE configuration. It can use IP
interfaces backed by that hardware when the operating system and fabric have
already configured them.

Jumbo frames help only when every hop and both endpoints support the same MTU.
A mismatch can cause fragmentation, packet loss, or a path-MTU black hole, and
changing the interface carrying the current ssh session can disconnect you.
Likewise, guessed private addresses, routes, firewall rules, or generated
network-manager files are specific to one site and do not belong in a generic
syq procedure. Use the provider's fabric instructions and verify errors and
drops with `ip -s link` and the vendor's tools.

## 6. Stop when the bottleneck is storage or CPU

- A single spinning disk often performs better with `-j 1`; syq's automatic
  tuner can reduce active workers during longer runs, but short jobs may finish
  before it measures the slowdown.
- NVMe, RAID, NFS, and other high-latency filesystems often benefit from
  parallelism. NFS mount choices such as `nconnect` are client and server
  policy; see the [NFS notes](README.md#nfs) and test with disposable data.
- Compression trades network bytes for CPU. Compare with and without `-z` when
  either the link or CPU is near saturation.
- `--bwlimit` is the appropriate control when the goal is coexistence with
  other traffic, not maximum benchmark throughput.

## Change record

Keep a small record for each host so later administrators can distinguish a
measured decision from an inherited assumption:

| Item | Record |
|---|---|
| Workload and bottleneck | What was measured and where saturation appeared |
| Original state | Effective setting and configuration file before the change |
| Proposed state | Exact setting and its expected benefit |
| Validation | Repeated before/after command and result |
| Trade-off | Host-wide resource, security, or fairness cost |
| Rollback | Exact removal or prior value, tested while access was available |

[ip-sysctl]: https://docs.kernel.org/networking/ip-sysctl.html#tcp-variables
[maxstartups]: https://man.openbsd.org/sshd_config#MaxStartups
