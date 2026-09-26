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

## Tune XFS storage

### Choose an allocation-group count

XFS divides storage into allocation groups, each with its own allocation
metadata. More groups can let concurrent file creation and block allocation
spread across independent locks. Inspect `agcount` and `agsize` with:

```sh
xfs_info /srv/data
```

For a new XFS filesystem on fast SSD storage used for concurrent file transfers,
we recommend 512 allocation groups as a starting point. The useful count depends
on filesystem size and workload. At a fixed size, more groups mean smaller
groups and more per-group metadata. Large files may need more extents, and
fragmented or nearly full filesystems can require more searching. A different
count alone is not a reason to reformat an existing filesystem that performs
well.

When comparing configurations, measure command-completion time. If you also
measure the time to flush pending writes to storage, report it separately:
faster flushing does not necessarily mean the copy command finishes sooner.

Choose the count when creating the filesystem with `mkfs.xfs -d agcount=512`.
For a device you intend to format, preview the proposed geometry without
writing it:

```sh
sudo mkfs.xfs -N -d agcount=512 /dev/your-empty-device
```

`-N` only prints the proposed layout. Removing it creates a filesystem and can
destroy existing data. The count cannot be changed through a mount option to subdivide existing
allocation groups. Check the proposed group and journal sizes:
excessively small groups constrain allocation sizes, and the internal journal
must fit within one group. See [XFS format options](https://man7.org/linux/man-pages/man8/mkfs.xfs.8.html).

To investigate an existing workload, use a kernel-capable `perf` installation
on the destination host. Find the syq process doing the destination writes,
then replace `COPY_PID` with its process ID:

```sh
pgrep -a -x syq
sudo perf top -g -p COPY_PID
```

Inspect call stacks while the copy is active; press `q` to stop profiling.
CPU time spent spinning on locks in XFS allocation-group paths is a reason to
test more groups. Allocation functions being busy, or generic spinlock samples
without their callers, do not by themselves establish contention on those
locks. CPU sampling also misses time threads spend asleep waiting for locks
or I/O. A low group count alone is not a diagnosis: confirm the effect with
the same workload and worker count on a disposable filesystem with more groups,
keeping the device, journal size, occupancy, and flush policy comparable.
See [perf top](https://man7.org/linux/man-pages/man1/perf-top.1.html).

### Keep free space available for allocation

As an XFS filesystem fills and its free space becomes fragmented, new writes
can require more allocation work and smaller extents. Keeping headroom gives
XFS more choices when placing data. An operating budget of 80% used and 20%
free is one starting point to evaluate; degradation is gradual and depends on
the workload and free-space layout, rather than starting at a universal 80%
threshold.

XFS's reserved-block pool can enforce headroom across the filesystem, including
for ordinary writes by root. It withholds an amount of space through accounting,
without allocating particular disk blocks. When ordinary available space runs
out, allocations fail with `ENOSPC` even though the reserve remains physically
free. The pool is normally a small emergency allowance for internal metadata
operations; enlarging it is an option to evaluate for your workload, not an
established general performance recommendation.

Inspect the filesystem geometry and current reserve on the machine that owns
the mount:

```sh
xfs_info /srv/data
sudo xfs_io -x -r -c 'resblks' /srv/data
```

Record the original reserve before changing it. The `resblks` values are
**filesystem blocks**, using `bsize` from the `data` line of `xfs_info`.
`reserved blocks` is the target pool size; `available reserved blocks` is the
amount currently held in it. The usual default with 4 KiB blocks is 8,192
blocks, or 32 MiB.

Set the desired total reserve, rather than an increment. For example,
**100 GiB on a filesystem with 4 KiB blocks** is 26,214,400 blocks:

```sh
sudo xfs_io -x -r -c 'resblks 26214400' /srv/data
sudo xfs_io -x -r -c 'resblks' /srv/data
```

The change is live: no remount or reformat is needed. Check the available
reserve afterward; increasing the target cannot reclaim space occupied by
existing files. The setting is not stored on disk. Reapply it after each mount,
including after reboot, before starting workloads that depend on the limit.
The reserve reduces the space reported as free by `df`, rather than reducing
the reported filesystem size.

A larger reserve also provides temporary recovery capacity. If ordinary writes
run out of space, lower the target with the same command to release part of the
available reserve immediately. Keep the original emergency allowance, then
restore the larger target after deleting or moving enough data. Released
headroom can be consumed again, so it buys time rather than solving continued
growth.

Compare command-completion time before adopting a larger reserve, and report
any subsequent flush time separately. XFS
reduces speculative preallocation near its available-space limit, and a larger
reserve makes that behavior start at a lower physical occupancy. A reserve
preserves allocation choices but does not guarantee unchanged throughput near
the imposed limit. See the [reserved-block command](https://man7.org/linux/man-pages/man8/xfs_io.8.html),
[reserve interface](https://man7.org/linux/man-pages/man2/ioctl_xfs_setresblks.2.html),
and [XFS allocation policy](https://github.com/torvalds/linux/blob/v6.12/fs/xfs/xfs_iomap.c).

## Measure and track improvements

Use [syq-bench](https://greaber.github.io/syq-bench/reproduce.html) for repeatable
comparisons. Record the commands, versions, mounts, cache state, and other load.
Keep reporting and flush settings consistent across runs. See
[performance tuning](tuning.md) to compare worker counts and request sizes.
