# Copy between servers

Copy directly between servers without copying your private keys to either server
or giving one server unrestricted access to your SSH agent. Your machine
authorizes the copy and shows the results; the file data bypasses it.

## Run the copy from your laptop

```sh
# Copy the contents of hostA's big directory into hostB's big directory.
syq cp --from hostA --srcs-in big --to hostB --into big
```

<figure class="transfer-flow" aria-label="Your machine authorizes the copy and displays results. File data goes directly from hostA to hostB.">
<div class="flow-machine"><strong>Your machine</strong><span>Authorize · see results</span></div>
<div class="flow-control" aria-hidden="true">│</div>
<div class="flow-data"><div class="flow-machine"><strong>hostA</strong><span>Source</span></div><div class="flow-arrow"><span>File data</span><b aria-hidden="true">⟶</b></div><div class="flow-machine"><strong>hostB</strong><span>Destination</span></div></div>
<figcaption>The files travel directly between the servers.</figcaption>
</figure>

HostA gets permission for this transfer only. HostB checks that permission
and reports what it changed. See [A compromised source server](security.md#a-compromised-source-server)
for what this protects against.

### What you need

- SSH access from your machine to both servers, with their host keys already
  trusted. Connect with ordinary SSH once if either server is new to you.
- An SSH agent on your machine, and OpenSSH 8.9 or newer on your machine,
  hostA's SSH client, and hostB's SSH server.
- SSH connectivity from hostA to hostB. A reachable TCP data port
  on hostB, normally in `47600–47699`, enables encrypted TCP workers; see
  [Make TCP reachable](server-tuning.md#make-tcp-reachable). Otherwise
  the copy uses SSH workers on the same hostA-to-hostB route. `--no-tcp` selects
  SSH directly.
- An existing parent directory for the destination.

The copy stops if your laptop command ends, so keep it running until the copy finishes.

### First copy and access management

The first copy sets up a restricted receiver on hostB automatically. It adds
a restricted key to `authorized_keys`; the private key stays on your machine.
Later copies reuse this setup.

To prepare `/archive` on hostB ahead of time, including before a dry run:

```sh
syq receiver enroll hostB:/archive
syq cp --dry-run -v --from hostA --srcs-in data --to hostB --into /archive
```

Inspect or remove this access with:

```sh
syq receiver list
syq receiver revoke ID
```

Use the ID from `list`. Revocation stops active copies for that enrollment
and removes its access; completed writes remain. If cleanup fails, retry
`receiver revoke`. See [Enrollment](remote-reference.md#enrollment)
for upgrades and sharing between installations.

If your machine reaches hostB through hostA, add `--via hostA` to `enroll` or
`revoke`.

<a id="start-a-copy-from-the-source-server"></a>

## Run the copy from a server

You can also start a copy in the source server's shell and use your laptop's
SSH credentials to authorize it. This uses a receiving connection from your
laptop; see [Authorize copies between servers](receive.md#authorize-copies-between-servers)
for setup, approval, and connectivity requirements.

From a third server, first request reusable account access to both endpoints:

```sh
syq persist connect hostB --auth-from @laptop
syq persist connect hostC --auth-from @laptop
syq cp --from hostB --srcs-in data --to hostC --into /archive --auth-from @laptop
```

Approve each account on the laptop. The requesting server has full access to
those accounts while the approvals remain open. HostB receives only permission
for the current copy to hostC; file data goes directly from hostB to hostC,
using TCP when reachable or SSH otherwise. `--no-tcp` selects SSH directly.
Keep the copy and laptop receiving connection open until it finishes.

HostB's SSH server must allow remote Unix-socket forwarding for the copy's
control connection. This does not forward an SSH agent. SSH data workers need
writable `~/.ssh/authorized_keys` on hostC for a temporary restricted key.
See [Approved account copies](remote-reference.md#approved-account-copies)
for option support.

## Mirror a directory

From your laptop:

```sh
syq cp --prune --max-delete 100 --from hostA --srcs-in data --to hostB --into-existing /archive
```

This updates `/archive` and removes extras. If more than 100 removals are
planned, none are performed and the command exits 25. Preview first with
`--dry-run -v`.

## Other routes and authentication

Copies started from your laptop can switch between encrypted TCP and SSH on
the selected route. Syq never silently relays file data through your machine
when a direct connection fails.
If the servers cannot connect directly, explicitly relay through your machine:

```sh
syq cp --coordinate-at local --from hostA --srcs-in data --to hostB --into /archive
```

This uses your machine's bandwidth and ordinary SSH access to each endpoint.

Other authentication modes can use server-held credentials, a destination-
restricted SSH agent, or full agent forwarding. They grant different authority;
see the [Remote copy reference](remote-reference.md) before choosing one.
That page also covers detached copies, signed results, and direct-mode limits.
