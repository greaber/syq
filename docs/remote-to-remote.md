# Copy between servers

Copy directly between servers without putting private keys on either server
or giving one server unrestricted access to your SSH agent. Your machine
authorizes the copy and shows the results; the file data bypasses it.

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
and reports what it changed. See [Security](security.md#a-compromised-source-server)
for what this protects against.

## Start a copy from the source server

With a [return connection](receive.md) from your laptop, you can inspect files
on hostA and send them to hostB from the same shell:

```sh
# Run on hostA, including in an existing tmux shell.
syq cp results --to hostB --into /archive --auth-from @laptop
```

Your laptop asks for approval, then uses its SSH access to hostB to authorize
this copy. Trust hostB's SSH host key on the laptop beforehand. Relative
destination paths start in the hostB account's home directory; your laptop's
receiving root does not contain this copy, but its transfer limits still apply.

Files go directly from hostA to hostB over encrypted TCP. HostB needs a
[reachable data port](server-tuning.md#make-tcp-reachable); this route cannot
use SSH for file data. Keep the laptop connection and source command running
until completion.

Without `--auth-from`, syq tries an available receiving machine, then hostA's
own SSH access if none is eligible. Once it requests approval, refusal or
failure ends the attempt. Use `--auth-from ssh` to choose hostA's SSH access
explicitly. See [authorization selection](remote-reference.md#authorization-selection)
for supported options.

## What you need

- SSH access from your machine to both servers, with their host keys already
  trusted. Connect with ordinary SSH once if either server is new to you.
- An SSH agent on your machine, and OpenSSH 8.9 or newer on your machine,
  hostA's SSH client, and hostB's SSH server.
- SSH connectivity from hostA to hostB. A [reachable TCP data port](server-tuning.md#make-tcp-reachable)
  on hostB, normally in `47600–47699`, enables encrypted TCP workers. Otherwise
  the copy uses SSH workers on the same hostA-to-hostB route. `--no-tcp` selects
  SSH directly.
- An existing parent directory for the destination.

Keep your command running until the copy finishes. Use native `syq cp`;
`syq rsync` does not accept two remote endpoints.

## First copy and access management

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
`receiver revoke`. See [enrollment details](remote-reference.md#enrollment)
for upgrades and sharing between installations.

If your machine reaches hostB through hostA, add `--via hostA` to `enroll` or
`revoke`.

## Mirror a directory

Include a deletion limit when pruning:

```sh
syq cp --prune --max-delete 100 --from hostA --srcs-in data --to hostB --into-existing /archive
```

This updates `/archive` and removes extras. If more than 100 removals are
planned, none are performed and the command exits 25. Preview first with
`--dry-run -v`.

## Other routes and authentication

Syq may switch between encrypted TCP and SSH on the selected route. It never
silently relays file data through your machine when a direct connection fails.
If the servers cannot connect directly, explicitly relay through your machine:

```sh
syq cp --coordinate-at local --from hostA --srcs-in data --to hostB --into /archive
```

This uses your machine's bandwidth and ordinary SSH access to each endpoint.

Other authentication modes can use server-held credentials, a destination-
restricted SSH agent, or full agent forwarding. They grant different authority;
see the [advanced reference](remote-reference.md) before choosing one.
That page also covers detached copies, signed results, and direct-mode limits.
