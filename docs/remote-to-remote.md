# Copy between servers

Copy directly between servers without putting private keys on either server
or giving one server unrestricted access to your SSH agent. Your machine
authorizes the copy and shows the results; the file data bypasses it.

```sh
# Copy the contents of hostA's big directory into hostB's big directory.
syq cp --from hostA --srcs-in big --to hostB --into big
```

```text
Your machine ── authorizes the copy and displays results
                       │
                    hostA ───── file data ─────▶ hostB
```

HostA gets permission for this transfer only. HostB checks that permission
and reports what it changed. See [Security](security.md#a-compromised-source-server)
for what this protects against.

## What you need

- SSH access from your machine to both servers, with their host keys already
  trusted. Connect with ordinary SSH once if either server is new to you.
- An SSH agent on your machine, and OpenSSH 8.9 or newer on your machine,
  hostA's SSH client, and hostB's SSH server.
- A [reachable TCP data port](server-tuning.md#make-tcp-reachable) on hostB,
  normally in `47600–47699`. This direct mode cannot send data over SSH instead.
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

Use the ID from `list`. Revocation blocks new sessions; an ongoing copy may
finish. If your machine reaches hostB through hostA, add `--via hostA` to
`enroll` or `revoke`.

## Mirror a directory

Include a deletion limit when pruning:

```sh
syq cp --prune --max-delete 100 --from hostA --srcs-in data --to hostB --into-existing /archive
```

This updates `/archive` and removes extras. If more than 100 removals are
planned, none are performed and the command exits 25. Preview first with
`--dry-run -v`.

## Other routes and authentication

If the servers cannot connect directly, relay through your machine:

```sh
syq cp --coordinate-at local --from hostA --srcs-in data --to hostB --into /archive
```

This uses your machine's bandwidth and ordinary SSH access to each endpoint.
Syq never switches to it silently.

Other authentication modes can use server-held credentials, a destination-
restricted SSH agent, or full agent forwarding. They grant different authority;
see the [advanced reference](remote-reference.md) before choosing one.
That page also covers detached copies, signed results, and direct-mode limits.
