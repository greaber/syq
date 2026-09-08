# syq

Syq (pronounced "sick") copies, reorganizes, and removes files—locally or
across machines.
It aims to perform well across file sizes, directory sizes, and network speeds.

[Documentation](https://greaber.github.io/syq/) ·
[Benchmarks](https://greaber.github.io/syq-bench/)

Quick links to docs for common tasks:

- [Send files to your laptop from a server you’re SSHed into](https://greaber.github.io/syq/receive.html).
  Your laptop needs no SSH server or incoming network port.
- [Run commands on your laptop from a server](https://greaber.github.io/syq/exec.html)
- [Copy directly between servers without forwarding your SSH agent](https://greaber.github.io/syq/remote-to-remote.html)
- [Rename and reorganize files during a copy](https://greaber.github.io/syq/mappings.html)
- Script syq using the [JSON API](https://greaber.github.io/syq/automation.html) or
  [Python SDK](https://greaber.github.io/syq/python.html).

## Install

On Linux or macOS (x86-64 or ARM64):

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

Installs into `~/.local/bin` without `sudo`; make sure it is on your `PATH`.
Or install with Homebrew:

```sh
brew install greaber/tap/syq
```

See [installation details](https://greaber.github.io/syq/install.html) for
updates and shell completion.

## Try a copy

Replace `server` with an SSH hostname or alias you normally connect to,
and `project` with a local directory:

```sh
syq cp project --to server --into backup
```

This creates or updates `backup/project` in your home directory on the server.
Add `--dry-run` to preview the copy. If interrupted, rerun the same command to
resume. See [Copy files](https://greaber.github.io/syq/reference.html) for more
examples.

## Developing syq

Build from source only when developing syq itself. For everyday use, install
an official release: it can fetch the right remote executable across platforms.

With [rustup](https://rustup.rs/), Git, and a C compiler installed:

```sh
git clone https://github.com/greaber/syq.git
cd syq
cargo build --locked --release
./target/release/syq cp data --to server
```

Local edits work without a commit or published branch. A source build uploads
its running executable to compatible SSH hosts automatically; OS, CPU, and
required system libraries must match.

Direct server-to-server copies use a separate restricted receiver. The first
copy can enroll it automatically, but after rebuilding, repeat
`./target/release/syq receiver enroll hostB:/archive` to update an existing
receiver. The local executable must run on hostB.

See [Developing syq](docs/development.md) for the rebuild/copy workflow,
manual setup on another platform, and checks to run before a pull request.

## License

MIT. See [LICENSE](LICENSE).
