# syq

Syq copies and removes files in parallel, on one machine or over SSH.
It is built for large files, large trees, and fast networks.

- **Parallel copies and removal**, with automatic connection tuning.
- **Resume interrupted copies** by rerunning the command.
- **Direct server-to-server transfers** without forwarding your SSH agent.
- **Gitignore-style filters**, programmable file placement, and JSON results.

[Documentation](https://greaber.github.io/syq/) ·
[Speed](https://greaber.github.io/syq/speed.html) ·
[Security](https://greaber.github.io/syq/security.html) ·
[Discussions](https://github.com/greaber/syq/discussions)

## Install

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

Linux and macOS; no `sudo` needed. Installs into `~/.local/bin`.
Homebrew and shell setup are covered in the
[installation guide](https://greaber.github.io/syq/install.html).

## Try it

```sh
syq cp project --to server --into /backup        # copy as /backup/project
syq cp --dry-run --srcs-in project --into backup # preview a contents copy
syq rsync -av server:data/ ./data/               # familiar rsync syntax
syq cp --from hostA --srcs-in big --to hostB --into big
syq rm old-output                               # parallel recursive removal
```

Rsync mode is the most stable interface; native commands are experimental.
Syq uses its own protocol and does not implement every rsync feature. See
[rsync compatibility](https://greaber.github.io/syq/rsync-compat.html).

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
its running executable to compatible remote hosts; OS, CPU, and required
system libraries must match. This caches a helper for syq's own use, not a
`syq` command on the remote `PATH`. Source builds do not check for release
updates or support `--self-update`.

For another platform, build the same commit and source changes there. Both
binaries must report the same `--build-identity`. Select that remote executable
with `--syq-path /path/to/syq`, or use `--no-bootstrap` when it is already on
the remote `PATH` (rsync mode: `--rsync-path` or `--syq-no-bootstrap`).

## License

MIT. See [LICENSE](LICENSE).
