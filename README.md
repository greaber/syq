# syq

Syq copies and removes files in parallel, on one machine or over SSH.
It is built for large files, large trees, and fast networks.

- **Parallel copies and removal**, with automatic connection tuning.
- **Resume interrupted copies** by rerunning the command.
- **Direct server-to-server transfers** without forwarding your SSH agent.
- **Gitignore-style filters**, programmable file placement, and JSON results.

[Documentation](https://greaber.github.io/syq/) ·
[Benchmarks](https://greaber.github.io/syq-bench/) ·
[Discussions](https://github.com/greaber/syq/discussions)

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
