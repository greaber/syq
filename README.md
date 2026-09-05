# syq

Syq (pronounced "sick") copies and removes files in parallel, on one machine
or over SSH.
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
