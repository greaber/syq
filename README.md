# syq

Syq copies and removes files in parallel, on one machine or over SSH.
It is built for large files, large trees, and fast networks.

- **Parallel copies and removal**, with automatic connection tuning.
- **Resume interrupted copies** by rerunning the command.
- **Direct server-to-server transfers** without forwarding your SSH agent.
- **Gitignore-style filters**, programmable file placement, and JSON results.

[Documentation](https://greaber.github.io/syq/) ·
[Speed](https://greaber.github.io/syq/speed.html) ·
[Security](https://greaber.github.io/syq/security.html)

## Install

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

Linux and macOS; no `sudo` needed. Installs into `~/.local/bin` and sets up
matching remote helpers on first use. Homebrew, Cargo, and source builds are
covered in the [installation guide](https://greaber.github.io/syq/install.html).

Source builds upload themselves to compatible remote hosts, including local
edits; no commit or published branch is needed.

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

## License

MIT. See [LICENSE](LICENSE).
