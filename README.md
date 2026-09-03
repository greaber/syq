# syq

Syq is fast, safe, programmable *file motion*: copying and deleting files and
directory trees on one machine or across a network, built for the jobs where
`cp -r`, `rm -r`, and rsync are too slow or too trusting.

- **Much faster in many common situations.** Parallel across files and inside
  large files, data over encrypted TCP instead of one ssh stream, kernel-side
  copies on a single machine, and a connection count that tunes itself while
  the copy runs.
- **Direct server-to-server transfers without dangerous ssh agent
  forwarding.** HostA gets a signed, single-use grant for exactly this
  transfer, never your agent, and hostB signs a receipt of what it wrote.
- **Filters in gitignore syntax** instead of rsync's include, exclude, and
  filter rules.

**Documentation: <https://greaber.github.io/syq/>**

## Install

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

No `sudo` is needed; the binary lands in `~/.local/bin`. Homebrew
(`brew install greaber/tap/syq`) and Cargo (`cargo install --locked syq`) also
work. Remote hosts need nothing installed in advance.

## Quick start

```sh
syq rsync -av project/ server:backup/project/      # rsync syntax: push
syq rsync -av server:data/ ./data/                 # pull
syq rsync -a --dry-run -v src/ host:dst/           # preview; change nothing
syq cp project --to server --into /backup          # native syntax → /backup/project
syq cp --from hostA --src-src big --to hostB --into big   # direct server-to-server
syq rm --root /srv --src-dir cache                 # remove /srv/cache; never leave /srv
```

The [documentation site](https://greaber.github.io/syq/) has the reasoning,
the full command reference, and the speed and security details.

## License

MIT. See [LICENSE](LICENSE).
