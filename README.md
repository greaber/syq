# syq

Syq is fast, safe, programmable *file motion*: copying and deleting files and
directory trees on one machine or across a network, built for the jobs where
`cp -r`, `rm -r`, and rsync are too slow or too trusting.

- **Much faster in many common situations.** Parallel across files and inside
  large files, data over encrypted TCP connections instead of one SSH stream,
  kernel-side copies on a single machine, and a connection count that tunes
  itself while the copy runs.
- **Direct server-to-server transfers without dangerous SSH agent
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
work. With the installer or Homebrew, syq installs its matching remote helper
on first use. Cargo builds need a compatible remote `syq`; see the
[installation guide](https://greaber.github.io/syq/install.html#cargo).
To use unreleased code, see [installing from `master` or another branch](https://greaber.github.io/syq/install.html#installing-from-master-or-another-branch),
including how to update and set up matching remote binaries.

Bash, Zsh, and fish completion includes remote paths and becomes especially
fast with `syq persist on`; see the [installation guide](https://greaber.github.io/syq/install.html#shell-completion).

## Quick start

```sh
syq rsync -av project/ server:backup/project/      # rsync syntax: push
syq rsync -av server:data/ ./data/                 # pull
syq rsync -a --dry-run -v src/ host:dst/           # preview; change nothing
syq cp project --to server --into /backup          # native mode → /backup/project
syq cp --from hostA --srcs-in big --to hostB --into big   # direct server-to-server
syq rm --root /srv --src-dir cache                 # remove /srv/cache; never leave /srv
syq rm old-output --results removal.ndjson         # structured per-path outcomes
```

The [documentation site](https://greaber.github.io/syq/) has the reasoning,
the full command reference, and the speed and security details.

## License

MIT. See [LICENSE](LICENSE).
