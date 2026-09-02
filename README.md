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

**Documentation: <https://greaber.github.io/syq/>** (source in [`docs/`](docs/)).

## Install

No `sudo` is needed. The installer puts the matching Linux or macOS binary in
`~/.local/bin`:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/greaber/syq/releases/latest/download/install.sh | sh
```

Homebrew (`brew install greaber/tap/syq`) and Cargo (`cargo install --locked
syq`) also work. Remote hosts need nothing installed in advance: syq installs a
matching, signature-verified helper there on first use.
[Installing](https://greaber.github.io/syq/install.html) has the details.

## Quick start

```sh
# rsync-shaped commands: say `syq rsync` instead of `rsync`
syq rsync -av project/ server:backup/project/      # push
syq rsync -av server:data/ ./data/                 # pull
syq rsync -a /mnt/nfs/tree /local/tree             # same machine, in parallel
syq rsync -a --syq-ignore node_modules --syq-ignore .git src/ host:dst/
syq rsync -a --dry-run -v src/ host:dst/           # preview; change nothing
syq rsync -a --delete --max-delete 100 src/ host:dst/   # mirror, refusing surprises

# native commands: verb first, endpoints and placement explicit
syq cp project --to server --into /backup          # → /backup/project
syq cp --from hostA --src-src big --to hostB --into big   # direct server-to-server
syq cp --prune --max-delete 100 --src-src build --to server --into-existing /srv/app
syq rm --root /srv --src-dir cache                 # remove /srv/cache; never leave /srv
set -o pipefail                                    # so a failed producer fails the pipeline
syq map --src-src photos | jq -c '.dst.value |= ascii_downcase' \
  | syq cp --mapping - -C photos --to nas --into /pub   # placement as data
```

## Documentation

- [Introduction](https://greaber.github.io/syq/): why syq exists, and what it
  does about connectivity, speed, composability, and security
- [Installing](https://greaber.github.io/syq/install.html)
- [Command reference](https://greaber.github.io/syq/reference.html)
- [Speed](https://greaber.github.io/syq/speed.html) and
  [Server tuning](https://greaber.github.io/syq/server-tuning.html)
- [Remote-to-remote transfers](https://greaber.github.io/syq/remote-to-remote.html)
- [Security](https://greaber.github.io/syq/security.html)
- [Composability](https://greaber.github.io/syq/composability.html) and
  [Mappings](https://greaber.github.io/syq/mappings.html)
- [Rsync compatibility record](https://greaber.github.io/syq/rsync-compat.html)

Syq is 0.1.x software for Linux and macOS. `syq rsync` is the most stable
surface; native commands are experimental and their grammar may change between
releases. To report a vulnerability, see [SECURITY.md](https://github.com/greaber/syq/blob/master/SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
