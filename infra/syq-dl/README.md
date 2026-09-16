# syq-dl

The download host at `https://dl.syq.christmas`. Every request records one
row in a D1 database and serves the matching GitHub release asset from the
Cloudflare edge cache, fetching it from GitHub on a miss. Tagged assets are
immutable, so they cache for a year; the tag behind `/latest/` is re-resolved
every five minutes. If GitHub cannot be fetched, the client is redirected to
GitHub to try directly. GitHub stays the immutable source of the bytes, and
every syq client verifies what it downloads against the signed release
manifest, so this host can only delay or withhold a download, never
substitute one. Responses carry `x-syq-cache: hit` or `miss`.

URL shapes mirror GitHub's release URLs:

    /latest/<asset>    resolves the current tag, records it, redirects
    /<tag>/<asset>     records, redirects

`migrations/0001_events.sql` holds the schema and two reporting views:
`daily_checks` (background reminder checks from installed clients, a
daily-active proxy; explicit `--self-update` fetches are excluded by the
`x-syq-purpose` header) and `daily_installs` (downloads by kind, tag, target, and country; kind `archive`
is the installer or a remote helper bootstrap, kind `binary` is Homebrew).

## Deploying

The Cloudflare account ID and API token live in the encrypted `.env.release`
inventory at the repository root. Run wrangler through dotenvx so they are
available without leaving the shell:

    cd infra/syq-dl
    npm install
    dotenvx run -f ../../.env.release -- npx wrangler deploy
    dotenvx run -f ../../.env.release -- npx wrangler d1 migrations apply syq-dl --remote

Query recorded events the same way:

    dotenvx run -f ../../.env.release -- npx wrangler d1 execute syq-dl --remote \
      --command 'select * from daily_checks order by day desc limit 20'
