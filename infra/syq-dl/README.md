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

    /latest/<asset>    resolves the current tag, records it, serves that tag's asset
    /<tag>/<asset>     records, serves from the edge cache (fetching GitHub on a miss)

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

To drop a cached asset, purge its URL; the token needs the zone's Cache Purge
permission, which the stored one does not have yet (add it to the token in the
Cloudflare dashboard):

    curl -X POST https://api.cloudflare.com/client/v4/zones/42640319e93a7dde7f09b46c5c9f69a7/purge_cache \
      -H "Authorization: Bearer $(dotenvx get CLOUDFLARE_API_TOKEN -f ../../.env.release)" \
      -H 'Content-Type: application/json' \
      -d '{"files":["https://dl.syq.christmas/v0.6.0/syq-linux-x86_64.gz"]}'

Query recorded events the same way:

    dotenvx run -f ../../.env.release -- npx wrangler d1 execute syq-dl --remote \
      --command 'select * from daily_checks order by day desc limit 20'
