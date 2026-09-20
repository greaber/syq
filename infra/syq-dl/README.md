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

Wrangler needs CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN supplied
through its environment, or authentication through Wrangler's own login.
Use your preferred credential manager; this repository does not load a
credential store. Run from the worktree containing the worker you intend to deploy:

    cd infra/syq-dl
    npm install
    npx wrangler deploy
    npx wrangler d1 migrations apply syq-dl --remote

Query recorded events using the same authentication:

    npx wrangler d1 execute syq-dl --remote \
      --command 'select * from daily_checks order by day desc limit 20'

Cache purges use Cloudflare's API and require a token with Cache Purge
permission for the target zone. Deployment credentials do not necessarily
include that permission.
