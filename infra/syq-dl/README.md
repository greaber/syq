# syq-dl

The download host at `https://dl.syq.christmas`. Every request records one
row in a D1 database and then redirects to the matching GitHub release asset.
GitHub stays the immutable source of the bytes, and every syq client verifies
what it downloads against the signed release manifest, so this host can only
delay or withhold a download, never substitute one.

URL shapes mirror GitHub's release URLs:

    /latest/<asset>    resolves the current tag, records it, redirects
    /<tag>/<asset>     records, redirects

`migrations/0001_events.sql` holds the schema and two reporting views:
`daily_checks` (daily update checks from installed clients, a daily-active
proxy) and `daily_installs` (archive downloads by tag, target, and country).

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
