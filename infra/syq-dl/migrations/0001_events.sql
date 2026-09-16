-- One row per request that reached the download host. Append-only.
CREATE TABLE IF NOT EXISTS events (
  id        INTEGER PRIMARY KEY,
  ts        TEXT    NOT NULL,           -- ISO-8601 UTC, second precision
  day       TEXT    NOT NULL,           -- YYYY-MM-DD, for cheap grouping
  kind      TEXT    NOT NULL,           -- installer | manifest | archive | binary | checksum | formula | other
  tag       TEXT,                       -- resolved release tag, e.g. v0.6.0
  latest    INTEGER NOT NULL DEFAULT 0, -- 1 when the request used /latest/
  asset     TEXT    NOT NULL,
  target    TEXT,                       -- linux-x86_64, macos-arm64, ... from asset name or X-Syq-Target
  client_version TEXT,                  -- from a "syq/x.y.z" user agent, else NULL
  user_agent TEXT,
  country   TEXT,                       -- ISO 3166-1 alpha-2 from Cloudflare
  region    TEXT,
  city      TEXT,
  colo      TEXT,
  ip        TEXT,
  status    INTEGER NOT NULL            -- HTTP status returned
);
CREATE INDEX IF NOT EXISTS events_day ON events(day);
CREATE INDEX IF NOT EXISTS events_kind_day ON events(kind, day);

-- Daily update checks from installed clients: a daily-active proxy.
-- Only installer-managed clients make this request, once per machine per day.
CREATE VIEW IF NOT EXISTS daily_checks AS
  SELECT day, client_version, target, country, COUNT(*) AS checks
  FROM events
  WHERE kind = 'manifest' AND latest = 1 AND client_version IS NOT NULL
  GROUP BY day, client_version, target, country;

-- Archive downloads are installs or upgrades: installer, Homebrew, or remote-helper bootstrap.
CREATE VIEW IF NOT EXISTS daily_installs AS
  SELECT day, tag, target, country, COUNT(*) AS downloads
  FROM events
  WHERE kind = 'archive'
  GROUP BY day, tag, target, country;
