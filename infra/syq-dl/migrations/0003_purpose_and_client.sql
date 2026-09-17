-- purpose: "check" for the daily background reminder check, "interactive"
-- for --self-update and remote bootstrap manifest fetches (sent by syq >= the
-- first release from this host). client: which program made the request.
ALTER TABLE events ADD COLUMN purpose TEXT;
ALTER TABLE events ADD COLUMN client TEXT;

DROP VIEW IF EXISTS daily_checks;
CREATE VIEW daily_checks AS
  SELECT day, client_version, target, country, COUNT(*) AS checks
  FROM events
  WHERE kind = 'manifest' AND latest = 1 AND purpose = 'check'
  GROUP BY day, client_version, target, country;
