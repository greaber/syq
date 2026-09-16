-- Homebrew fetches the uncompressed binary; the installer and the remote
-- helper bootstrap fetch the .gz archive. Keep the kind so the two channels
-- can be told apart.
DROP VIEW IF EXISTS daily_installs;
CREATE VIEW daily_installs AS
  SELECT day, kind, tag, target, country, COUNT(*) AS downloads
  FROM events
  WHERE kind IN ('archive', 'binary')
  GROUP BY day, kind, tag, target, country;
