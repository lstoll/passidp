-- Drop the previous keyset envelopes. The material-only keyset format is not
-- compatible, and signing/session secrets are regenerated on startup.
DROP TABLE IF EXISTS keysets;
