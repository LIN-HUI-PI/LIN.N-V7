-- NELUUN V9.5: additive D1 migration for ADULT STEP-UP sessions.
-- Apply only to a new isolated V9.5 test D1 database first. Never apply to V7.
-- No children, guardian identity or private notes are stored in these tables.
CREATE TABLE IF NOT EXISTS parent_challenges (
  session_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  sent_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS parent_grants (
  session_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_parent_grants_expiry ON parent_grants(expires_at);
CREATE INDEX IF NOT EXISTS idx_parent_challenges_expiry ON parent_challenges(expires_at);
