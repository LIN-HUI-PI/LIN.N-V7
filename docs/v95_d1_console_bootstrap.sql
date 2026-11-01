-- NELUUN V9.5 ISOLATED TEST D1 ONLY.
-- STOP if the Cloudflare database name is NOT neluun-v95-auth-isolated-test.
-- DO NOT execute this in any V7, V9.4 or production database.
-- First confirm the database name and that there are no important preexisting records.

-- BEGIN migrations/0001_init.sql
-- NELUUN V9 - new isolated D1 schema; never migrate the old V7 database directly.
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_codes (
  email TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  issued_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS rate_limits (
  bucket TEXT PRIMARY KEY,
  hits INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS daily_ai_usage (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  day TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day)
);
CREATE TABLE IF NOT EXISTS guardian_declarations (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  declared_at INTEGER,
  withdrawn_at INTEGER,
  policy_version TEXT NOT NULL
);
-- END migrations/0001_init.sql

-- BEGIN migrations/0002_parent_access.sql
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
-- END migrations/0002_parent_access.sql

-- Verification: the result should list exactly 8 application tables.
SELECT name FROM sqlite_master WHERE type='table' AND name IN (
 'users','login_codes','sessions','rate_limits','daily_ai_usage',
 'guardian_declarations','parent_challenges','parent_grants'
) ORDER BY name;
