-- NELUUN V9.5: additive D1 migration for CHILD profiles and parent-approved child sessions.
-- Apply only to the isolated V9.5 test D1 database, after 0001 and 0002. Never apply to V7.
-- Data minimisation: a child profile holds only a nickname and an avatar id. No real name,
-- email, birth date, school or free-text notes are stored.
CREATE TABLE IF NOT EXISTS children (
  id TEXT PRIMARY KEY,
  guardian_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  nickname TEXT NOT NULL,
  avatar TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_children_guardian ON children(guardian_user_id);

-- One-time entry codes issued by a verified adult (step-up) for one child.
-- Only a peppered hash is stored; the plain code is shown once on the adult screen.
CREATE TABLE IF NOT EXISTS child_entry_codes (
  code_hash TEXT PRIMARY KEY,
  child_id TEXT NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  guardian_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_minutes INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_child_codes_child ON child_entry_codes(child_id);
CREATE INDEX IF NOT EXISTS idx_child_codes_expiry ON child_entry_codes(expires_at);

-- Child sessions live in their own table so an adult session lookup can never match one.
CREATE TABLE IF NOT EXISTS child_sessions (
  token_hash TEXT PRIMARY KEY,
  child_id TEXT NOT NULL REFERENCES children(id) ON DELETE CASCADE,
  guardian_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_child_sessions_child ON child_sessions(child_id);
CREATE INDEX IF NOT EXISTS idx_child_sessions_expiry ON child_sessions(expires_at);
