-- NELUUN V9.5: authenticator-app (TOTP) second factor for the parent step-up.
-- Additive. Secrets are stored AES-GCM encrypted; recovery codes only as peppered hashes.
CREATE TABLE IF NOT EXISTS parent_totp (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret_enc TEXT NOT NULL,
  confirmed_at INTEGER,
  last_step INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS parent_totp_recovery (
  code_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_parent_totp_recovery_user ON parent_totp_recovery(user_id);
