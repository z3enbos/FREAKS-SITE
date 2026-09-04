-- Freaks Web Panel migration
-- Rulează o singură dată pe aceeași bază de date folosită de freaks_auth.

ALTER TABLE freaks_accounts
  ADD COLUMN IF NOT EXISTS fivem_name VARCHAR(128) NULL AFTER email,
  ADD COLUMN IF NOT EXISTS user_id INT NULL AFTER fivem_name,
  ADD COLUMN IF NOT EXISTS flcoins BIGINT NOT NULL DEFAULT 0 AFTER user_id;

CREATE INDEX IF NOT EXISTS idx_freaks_accounts_user_id
  ON freaks_accounts (user_id);