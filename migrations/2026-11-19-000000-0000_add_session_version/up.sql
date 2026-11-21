-- up.sql
-- Bumped whenever existing sessions must stop being accepted (password change/reset, key rotation)
ALTER TABLE users ADD COLUMN session_version BIGINT NOT NULL DEFAULT 0;
