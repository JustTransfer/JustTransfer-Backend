-- down.sql
ALTER TABLE link_transfers DROP COLUMN session_version;
ALTER TABLE users DROP COLUMN session_version;
