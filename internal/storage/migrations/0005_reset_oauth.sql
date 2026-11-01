-- Discard OAuth state from the former standalone migration runner.
-- Existing grants and tokens are intentionally invalidated once.
DROP TABLE IF EXISTS oauth2as_refresh_sessions;
DROP TABLE IF EXISTS oauth2as_refresh_tokens;
DROP TABLE IF EXISTS oauth2as_authorization_codes;
DROP TABLE IF EXISTS oauth2as_grants;
DROP TABLE IF EXISTS oauth2as_schema_migrations;
