-- name: ListSchemaMigrationVersions :many
SELECT version FROM schema_migrations;

-- name: RecordSchemaMigration :exec
INSERT INTO schema_migrations (version, name, applied_at)
VALUES (?, ?, ?);
