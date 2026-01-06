-- name: CreateUserCredential :exec
INSERT INTO credentials (id, user_id, name, credential_id, credential_data, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetUsersForMigration :many
SELECT * FROM users;

-- name: GetUserCredentials :many
SELECT * FROM credentials c
WHERE user_id = ?;

-- name: UpdateCredentialDataByCredentialID :exec
UPDATE credentials SET credential_data = ? WHERE credential_id = ?;
