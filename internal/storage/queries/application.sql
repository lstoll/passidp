-- name: CreatePendingEnrollment :exec
INSERT INTO pending_enrollments (id, user_id, enrollment_key, created_at, expires_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetPendingEnrollmentByKey :one
SELECT id, user_id, enrollment_key, created_at, expires_at
FROM pending_enrollments
WHERE enrollment_key = ?;

-- name: GetPendingEnrollmentByID :one
SELECT id, user_id, enrollment_key, created_at, expires_at
FROM pending_enrollments
WHERE id = ?;

-- name: ConsumePendingEnrollment :one
DELETE FROM pending_enrollments
WHERE id = ? AND expires_at > ?
RETURNING id, user_id, enrollment_key, created_at, expires_at;

-- name: ListPendingEnrollmentsByUser :many
SELECT id, user_id, enrollment_key, created_at, expires_at
FROM pending_enrollments
WHERE user_id = ?;

-- name: GarbageCollectPendingEnrollments :execrows
DELETE FROM pending_enrollments
WHERE expires_at < ?;

-- name: CreateDynamicClient :exec
INSERT INTO dynamic_clients (id, active, expires_at, created_at, client_secret, registration_blob)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetDynamicClientByID :one
SELECT id, active, expires_at, created_at, client_secret, registration_blob
FROM dynamic_clients
WHERE id = ?;

-- name: DeactivateDynamicClient :exec
UPDATE dynamic_clients SET active = false WHERE id = ?;

-- name: ListActiveDynamicClients :many
SELECT id, active, expires_at, created_at, client_secret, registration_blob
FROM dynamic_clients
WHERE active = true AND expires_at > ?
ORDER BY created_at DESC;

-- name: CleanupExpiredDynamicClients :execrows
DELETE FROM dynamic_clients
WHERE active = false OR expires_at < ?;

-- name: InsertDPoPProof :execrows
INSERT INTO dpop_replay (proof_key, until)
VALUES (?, ?)
ON CONFLICT(proof_key) DO NOTHING;

-- name: RefreshExpiredDPoPProof :execrows
UPDATE dpop_replay
SET until = sqlc.arg(until)
WHERE proof_key = sqlc.arg(proof_key) AND until < sqlc.arg(cutoff);

-- name: GarbageCollectDPoPProofs :execrows
DELETE FROM dpop_replay
WHERE until < ?;
