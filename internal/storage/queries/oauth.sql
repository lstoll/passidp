-- name: GetOAuthGrant :one
SELECT * FROM oauth2as_grants WHERE id = ?;

-- name: InsertOAuthGrant :exec
INSERT INTO oauth2as_grants (id, user_id, client_id, granted_scopes, redirect_uri, code_challenge, nonce, max_age, granted_at, authenticated_at, expires_at, dpop_thumbprint, acr, amr, version)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(client_id), sqlc.arg(granted_scopes), sqlc.arg(redirect_uri), sqlc.arg(code_challenge), sqlc.arg(nonce), sqlc.arg(max_age), sqlc.arg(granted_at), sqlc.arg(authenticated_at), sqlc.arg(expires_at), sqlc.arg(dpop_thumbprint), sqlc.arg(acr), sqlc.arg(amr), sqlc.arg(version));

-- name: DeleteOAuthGrant :exec
DELETE FROM oauth2as_grants WHERE id = ?;

-- name: CleanupOAuthGrants :execrows
DELETE FROM oauth2as_grants WHERE id IN (
 SELECT oauth2as_grants.id FROM oauth2as_grants WHERE oauth2as_grants.expires_at <= sqlc.arg(cutoff)
 ORDER BY oauth2as_grants.expires_at LIMIT sqlc.arg(max_rows)
);

-- name: InsertOAuthAuthCode :exec
INSERT INTO oauth2as_authorization_codes (id, grant_id, valid_until, delete_after)
VALUES (sqlc.arg(id), sqlc.arg(grant_id), sqlc.arg(valid_until), sqlc.arg(delete_after));

-- name: CleanupOAuthAuthCodes :execrows
DELETE FROM oauth2as_authorization_codes WHERE id IN (
 SELECT oauth2as_authorization_codes.id FROM oauth2as_authorization_codes WHERE oauth2as_authorization_codes.delete_after <= sqlc.arg(cutoff)
 ORDER BY oauth2as_authorization_codes.delete_after LIMIT sqlc.arg(max_rows)
);

-- name: InsertOAuthRefreshToken :exec
INSERT INTO oauth2as_refresh_tokens (id, grant_id, valid_until, delete_after, replaced_by_id)
VALUES (sqlc.arg(id), sqlc.arg(grant_id), sqlc.arg(valid_until), sqlc.arg(delete_after), sqlc.arg(replaced_by_id));

-- name: UpdateOAuthRefreshToken :execrows
UPDATE oauth2as_refresh_tokens SET grant_id = sqlc.arg(grant_id), valid_until = sqlc.arg(valid_until), delete_after = sqlc.arg(delete_after), replaced_by_id = sqlc.arg(replaced_by_id)
WHERE id = sqlc.arg(id);

-- name: DeleteOAuthRefreshToken :exec
DELETE FROM oauth2as_refresh_tokens WHERE id = ?;

-- name: CleanupOAuthRefreshTokens :execrows
DELETE FROM oauth2as_refresh_tokens WHERE id IN (
 SELECT oauth2as_refresh_tokens.id FROM oauth2as_refresh_tokens WHERE oauth2as_refresh_tokens.delete_after <= sqlc.arg(cutoff)
 ORDER BY oauth2as_refresh_tokens.delete_after LIMIT sqlc.arg(max_rows)
);

-- name: UpsertOAuthRefreshSession :exec
INSERT INTO oauth2as_refresh_sessions (grant_id, expires_at, last_used_at)
VALUES (sqlc.arg(grant_id), sqlc.arg(expires_at), sqlc.arg(last_used_at))
ON CONFLICT(grant_id) DO UPDATE SET expires_at = excluded.expires_at, last_used_at = excluded.last_used_at;

-- name: DeleteOAuthRefreshSession :exec
DELETE FROM oauth2as_refresh_sessions WHERE grant_id = ?;

-- name: CleanupOAuthRefreshSessions :execrows
DELETE FROM oauth2as_refresh_sessions WHERE grant_id IN (
 SELECT oauth2as_refresh_sessions.grant_id FROM oauth2as_refresh_sessions WHERE oauth2as_refresh_sessions.expires_at <= sqlc.arg(cutoff)
 ORDER BY oauth2as_refresh_sessions.expires_at LIMIT sqlc.arg(max_rows)
);

-- name: ListOAuthRefreshSessions :many
SELECT rs.grant_id, g.user_id, g.client_id, g.granted_scopes, g.granted_at, g.authenticated_at,
       rs.expires_at, rs.last_used_at, g.dpop_thumbprint
FROM oauth2as_refresh_sessions rs JOIN oauth2as_grants g ON g.id = rs.grant_id
WHERE g.user_id = sqlc.arg(user_id) AND rs.expires_at > sqlc.arg(active_at)
 AND (g.client_id = sqlc.arg(client_id) OR sqlc.arg(client_id) = '')
 AND (rs.grant_id > sqlc.arg(after_grant_id) AND rs.last_used_at = sqlc.arg(after_last_used)
      OR sqlc.arg(after_grant_id) = '' OR rs.last_used_at < sqlc.arg(after_last_used))
ORDER BY rs.last_used_at DESC, rs.grant_id ASC LIMIT sqlc.arg(max_rows);

-- name: InsertOAuthClientAssertion :execrows
INSERT INTO oauth2as_client_assertions (assertion_key, expires_at)
VALUES (sqlc.arg(assertion_key), sqlc.arg(expires_at))
ON CONFLICT(assertion_key) DO NOTHING;

-- name: ReuseExpiredOAuthClientAssertion :execrows
UPDATE oauth2as_client_assertions SET expires_at = sqlc.arg(expires_at)
WHERE assertion_key = sqlc.arg(assertion_key) AND expires_at <= sqlc.arg(cutoff);

-- name: CleanupOAuthClientAssertions :execrows
DELETE FROM oauth2as_client_assertions WHERE assertion_key IN (
 SELECT oauth2as_client_assertions.assertion_key FROM oauth2as_client_assertions WHERE oauth2as_client_assertions.expires_at <= sqlc.arg(cutoff)
 ORDER BY oauth2as_client_assertions.expires_at LIMIT sqlc.arg(max_rows)
);

-- name: HasExpiredOAuthRecords :one
SELECT EXISTS (
 SELECT 1 FROM oauth2as_refresh_sessions WHERE oauth2as_refresh_sessions.expires_at <= sqlc.arg(cutoff)
 UNION ALL SELECT 1 FROM oauth2as_authorization_codes WHERE oauth2as_authorization_codes.delete_after <= sqlc.arg(cutoff)
 UNION ALL SELECT 1 FROM oauth2as_refresh_tokens WHERE oauth2as_refresh_tokens.delete_after <= sqlc.arg(cutoff)
 UNION ALL SELECT 1 FROM oauth2as_grants WHERE oauth2as_grants.expires_at <= sqlc.arg(cutoff)
 UNION ALL SELECT 1 FROM oauth2as_client_assertions WHERE oauth2as_client_assertions.expires_at <= sqlc.arg(cutoff)
);

-- name: GetOAuthAuthCodeAndGrant :one
SELECT sqlc.embed(c), sqlc.embed(g)
FROM oauth2as_authorization_codes c JOIN oauth2as_grants g ON g.id = c.grant_id
WHERE c.id = ?;

-- name: GetOAuthRefreshTokenAndGrant :one
SELECT sqlc.embed(t), sqlc.embed(g)
FROM oauth2as_refresh_tokens t JOIN oauth2as_grants g ON g.id = t.grant_id
WHERE t.id = ?;

-- name: ConsumeOAuthAuthCode :execrows
UPDATE oauth2as_authorization_codes SET consumed_at = sqlc.arg(consumed_at)
WHERE id = sqlc.arg(id) AND grant_id = sqlc.arg(grant_id) AND consumed_at IS NULL;

-- name: RevokeOAuthGrantForUser :execrows
DELETE FROM oauth2as_grants WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id);

-- name: AdvanceOAuthGrantRevision :execrows
UPDATE oauth2as_grants
SET dpop_thumbprint = sqlc.arg(dpop_thumbprint), version = version + 1
WHERE id = sqlc.arg(id) AND version = sqlc.arg(version);
