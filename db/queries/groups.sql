-- name: GetUserActiveGroupMembershipsForMigration :many
SELECT ug.*, g.name as group_name, g.description as group_description
FROM user_groups ug
JOIN groups g ON ug.group_id = g.id
WHERE ug.user_id = ?
  AND g.active = TRUE
  AND (ug.end_date IS NULL OR ug.end_date > CURRENT_TIMESTAMP)
ORDER BY g.name;
