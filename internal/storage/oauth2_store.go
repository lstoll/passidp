package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"lds.li/passidp/internal/oauth2as"
)

const oauth2asGrantsTable = "oauth2as_grants"

// NewOAuth2Storage returns oauth2as SQL storage on the shared SQLite database
// and applies its schema migrations.
func NewOAuth2Storage(ctx context.Context, db *sql.DB) (*oauth2as.Storage, error) {
	store, err := oauth2as.NewSQLStorage(db)
	if err != nil {
		return nil, err
	}
	if err := store.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate oauth2 storage: %w", err)
	}
	return store, nil
}

// OAuth2Grants inspects oauth2as grant records in the shared SQLite database.
type OAuth2Grants struct {
	db *sql.DB
}

// NewOAuth2Grants returns a helper for reading oauth2as grant metadata.
func NewOAuth2Grants(sqlDB *sql.DB) *OAuth2Grants {
	return &OAuth2Grants{db: sqlDB}
}

type oauth2asAdditionalState struct {
	DPoPThumbprint *string `json:"dpopThumbprint"`
}

// DPoPBound reports which of the given grant IDs currently have a DPoP
// thumbprint recorded by oauth2ext.
func (g *OAuth2Grants) DPoPBound(ctx context.Context, grantIDs []string) (map[string]bool, error) {
	bound := make(map[string]bool, len(grantIDs))
	if len(grantIDs) == 0 {
		return bound, nil
	}

	placeholders := strings.Repeat("?,", len(grantIDs))
	query := `SELECT id, additional_state FROM ` + oauth2asGrantsTable + ` WHERE id IN (` + placeholders[:len(placeholders)-1] + `)`
	args := make([]any, len(grantIDs))
	for i, id := range grantIDs {
		args[i] = id
	}

	rows, err := g.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("lookup dpop-bound grants: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id string
		var additionalState []byte
		if err := rows.Scan(&id, &additionalState); err != nil {
			return nil, fmt.Errorf("lookup dpop-bound grants: %w", err)
		}
		if len(additionalState) == 0 {
			continue
		}
		var state oauth2asAdditionalState
		if err := json.Unmarshal(additionalState, &state); err != nil {
			return nil, fmt.Errorf("decode grant additional state for %s: %w", id, err)
		}
		if state.DPoPThumbprint != nil && *state.DPoPThumbprint != "" {
			bound[id] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("lookup dpop-bound grants: %w", err)
	}
	return bound, nil
}
