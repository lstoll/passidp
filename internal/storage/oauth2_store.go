package storage

import (
	"context"
	"database/sql"
	"fmt"

	"lds.li/passidp/internal/oauth2as"
)

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
