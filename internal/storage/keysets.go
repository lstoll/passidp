package storage

import (
	"context"
	"database/sql"
	"fmt"

	"lds.li/keyset/insecurecleartext"
	"lds.li/keyset/sqlstore"
)

const keysetTableName = "keysets"

// NewKeysetStore uses cleartext key material explicitly. Deployments can
// introduce a Keeper once a persistent wrapping-key source is available.
// Schema() is applied after migrations, including the reset that drops the
// previous envelope format.
func NewKeysetStore(db *sql.DB) (*sqlstore.Store, error) {
	store, err := sqlstore.New(db, insecurecleartext.Keeper,
		sqlstore.WithDialect(sqlstore.SQLite),
		sqlstore.WithTable(keysetTableName),
	)
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(context.Background(), store.Schema()); err != nil {
		return nil, fmt.Errorf("apply keyset schema: %w", err)
	}
	return store, nil
}
