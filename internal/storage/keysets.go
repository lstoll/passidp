package storage

import (
	"database/sql"

	"lds.li/keyset/insecurecleartext"
	"lds.li/keyset/sqlstore"
)

const keysetTableName = "keysets"

// NewKeysetStore uses cleartext key material explicitly. Deployments can
// introduce a Keeper once a persistent wrapping-key source is available.
// Its table is created by the application migrations.
func NewKeysetStore(db *sql.DB) (*sqlstore.Store, error) {
	store, err := sqlstore.New(db, insecurecleartext.Keeper,
		sqlstore.WithDialect(sqlstore.SQLite),
		sqlstore.WithTable(keysetTableName),
	)
	if err != nil {
		return nil, err
	}
	return store, nil
}
