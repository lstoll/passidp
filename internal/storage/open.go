package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"lds.li/passidp/internal/storage/migrations"
	_ "modernc.org/sqlite"
)

const (
	sqliteOpenPragmas     = "_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	sqliteTestOpenPragmas = "mode=memory&cache=shared&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
)

// Open opens (or creates) a SQLite database at path, runs pending migrations,
// and returns the raw *sql.DB handle.
func Open(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?%s", path, sqliteOpenPragmas)
	sqlDB, err := openDB(dsn)
	if err != nil {
		return nil, err
	}
	ReportStateFileSize(path)
	return sqlDB, nil
}

// OpenTest opens an in-memory SQLite database with migrations applied.
// The database is closed automatically when the test finishes.
func OpenTest(t testing.TB) *sql.DB {
	t.Helper()

	name := sanitizeTestDBName(t.Name())
	dsn := fmt.Sprintf("file:%s?%s", name, sqliteTestOpenPragmas)
	sqlDB, err := openDB(dsn)
	if err != nil {
		t.Fatalf("open test sqlite: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	return sqlDB
}

func openDB(dsn string) (*sql.DB, error) {
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping sqlite database: %w", err)
	}

	if err := migrations.Apply(context.Background(), sqlDB); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("apply migrations: %w", err)
	}

	return sqlDB, nil
}

func sanitizeTestDBName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
