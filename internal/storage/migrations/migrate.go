// Package migrations applies the shared PassIDP SQLite schema.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"lds.li/passidp/internal/storage/dbsql"
)

// Numbered migrations and bootstrap.sql are also the schema input for sqlc.
// Bootstrap creates migration metadata before the numbered migrations run.
//
//go:embed [0-9]*.sql
var migrationFS embed.FS

//go:embed bootstrap.sql
var bootstrapSQL string

var migrationFilePattern = regexp.MustCompile(`^(\d+)_(.+)\.sql$`)

type migration struct {
	version int
	name    string
	stmts   []string
}

// Apply runs pending migrations in a single transaction.
func Apply(ctx context.Context, db *sql.DB) error {
	migrations, err := loadMigrations(migrationFS)
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, bootstrapSQL); err != nil {
		return fmt.Errorf("create schema migrations table: %w", err)
	}

	queries := dbsql.New(tx)
	versions, err := queries.ListSchemaMigrationVersions(ctx)
	if err != nil {
		return fmt.Errorf("list schema migrations: %w", err)
	}
	applied := make(map[int64]struct{})
	for _, version := range versions {
		applied[version] = struct{}{}
	}

	known := make(map[int64]struct{}, len(migrations))
	for _, m := range migrations {
		known[int64(m.version)] = struct{}{}
	}
	for version := range applied {
		if _, ok := known[version]; !ok {
			return fmt.Errorf("database schema version %d is newer than this binary", version)
		}
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, m := range migrations {
		if _, ok := applied[int64(m.version)]; ok {
			continue
		}
		for version := range applied {
			if version > int64(m.version) {
				return fmt.Errorf("database schema is missing version %d", m.version)
			}
		}
		for _, stmt := range m.stmts {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("apply migration %d %s: %w", m.version, m.name, err)
			}
		}
		if err := queries.RecordSchemaMigration(ctx, dbsql.RecordSchemaMigrationParams{
			Version: int64(m.version), Name: m.name, AppliedAt: now,
		}); err != nil {
			return fmt.Errorf("record migration %d %s: %w", m.version, m.name, err)
		}
		applied[int64(m.version)] = struct{}{}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema migration: %w", err)
	}
	return nil
}

func loadMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}

	migrations := make([]migration, 0, len(entries))
	seen := make(map[int]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		match := migrationFilePattern.FindStringSubmatch(entry.Name())
		if match == nil {
			return nil, fmt.Errorf("invalid migration filename %q", entry.Name())
		}
		version, err := strconv.Atoi(match[1])
		if err != nil {
			return nil, fmt.Errorf("invalid migration version in %q: %w", entry.Name(), err)
		}
		if version <= 0 {
			return nil, fmt.Errorf("migration version in %q must be positive", entry.Name())
		}
		if existing, ok := seen[version]; ok {
			return nil, fmt.Errorf("duplicate migration version %d (%s and %s)", version, existing, entry.Name())
		}
		body, err := fs.ReadFile(fsys, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		stmts := splitStatements(string(body))
		if len(stmts) == 0 {
			return nil, fmt.Errorf("migration %s has no statements", entry.Name())
		}
		seen[version] = entry.Name()
		migrations = append(migrations, migration{version: version, name: match[2], stmts: stmts})
	}
	if len(migrations) == 0 {
		return nil, fmt.Errorf("no migrations found")
	}
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})
	return migrations, nil
}

func splitStatements(sqlText string) []string {
	var stmts []string
	var b strings.Builder
	for line := range strings.SplitSeq(sqlText, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(trimmed)
		if strings.HasSuffix(trimmed, ";") {
			stmt := strings.TrimSuffix(b.String(), ";")
			stmt = strings.TrimSpace(stmt)
			if stmt != "" {
				stmts = append(stmts, stmt)
			}
			b.Reset()
		}
	}
	if leftover := strings.TrimSpace(b.String()); leftover != "" {
		stmts = append(stmts, leftover)
	}
	return stmts
}
