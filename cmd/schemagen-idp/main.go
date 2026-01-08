package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"lds.li/passidp/db"
)

func main() {
	ctx := context.Background()

	if len(os.Args) < 2 {
		slog.Error("no output file specified")
		os.Exit(1)
	}
	outputFile := os.Args[1]

	slog.Info("schemagen-idp running migrations")
	dbConn, err := sql.Open("sqlite3", "file:test.db?mode=memory&cache=shared")
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer dbConn.Close()

	if err := db.Migrate(ctx, dbConn); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	slog.Info("schemagen-idp migrations complete, exporting schema")

	// Query to get the schema
	rows, err := dbConn.Query("SELECT sql FROM sqlite_master WHERE type='table'")
	if err != nil {
		slog.Error("failed to query schema", "error", err)
		os.Exit(1)
	}
	defer rows.Close()

	// Create output file
	f, err := os.Create(outputFile)
	if err != nil {
		slog.Error("failed to create output file", "error", err)
		os.Exit(1)
	}
	defer f.Close()

	// Write each table's schema to the file
	for rows.Next() {
		var sql string
		if err := rows.Scan(&sql); err != nil {
			slog.Error("failed to scan schema row", "error", err)
			os.Exit(1)
		}
		if _, err := f.WriteString(sql + ";\n\n"); err != nil {
			slog.Error("failed to write schema to file", "error", err)
			os.Exit(1)
		}
	}

	if err := rows.Err(); err != nil {
		slog.Error("error iterating schema rows", "error", err)
		os.Exit(1)
	}

	slog.Info("schema exported successfully", "file", outputFile)
}
