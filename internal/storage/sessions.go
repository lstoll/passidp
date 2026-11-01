package storage

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"lds.li/session/sqlkv"
)

const sessionTableName = "sessions"

// NewSessionKV returns a SQL-backed session store using the shared SQLite database.
func NewSessionKV(sqlDB *sql.DB) (*sqlkv.SqlKV, error) {
	kv, err := sqlkv.New(sqlDB, &sqlkv.Opts{
		Dialect:   sqlkv.SQLite,
		TableName: sessionTableName,
	})
	if err != nil {
		return nil, err
	}
	return kv, nil
}

// SessionGarbageCollector returns a run.Group-compatible worker that periodically
// garbage-collects expired sessions.
func SessionGarbageCollector(kv *sqlkv.SqlKV, interval time.Duration) (execute func() error, interrupt func(error)) {
	stopCh := make(chan struct{})

	return func() error {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			runSessionGC(kv)

			for {
				select {
				case <-ticker.C:
					runSessionGC(kv)
				case <-stopCh:
					return nil
				}
			}
		},
		func(error) {
			close(stopCh)
		}
}

func runSessionGC(kv *sqlkv.SqlKV) {
	log := slog.With("component", "session_garbage_collector")
	log.Info("starting")

	deleted, err := kv.GC(context.Background())
	if err != nil {
		log.Error("garbage collect sessions", slog.String("error", err.Error()))
	} else if deleted > 0 {
		log.Info("garbage collected sessions", slog.Int("deleted", deleted))
	}

	log.Info("finished garbage collection")
}
