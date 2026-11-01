package storage

import (
	"context"
	"log/slog"
	"time"

	"lds.li/passidp/internal/oauth2as"
)

// OAuth2GarbageCollector returns a run.Group-compatible worker that periodically
// garbage-collects expired OAuth2 state.
func OAuth2GarbageCollector(store *oauth2as.Storage, interval time.Duration) (execute func() error, interrupt func(error)) {
	stopCh := make(chan struct{})

	return func() error {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			runOAuth2GC(store)

			for {
				select {
				case <-ticker.C:
					runOAuth2GC(store)
				case <-stopCh:
					return nil
				}
			}
		},
		func(error) {
			close(stopCh)
		}
}

func runOAuth2GC(store *oauth2as.Storage) {
	log := slog.With("component", "oauth2_garbage_collector")
	log.Info("starting")

	ctx := context.Background()
	var deleted int
	for {
		result, err := store.Cleanup(ctx, oauth2as.CleanupOptions{})
		if err != nil {
			log.Error("garbage collect oauth2 state", slog.String("error", err.Error()))
			return
		}
		deleted += result.Deleted
		if !result.More {
			break
		}
	}
	if deleted > 0 {
		log.Info("garbage collected oauth2 state",
			slog.Int("records_deleted", deleted))
	}

	log.Info("finished garbage collection")
}

// EnrollmentGarbageCollector returns a run.Group-compatible worker that periodically
// garbage-collects expired pending enrollments.
func EnrollmentGarbageCollector(store *EnrollmentStore, interval time.Duration) (execute func() error, interrupt func(error)) {
	stopCh := make(chan struct{})

	return func() error {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			runEnrollmentGC(store)

			for {
				select {
				case <-ticker.C:
					runEnrollmentGC(store)
				case <-stopCh:
					return nil
				}
			}
		},
		func(error) {
			close(stopCh)
		}
}

func runEnrollmentGC(store *EnrollmentStore) {
	log := slog.With("component", "enrollment_garbage_collector")
	log.Info("starting")

	deleted, err := store.GarbageCollectPendingEnrollments()
	if err != nil {
		log.Error("garbage collect pending enrollments", slog.String("error", err.Error()))
	} else if deleted > 0 {
		log.Info("garbage collected pending enrollments", slog.Int("deleted", deleted))
	}

	log.Info("finished garbage collection")
}

// DynamicClientGarbageCollector returns a run.Group-compatible worker that periodically
// garbage-collects expired dynamic clients.
func DynamicClientGarbageCollector(store *DynamicClientStore, interval time.Duration) (execute func() error, interrupt func(error)) {
	stopCh := make(chan struct{})

	return func() error {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			runDynamicClientGC(store)

			for {
				select {
				case <-ticker.C:
					runDynamicClientGC(store)
				case <-stopCh:
					return nil
				}
			}
		},
		func(error) {
			close(stopCh)
		}
}

func runDynamicClientGC(store *DynamicClientStore) {
	log := slog.With("component", "dynamic_client_garbage_collector")
	log.Info("starting")

	deleted, err := store.CleanupExpiredDynamicClients()
	if err != nil {
		log.Error("garbage collect dynamic clients", slog.String("error", err.Error()))
	} else if deleted > 0 {
		log.Info("garbage collected dynamic clients", slog.Int("deleted", deleted))
	}

	log.Info("finished garbage collection")
}

// DPoPReplayGarbageCollector returns a run.Group-compatible worker that periodically
// garbage-collects expired DPoP replay records.
func DPoPReplayGarbageCollector(store *DPoPReplayStore, interval time.Duration) (execute func() error, interrupt func(error)) {
	stopCh := make(chan struct{})

	return func() error {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			runDPoPReplayGC(store)

			for {
				select {
				case <-ticker.C:
					runDPoPReplayGC(store)
				case <-stopCh:
					return nil
				}
			}
		},
		func(error) {
			close(stopCh)
		}
}

func runDPoPReplayGC(store *DPoPReplayStore) {
	log := slog.With("component", "dpop_replay_garbage_collector")
	log.Info("starting")

	deleted, err := store.GarbageCollectExpiredProofs()
	if err != nil {
		log.Error("garbage collect dpop replay records", slog.String("error", err.Error()))
	} else if deleted > 0 {
		log.Info("garbage collected dpop replay records", slog.Int("deleted", deleted))
	}

	log.Info("finished garbage collection")
}
