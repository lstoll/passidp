package storage_test

import (
	"sync"
	"testing"
	"time"
	"uuid"

	"lds.li/passidp/internal/storage"
)

func TestEnrollmentStore(t *testing.T) {
	store := storage.NewEnrollmentStore(storage.OpenTest(t))
	userID := uuid.New()

	enrollment, err := store.CreatePendingEnrollment(userID, storage.DefaultEnrollmentValidity)
	if err != nil {
		t.Fatalf("create enrollment: %v", err)
	}
	if enrollment.EnrollmentKey == "" {
		t.Fatal("expected enrollment key")
	}
	if enrollment.ExpiresAt.Sub(enrollment.CreatedAt) != storage.DefaultEnrollmentValidity {
		t.Fatalf("validity = %v, want %v", enrollment.ExpiresAt.Sub(enrollment.CreatedAt), storage.DefaultEnrollmentValidity)
	}

	byKey, err := store.GetPendingEnrollmentByKey(enrollment.EnrollmentKey)
	if err != nil {
		t.Fatalf("get by key: %v", err)
	}
	if byKey.ID != enrollment.ID {
		t.Fatalf("expected enrollment id %v, got %v", enrollment.ID, byKey.ID)
	}

	byID, err := store.GetPendingEnrollmentByID(enrollment.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if byID.EnrollmentKey != enrollment.EnrollmentKey {
		t.Fatalf("expected enrollment key %q, got %q", enrollment.EnrollmentKey, byKey.EnrollmentKey)
	}

	list, err := store.ListPendingEnrollmentsByUser(userID)
	if err != nil {
		t.Fatalf("list by user: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 enrollment, got %d", len(list))
	}

	consumed, err := store.ConsumePendingEnrollment(enrollment.ID)
	if err != nil {
		t.Fatalf("consume enrollment: %v", err)
	}
	if consumed.ID != enrollment.ID {
		t.Fatalf("expected consumed id %v, got %v", enrollment.ID, consumed.ID)
	}

	_, err = store.GetPendingEnrollmentByID(enrollment.ID)
	if err == nil {
		t.Fatal("expected consumed enrollment to be deleted")
	}
}

func TestConsumePendingEnrollmentExpired(t *testing.T) {
	sqlDB := storage.OpenTest(t)
	store := storage.NewEnrollmentStore(sqlDB)
	enrollment, err := store.CreatePendingEnrollment(uuid.New(), storage.DefaultEnrollmentValidity)
	if err != nil {
		t.Fatalf("create enrollment: %v", err)
	}
	if _, err := sqlDB.Exec(`UPDATE pending_enrollments SET expires_at = ? WHERE id = ?`, time.Now().Add(-time.Second), enrollment.ID); err != nil {
		t.Fatalf("backdate enrollment: %v", err)
	}
	if _, err := store.ConsumePendingEnrollment(enrollment.ID); err == nil || err.Error() != "enrollment expired" {
		t.Fatalf("consume expired enrollment error = %v, want enrollment expired", err)
	}
}

func TestConsumePendingEnrollmentConcurrent(t *testing.T) {
	store := storage.NewEnrollmentStore(storage.OpenTest(t))
	enrollment, err := store.CreatePendingEnrollment(uuid.New(), storage.DefaultEnrollmentValidity)
	if err != nil {
		t.Fatalf("create enrollment: %v", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			_, err := store.ConsumePendingEnrollment(enrollment.ID)
			results <- err
		})
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("successful consumes = %d, want 1", wins)
	}
}

func TestEnrollmentStoreExpired(t *testing.T) {
	sqlDB := storage.OpenTest(t)
	store := storage.NewEnrollmentStore(sqlDB)
	userID := uuid.New()

	enrollment, err := store.CreatePendingEnrollment(userID, storage.DefaultEnrollmentValidity)
	if err != nil {
		t.Fatalf("create enrollment: %v", err)
	}

	_, err = sqlDB.Exec(`UPDATE pending_enrollments SET expires_at = ? WHERE id = ?`, time.Now().Add(-time.Second), enrollment.ID)
	if err != nil {
		t.Fatalf("backdate enrollment: %v", err)
	}

	if _, err := store.GetPendingEnrollmentByID(enrollment.ID); err == nil {
		t.Fatal("expected expired enrollment to be rejected")
	}

	deleted, err := store.GarbageCollectPendingEnrollments()
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted enrollment, got %d", deleted)
	}
}
