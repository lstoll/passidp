package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"
	"uuid"

	"lds.li/passidp/internal/storage/dbsql"
)

const DefaultEnrollmentValidity = 15 * time.Minute

// EnrollmentStore persists in-progress credential enrollments in SQLite.
type EnrollmentStore struct {
	queries *dbsql.Queries
}

// PendingEnrollment is a short-lived passkey enrollment token.
type PendingEnrollment struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	EnrollmentKey string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// NewEnrollmentStore returns a SQL-backed pending enrollment store.
func NewEnrollmentStore(sqlDB *sql.DB) *EnrollmentStore {
	return &EnrollmentStore{queries: dbsql.New(sqlDB)}
}

func (e *EnrollmentStore) CreatePendingEnrollment(userID uuid.UUID, validity time.Duration) (PendingEnrollment, error) {
	if validity <= 0 {
		return PendingEnrollment{}, fmt.Errorf("enrollment validity must be positive")
	}
	now := time.Now()
	enrollment := PendingEnrollment{
		ID:            uuid.New(),
		UserID:        userID,
		EnrollmentKey: rand.Text(),
		CreatedAt:     now,
		ExpiresAt:     now.Add(validity),
	}

	err := e.queries.CreatePendingEnrollment(context.Background(), dbsql.CreatePendingEnrollmentParams{
		ID: enrollment.ID.String(), UserID: enrollment.UserID.String(),
		EnrollmentKey: enrollment.EnrollmentKey, CreatedAt: enrollment.CreatedAt,
		ExpiresAt: sql.NullTime{Time: enrollment.ExpiresAt, Valid: true},
	})
	if err != nil {
		return PendingEnrollment{}, fmt.Errorf("insert enrollment: %w", err)
	}
	return enrollment, nil
}

func (e *EnrollmentStore) GetPendingEnrollmentByKey(enrollmentKey string) (PendingEnrollment, error) {
	row, err := e.queries.GetPendingEnrollmentByKey(context.Background(), enrollmentKey)
	return e.pendingEnrollment(row, err)
}

func (e *EnrollmentStore) GetPendingEnrollmentByID(enrollmentID uuid.UUID) (PendingEnrollment, error) {
	row, err := e.queries.GetPendingEnrollmentByID(context.Background(), enrollmentID.String())
	return e.pendingEnrollment(row, err)
}

func (e *EnrollmentStore) pendingEnrollment(row dbsql.PendingEnrollment, err error) (PendingEnrollment, error) {
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PendingEnrollment{}, fmt.Errorf("enrollment not found")
		}
		return PendingEnrollment{}, fmt.Errorf("get enrollment: %w", err)
	}
	enrollment, err := convertPendingEnrollment(row)
	if err != nil {
		return PendingEnrollment{}, fmt.Errorf("get enrollment: %w", err)
	}
	if enrollment.Expired() {
		return PendingEnrollment{}, fmt.Errorf("enrollment expired")
	}
	return enrollment, nil
}

// ConsumePendingEnrollment deletes a still-valid enrollment and returns it.
func (e *EnrollmentStore) ConsumePendingEnrollment(enrollmentID uuid.UUID) (PendingEnrollment, error) {
	row, err := e.queries.ConsumePendingEnrollment(context.Background(), dbsql.ConsumePendingEnrollmentParams{
		ID: enrollmentID.String(), ExpiresAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			_, lookupErr := e.GetPendingEnrollmentByID(enrollmentID)
			if lookupErr != nil {
				return PendingEnrollment{}, lookupErr
			}
			return PendingEnrollment{}, fmt.Errorf("enrollment not found")
		}
		return PendingEnrollment{}, fmt.Errorf("delete enrollment: %w", err)
	}
	return convertPendingEnrollment(row)
}

func (e *EnrollmentStore) ListPendingEnrollmentsByUser(userID uuid.UUID) ([]PendingEnrollment, error) {
	rows, err := e.queries.ListPendingEnrollmentsByUser(context.Background(), userID.String())
	if err != nil {
		return nil, fmt.Errorf("list enrollments: %w", err)
	}
	var enrollments []PendingEnrollment
	for _, row := range rows {
		enrollment, err := convertPendingEnrollment(row)
		if err != nil {
			return nil, fmt.Errorf("list enrollments: %w", err)
		}
		if enrollment.Expired() {
			continue
		}
		enrollments = append(enrollments, enrollment)
	}
	return enrollments, nil
}

func (e *EnrollmentStore) GarbageCollectPendingEnrollments() (int, error) {
	deleted, err := e.queries.GarbageCollectPendingEnrollments(context.Background(), sql.NullTime{Time: time.Now(), Valid: true})
	if err != nil {
		return 0, fmt.Errorf("delete expired enrollments: %w", err)
	}
	return int(deleted), nil
}

func (p PendingEnrollment) Expired() bool {
	return !p.ExpiresAt.After(time.Now())
}

func convertPendingEnrollment(row dbsql.PendingEnrollment) (PendingEnrollment, error) {
	id, err := uuid.Parse(row.ID)
	if err != nil {
		return PendingEnrollment{}, err
	}
	userID, err := uuid.Parse(row.UserID)
	if err != nil {
		return PendingEnrollment{}, err
	}
	if !row.ExpiresAt.Valid {
		return PendingEnrollment{}, fmt.Errorf("enrollment has no expiry")
	}
	return PendingEnrollment{ID: id, UserID: userID, EnrollmentKey: row.EnrollmentKey,
		CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt.Time}, nil
}
