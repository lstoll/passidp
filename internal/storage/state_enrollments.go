package storage

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

const (
	bucketPendingEnrollments = "pending_enrollments"
	pendingEnrollmentMaxAge  = 24 * time.Hour
)

// PendingEnrollment represents a pending WebAuthn credential enrollment.
type PendingEnrollment struct {
	ID              uuid.UUID            `json:"id"`
	UserID          uuid.UUID            `json:"user_id"`
	EnrollmentKey   string               `json:"enrollment_key"`
	ConfirmationKey string               `json:"confirmation_key"`
	CredentialID    []byte               `json:"credential_id"`
	CredentialData  *webauthn.Credential `json:"credential_data"`
	Name            string               `json:"name"`
	CreatedAt       time.Time            `json:"created_at"`
}

// PendingEnrollments implements pending enrollment storage using BoltDB
type PendingEnrollments struct {
	dbAccessor *dbAccessor
}

var errStopIteration = fmt.Errorf("stop iteration")

// iteratePendingEnrollments iterates through all pending enrollments and calls the provided function
// for each enrollment. If the function returns false, iteration stops.
func (p *PendingEnrollments) iteratePendingEnrollments(fn func(*PendingEnrollment) (bool, error)) error {
	db, release := p.dbAccessor.db()
	defer release()

	return db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketPendingEnrollments))
		if bucket == nil {
			return fmt.Errorf("pending enrollments bucket not found")
		}

		err := bucket.ForEach(func(k, v []byte) error {
			// Skip sub-buckets (if any exist from old data)
			if v == nil {
				return nil
			}

			enrollment := &PendingEnrollment{}
			if err := json.Unmarshal(v, enrollment); err != nil {
				// Skip invalid entries
				return nil
			}

			cont, err := fn(enrollment)
			if err != nil {
				return err
			}
			if !cont {
				return errStopIteration
			}
			return nil
		})
		if err == errStopIteration {
			return nil
		}
		return err
	})
}

// CreatePendingEnrollment creates a new pending enrollment for a user.
func (p *PendingEnrollments) CreatePendingEnrollment(userID uuid.UUID) (*PendingEnrollment, error) {
	db, release := p.dbAccessor.db()
	defer release()

	enrollment := &PendingEnrollment{
		ID:            uuid.New(),
		UserID:        userID,
		EnrollmentKey: uuid.New().String(),
		CreatedAt:     time.Now(),
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketPendingEnrollments))
		if bucket == nil {
			return fmt.Errorf("pending enrollments bucket not found")
		}

		data, err := json.Marshal(enrollment)
		if err != nil {
			return fmt.Errorf("marshal enrollment: %w", err)
		}

		if err := bucket.Put([]byte(enrollment.ID.String()), data); err != nil {
			return fmt.Errorf("store enrollment: %w", err)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return enrollment, nil
}

// GetPendingEnrollmentByKey retrieves a pending enrollment by its enrollment key.
func (p *PendingEnrollments) GetPendingEnrollmentByKey(enrollmentKey string) (*PendingEnrollment, error) {
	var enrollment *PendingEnrollment
	err := p.iteratePendingEnrollments(func(e *PendingEnrollment) (bool, error) {
		if e.EnrollmentKey == enrollmentKey {
			enrollment = e
			return false, nil // Stop iteration
		}
		return true, nil // Continue iteration
	})

	if err != nil {
		return nil, err
	}

	if enrollment == nil {
		return nil, fmt.Errorf("enrollment not found")
	}

	return enrollment, nil
}

// GetPendingEnrollmentByID retrieves a pending enrollment by its ID.
func (p *PendingEnrollments) GetPendingEnrollmentByID(enrollmentID uuid.UUID) (*PendingEnrollment, error) {
	db, release := p.dbAccessor.db()
	defer release()

	var enrollment *PendingEnrollment

	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketPendingEnrollments))
		if bucket == nil {
			return fmt.Errorf("pending enrollments bucket not found")
		}

		data := bucket.Get([]byte(enrollmentID.String()))
		if data == nil {
			return fmt.Errorf("enrollment not found")
		}

		enrollment = &PendingEnrollment{}
		if err := json.Unmarshal(data, enrollment); err != nil {
			return fmt.Errorf("unmarshal enrollment: %w", err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return enrollment, nil
}

// UpdatePendingEnrollment updates a pending enrollment with credential data and confirmation key.
func (p *PendingEnrollments) UpdatePendingEnrollment(enrollmentID uuid.UUID, credentialID []byte, credentialData *webauthn.Credential, name string, confirmationKey string) error {
	db, release := p.dbAccessor.db()
	defer release()

	return db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketPendingEnrollments))
		if bucket == nil {
			return fmt.Errorf("pending enrollments bucket not found")
		}

		data := bucket.Get([]byte(enrollmentID.String()))
		if data == nil {
			return fmt.Errorf("enrollment not found")
		}

		enrollment := &PendingEnrollment{}
		if err := json.Unmarshal(data, enrollment); err != nil {
			return fmt.Errorf("unmarshal enrollment: %w", err)
		}

		// Prevent re-registration: if a credential is already registered, reject the update
		if enrollment.CredentialData != nil {
			return fmt.Errorf("enrollment already completed - a passkey has already been registered for this enrollment")
		}

		enrollment.CredentialID = credentialID
		enrollment.CredentialData = credentialData
		enrollment.Name = name
		enrollment.ConfirmationKey = confirmationKey

		updatedData, err := json.Marshal(enrollment)
		if err != nil {
			return fmt.Errorf("marshal enrollment: %w", err)
		}

		if err := bucket.Put([]byte(enrollmentID.String()), updatedData); err != nil {
			return fmt.Errorf("update enrollment: %w", err)
		}

		return nil
	})
}

// ConfirmPendingEnrollment confirms a pending enrollment and returns the enrollment data.
// After confirmation, the enrollment is deleted from the pending store.
func (p *PendingEnrollments) ConfirmPendingEnrollment(enrollmentID uuid.UUID, confirmationKey string) (*PendingEnrollment, error) {
	db, release := p.dbAccessor.db()
	defer release()

	var enrollment *PendingEnrollment

	err := db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketPendingEnrollments))
		if bucket == nil {
			return fmt.Errorf("pending enrollments bucket not found")
		}

		data := bucket.Get([]byte(enrollmentID.String()))
		if data == nil {
			return fmt.Errorf("enrollment not found")
		}

		enrollment = &PendingEnrollment{}
		if err := json.Unmarshal(data, enrollment); err != nil {
			return fmt.Errorf("unmarshal enrollment: %w", err)
		}

		if enrollment.ConfirmationKey != confirmationKey {
			return fmt.Errorf("invalid confirmation key")
		}

		if enrollment.CredentialData == nil {
			return fmt.Errorf("enrollment not completed")
		}

		if err := bucket.Delete([]byte(enrollmentID.String())); err != nil {
			return fmt.Errorf("delete enrollment: %w", err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return enrollment, nil
}

// ListPendingEnrollmentsByUser lists all pending enrollments for a user.
func (p *PendingEnrollments) ListPendingEnrollmentsByUser(userID uuid.UUID) ([]*PendingEnrollment, error) {
	var enrollments []*PendingEnrollment
	err := p.iteratePendingEnrollments(func(e *PendingEnrollment) (bool, error) {
		if e.UserID == userID {
			enrollments = append(enrollments, e)
		}
		return true, nil // Continue iteration
	})

	if err != nil {
		return nil, err
	}

	return enrollments, nil
}

// GarbageCollectPendingEnrollments removes pending enrollments older than pendingEnrollmentMaxAge.
// Returns the number of enrollments deleted.
func (p *PendingEnrollments) GarbageCollectPendingEnrollments() (int, error) {
	db, release := p.dbAccessor.db()
	defer release()

	var deletedCount int
	cutoff := time.Now().Add(-pendingEnrollmentMaxAge)

	err := db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketPendingEnrollments))
		if bucket == nil {
			return fmt.Errorf("pending enrollments bucket not found")
		}

		return bucket.ForEach(func(k, v []byte) error {
			// Skip sub-buckets (if any exist from old data)
			if v == nil {
				return nil
			}

			enrollment := &PendingEnrollment{}
			if err := json.Unmarshal(v, enrollment); err != nil {
				// Skip invalid entries
				return nil
			}

			// Delete if older than cutoff
			if enrollment.CreatedAt.Before(cutoff) {
				if err := bucket.Delete(k); err != nil {
					return fmt.Errorf("delete enrollment %s: %w", string(k), err)
				}
				deletedCount++
			}

			return nil
		})
	})

	if err != nil {
		return 0, err
	}

	return deletedCount, nil
}
