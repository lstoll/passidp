package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

const (
	bucketPendingEnrollments = "pending_enrollments"
)

// PendingEnrollment represents a pending WebAuthn credential enrollment.
type PendingEnrollment struct {
	ID             uuid.UUID              `json:"id"`
	UserID         uuid.UUID              `json:"user_id"`
	EnrollmentKey  string                 `json:"enrollment_key"`
	ConfirmationKey string                `json:"confirmation_key"`
	CredentialID   []byte                 `json:"credential_id"`
	CredentialData *webauthn.Credential   `json:"credential_data"`
	Name           string                 `json:"name"`
	CreatedAt      time.Time              `json:"created_at"`
}

// CreatePendingEnrollment creates a new pending enrollment for a user.
func (s *State) CreatePendingEnrollment(userID uuid.UUID) (*PendingEnrollment, error) {
	enrollment := &PendingEnrollment{
		ID:            uuid.New(),
		UserID:        userID,
		EnrollmentKey: uuid.New().String(),
		CreatedAt:     time.Now(),
	}

	if err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketPendingEnrollments))
		if bucket == nil {
			return fmt.Errorf("pending enrollments bucket not found")
		}

		data, err := json.Marshal(enrollment)
		if err != nil {
			return fmt.Errorf("marshal enrollment: %w", err)
		}

		// Store by enrollment ID
		if err := bucket.Put([]byte(enrollment.ID.String()), data); err != nil {
			return fmt.Errorf("store enrollment: %w", err)
		}

		// Also index by enrollment key for quick lookup
		enrollmentKeyBucket, err := bucket.CreateBucketIfNotExists([]byte("by_enrollment_key"))
		if err != nil {
			return fmt.Errorf("create enrollment key bucket: %w", err)
		}
		if err := enrollmentKeyBucket.Put([]byte(enrollment.EnrollmentKey), []byte(enrollment.ID.String())); err != nil {
			return fmt.Errorf("index enrollment key: %w", err)
		}

		// Index by user ID
		userBucket, err := bucket.CreateBucketIfNotExists([]byte("by_user_id"))
		if err != nil {
			return fmt.Errorf("create user bucket: %w", err)
		}
		userKey := append([]byte(userID.String()), []byte(":")...)
		userKey = append(userKey, []byte(enrollment.ID.String())...)
		if err := userBucket.Put(userKey, []byte(enrollment.ID.String())); err != nil {
			return fmt.Errorf("index user: %w", err)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return enrollment, nil
}

// GetPendingEnrollmentByKey retrieves a pending enrollment by its enrollment key.
func (s *State) GetPendingEnrollmentByKey(enrollmentKey string) (*PendingEnrollment, error) {
	var enrollment *PendingEnrollment
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketPendingEnrollments))
		if bucket == nil {
			return fmt.Errorf("pending enrollments bucket not found")
		}

		enrollmentKeyBucket := bucket.Bucket([]byte("by_enrollment_key"))
		if enrollmentKeyBucket == nil {
			return fmt.Errorf("enrollment not found")
		}

		enrollmentIDBytes := enrollmentKeyBucket.Get([]byte(enrollmentKey))
		if enrollmentIDBytes == nil {
			return fmt.Errorf("enrollment not found")
		}

		data := bucket.Get(enrollmentIDBytes)
		if data == nil {
			return fmt.Errorf("enrollment data not found")
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

// GetPendingEnrollmentByID retrieves a pending enrollment by its ID.
func (s *State) GetPendingEnrollmentByID(enrollmentID uuid.UUID) (*PendingEnrollment, error) {
	var enrollment *PendingEnrollment
	err := s.db.View(func(tx *bolt.Tx) error {
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
func (s *State) UpdatePendingEnrollment(enrollmentID uuid.UUID, credentialID []byte, credentialData *webauthn.Credential, name string, confirmationKey string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
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
func (s *State) ConfirmPendingEnrollment(enrollmentID uuid.UUID, confirmationKey string) (*PendingEnrollment, error) {
	var enrollment *PendingEnrollment
	err := s.db.Update(func(tx *bolt.Tx) error {
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

		// Delete the enrollment
		if err := bucket.Delete([]byte(enrollmentID.String())); err != nil {
			return fmt.Errorf("delete enrollment: %w", err)
		}

		// Delete from enrollment key index
		enrollmentKeyBucket := bucket.Bucket([]byte("by_enrollment_key"))
		if enrollmentKeyBucket != nil {
			if err := enrollmentKeyBucket.Delete([]byte(enrollment.EnrollmentKey)); err != nil {
				return fmt.Errorf("delete enrollment key index: %w", err)
			}
		}

		// Delete from user index
		userBucket := bucket.Bucket([]byte("by_user_id"))
		if userBucket != nil {
			userKey := append([]byte(enrollment.UserID.String()), []byte(":")...)
			userKey = append(userKey, []byte(enrollmentID.String())...)
			if err := userBucket.Delete(userKey); err != nil {
				return fmt.Errorf("delete user index: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return enrollment, nil
}

// ListPendingEnrollmentsByUser lists all pending enrollments for a user.
func (s *State) ListPendingEnrollmentsByUser(userID uuid.UUID) ([]*PendingEnrollment, error) {
	var enrollments []*PendingEnrollment
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketPendingEnrollments))
		if bucket == nil {
			return fmt.Errorf("pending enrollments bucket not found")
		}

		userBucket := bucket.Bucket([]byte("by_user_id"))
		if userBucket == nil {
			return nil // No enrollments for this user
		}

		prefix := []byte(userID.String() + ":")
		c := userBucket.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			enrollmentID := string(v)
			data := bucket.Get([]byte(enrollmentID))
			if data == nil {
				continue
			}

			enrollment := &PendingEnrollment{}
			if err := json.Unmarshal(data, enrollment); err != nil {
				continue
			}

			enrollments = append(enrollments, enrollment)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return enrollments, nil
}
