package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	"lds.li/tinkrotate"
	tinkrotatev1 "lds.li/tinkrotate/proto/tinkrotate/v1"
)

var _ tinkrotate.ManagedStore = (*KeysetStore)(nil)

const (
	// Bucket name for keyset storage
	bucketKeysets = "keysets"
)

// KeysetStore implements tinkrotate.ManagedStore using BoltDB
type KeysetStore struct {
	dbAccessor *dbAccessor
}

// storedKeyset represents a keyset stored in BoltDB
type storedKeyset struct {
	Handle   []byte `json:"handle"`
	Metadata []byte `json:"metadata"` // protobuf marshaled metadata
	Version  int64  `json:"version"`
}

// GetHandle returns the handle for the given keyset name.
func (k *KeysetStore) GetHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	result, err := k.ReadKeysetAndMetadata(ctx, keysetName)
	if err != nil {
		return nil, err
	}
	return result.Handle, nil
}

// GetPublicHandle returns the handle for the given keyset name, with only
// the public key material.
func (k *KeysetStore) GetPublicHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	handle, err := k.GetHandle(ctx, keysetName)
	if err != nil {
		return nil, err
	}
	return handle.Public()
}

// ReadKeysetAndMetadata reads a keyset and its metadata from the store.
func (k *KeysetStore) ReadKeysetAndMetadata(ctx context.Context, keysetName string) (*tinkrotate.ReadResult, error) {
	db, release := k.dbAccessor.db()
	defer release()

	var result *tinkrotate.ReadResult
	var notFound bool
	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketKeysets))
		if bucket == nil {
			notFound = true
			return nil
		}

		data := bucket.Get([]byte(keysetName))
		if data == nil {
			notFound = true
			return nil
		}

		var stored storedKeyset
		if err := json.Unmarshal(data, &stored); err != nil {
			return fmt.Errorf("unmarshal keyset: %w", err)
		}

		reader := keyset.NewBinaryReader(bytes.NewReader(stored.Handle))
		handle, err := insecurecleartextkeyset.Read(reader)
		if err != nil {
			return fmt.Errorf("read keyset handle: %w", err)
		}

		metadata := &tinkrotatev1.KeyRotationMetadata{}
		if err := proto.Unmarshal(stored.Metadata, metadata); err != nil {
			return fmt.Errorf("unmarshal metadata: %w", err)
		}

		result = &tinkrotate.ReadResult{
			Handle:   handle,
			Metadata: metadata,
			Context:  stored.Version,
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	if notFound {
		return &tinkrotate.ReadResult{Context: int64(0)}, tinkrotate.ErrKeysetNotFound
	}

	return result, nil
}

// WriteKeysetAndMetadata writes a keyset and its metadata to the store.
func (k *KeysetStore) WriteKeysetAndMetadata(ctx context.Context, keysetName string, handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata, expectedContext any) error {
	if handle == nil || metadata == nil {
		return errors.New("handle and metadata cannot be nil for writing")
	}

	metadataData, err := proto.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata protobuf: %w", err)
	}

	keysetBuf := new(bytes.Buffer)
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(keysetBuf)); err != nil {
		return fmt.Errorf("write cleartext keyset handle for %q: %w", keysetName, err)
	}

	db, release := k.dbAccessor.db()
	defer release()

	return db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketKeysets))
		if bucket == nil {
			return fmt.Errorf("keysets bucket does not exist")
		}

		existingData := bucket.Get([]byte(keysetName))
		var newVersion int64

		if expectedContext == nil {
			// Insert: expect keyset to not exist
			if existingData != nil {
				return tinkrotate.ErrOptimisticLockFailed
			}
			newVersion = 1
		} else {
			// Update: verify version matches
			expectedVersion, ok := expectedContext.(int64)
			if !ok {
				return fmt.Errorf("invalid expectedContext type: expected int64, got %T", expectedContext)
			}

			if existingData == nil {
				return tinkrotate.ErrOptimisticLockFailed
			}

			var existing storedKeyset
			if err := json.Unmarshal(existingData, &existing); err != nil {
				return fmt.Errorf("unmarshal existing keyset: %w", err)
			}

			if existing.Version != expectedVersion {
				return tinkrotate.ErrOptimisticLockFailed
			}

			newVersion = expectedVersion + 1
		}

		stored := storedKeyset{
			Handle:   keysetBuf.Bytes(),
			Metadata: metadataData,
			Version:  newVersion,
		}

		data, err := json.Marshal(stored)
		if err != nil {
			return fmt.Errorf("marshal stored keyset: %w", err)
		}

		if err := bucket.Put([]byte(keysetName), data); err != nil {
			return fmt.Errorf("store keyset: %w", err)
		}

		return nil
	})
}

// ForEachKeyset calls fn for each keyset name in the store.
func (k *KeysetStore) ForEachKeyset(ctx context.Context, fn func(keysetName string) error) error {
	db, release := k.dbAccessor.db()
	defer release()

	var keys []string

	// capture all the keys first, the update will start a child write TX and
	// will deadlock on the read TX. We only have a small number of keysets so
	// this is cheap anyway.
	//
	// TODO - see if there's a better way to deal with the nested TX setup in
	// tinkrotate.
	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketKeysets))
		if bucket == nil {
			return nil // No bucket means no keysets
		}

		return bucket.ForEach(func(k, v []byte) error {
			keys = append(keys, string(k))
			return nil
		})
	})
	if err != nil {
		return err
	}

	for _, key := range keys {
		if err := fn(key); err != nil {
			return err
		}
	}

	return nil
}
