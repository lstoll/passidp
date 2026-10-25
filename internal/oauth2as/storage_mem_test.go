package oauth2as

import (
	"testing"
)

func TestMemoryStorage(t *testing.T) {
	testStorage(t, func(*testing.T) *Storage {
		return NewMemoryStorage()
	})
}
