package storage_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/passkey"
	"lds.li/passidp/internal/storage"
)

func TestImportProdCredentialsJSON(t *testing.T) {
	path := filepath.Join("..", "..", "..", "infra", "fly", "lstoll-idp", "credentials.json")
	if _, err := os.Stat(path); err != nil {
		t.Skip("prod credentials.json not present")
	}

	store, err := storage.NewCredentialFile(path)
	if err != nil {
		t.Fatalf("open prod credentials: %v", err)
	}

	const rpID = "id.lds.li"
	var (
		before int
		names  []string
	)
	store.Read(func(cs *storage.CredentialStore) {
		before = len(cs.Credentials)
		for _, cred := range cs.Credentials {
			names = append(names, cred.Name)
			_, err := storage.PasskeyRecordFromLegacyCredential(cred, rpID)
			if err != nil {
				t.Errorf("%s (%s): convert: %v", cred.Name, cred.ID, err)
				continue
			}
		}
	})
	if before == 0 {
		t.Fatal("expected legacy credentials in prod file")
	}

	tmp := t.TempDir() + "/credentials.json"
	cloned, err := storage.NewCredentialFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if err := cloned.Write(func(cs *storage.CredentialStore) error {
		store.Read(func(src *storage.CredentialStore) {
			cs.Users = src.Users
			cs.Credentials = src.Credentials
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := cloned.Write(func(cs *storage.CredentialStore) error {
		cs.ImportLegacyCredentials(rpID)
		if n := len(cs.Credentials); n != 0 {
			t.Errorf("leftover credentials after import: %d", n)
			for _, cred := range cs.Credentials {
				t.Errorf("  leftover %s %s", cred.Name, cred.ID)
			}
		}
		for _, user := range cs.Users {
			for _, pk := range user.Passkeys {
				if _, err := passkey.AAGUID(pk.Record); err != nil {
					t.Errorf("%s: filippo parse: %v", pk.Name, err)
				}
				flags := parseAuthData(t, authDataFromRecord(t, pk.Record))
				if flags.userPresent && !flags.userVerified {
					t.Errorf("%s: imported record has UP without UV and cannot support passwordless login", pk.Name)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
